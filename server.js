const express = require("express");
const mqtt = require("mqtt");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const { ethers } = require("ethers");

require("dotenv").config({
  path: "../.env"
});

const app = express();

app.use(cors());
app.use(express.json());

// =====================================================
// CONFIG
// =====================================================

const PORT = 5000;

const DEVICE_NAME = "COLDNODE-01";

const MQTT_BROKER = "mqtt://broker.hivemq.com";
const MQTT_TOPIC = `coldchain/${DEVICE_NAME}/telemetry`;

const BATCH_SIZE = 5;

// =====================================================
// MQTT
// =====================================================

const mqttClient = mqtt.connect(MQTT_BROKER);

// =====================================================
// POLYGON AMOY
// =====================================================

const RPC_URL = process.env.AMOY_RPC_URL;

const PRIVATE_KEY = process.env.AMOY_PRIVATE_KEY.startsWith("0x")
  ? process.env.AMOY_PRIVATE_KEY
  : "0x" + process.env.AMOY_PRIVATE_KEY;

const CONTRACT_ADDRESS =
  "0x631aB27429954e0d53e493816213Ee1e391895da";

// Contract functions used by backend
const CONTRACT_ABI = [
  "function registeredDevices(bytes32) view returns (bool)",
  "function anchorBatch(bytes32 deviceId, bytes32 batchId, bytes32 merkleRoot) external",
  "function verifyLeaf(bytes32 deviceId, bytes32 batchId, bytes32 leaf, bytes32[] proof) external view returns (bool)"
];

const provider = new ethers.JsonRpcProvider(RPC_URL);

const wallet = new ethers.Wallet(
  PRIVATE_KEY,
  provider
);

const contract = new ethers.Contract(
  CONTRACT_ADDRESS,
  CONTRACT_ABI,
  wallet
);

// =====================================================
// DEVICE ID
// =====================================================
//
// IMPORTANT:
//
// The registration script creates the device ID as:
//
// keccak256(raw Ed25519 public key)
//
// We MUST use exactly the same method here.
// =====================================================

function getDeviceId() {

  const publicKeyPath =
    "../simulator/public_key.pem";

  const publicKey = crypto.createPublicKey(
    fs.readFileSync(publicKeyPath)
  );

  const der = publicKey.export({
    type: "spki",
    format: "der"
  });

  // Ed25519 raw public key = final 32 bytes
  const rawPublicKey = der.subarray(-32);

  return ethers.keccak256(rawPublicKey);
}

const DEVICE_ID = getDeviceId();

console.log();
console.log("Device:", DEVICE_NAME);
console.log("Device ID:", DEVICE_ID);
console.log("Contract:", CONTRACT_ADDRESS);

// =====================================================
// TELEMETRY STORAGE
// =====================================================

let latestTelemetry = null;

let batch = [];

let anchoring = false;

// =====================================================
// SHA-256
// =====================================================

function sha256Hex(data) {

  return crypto
    .createHash("sha256")
    .update(data)
    .digest("hex");
}

// =====================================================
// HEX -> BYTES32
// =====================================================

function hexToBytes32(hex) {

  return "0x" + hex;
}

// =====================================================
// MERKLE TREE
// =====================================================

function hashPair(left, right) {

  const a = left < right
    ? left
    : right;

  const b = left < right
    ? right
    : left;

  return ethers.keccak256(
    ethers.concat([
      a,
      b
    ])
  );
}

function buildMerkleTree(leaves) {

  let level =
    leaves.map(hexToBytes32);

  while (level.length > 1) {

    const nextLevel = [];

    for (
      let i = 0;
      i < level.length;
      i += 2
    ) {

      const left = level[i];

      const right =
        i + 1 < level.length
          ? level[i + 1]
          : level[i];

      nextLevel.push(
        hashPair(left, right)
      );
    }

    level = nextLevel;
  }

  return level[0];
}

// =====================================================
// MERKLE PROOF
// =====================================================

function getMerkleProof(
  leaves,
  index
) {

  let level =
    leaves.map(hexToBytes32);

  const proof = [];

  let currentIndex = index;

  while (level.length > 1) {

    const isRightNode =
      currentIndex % 2 === 1;

    const siblingIndex =
      isRightNode
        ? currentIndex - 1
        : currentIndex + 1;

    if (
      siblingIndex < level.length
    ) {

      proof.push(
        level[siblingIndex]
      );
    }

    const nextLevel = [];

    for (
      let i = 0;
      i < level.length;
      i += 2
    ) {

      const left = level[i];

      const right =
        i + 1 < level.length
          ? level[i + 1]
          : level[i];

      nextLevel.push(
        hashPair(left, right)
      );
    }

    currentIndex =
      Math.floor(currentIndex / 2);

    level = nextLevel;
  }

  return proof;
}

// =====================================================
// ANCHOR BATCH
// =====================================================

async function anchorBatch() {

  if (batch.length !== BATCH_SIZE) {
    return;
  }

  if (anchoring) {
    return;
  }

  anchoring = true;

  // Freeze this exact batch.
  // New telemetry will not be added until this finishes.
  const currentBatch = [...batch];

  console.log();
  console.log("========================================");
  console.log(" 5 RECORD BATCH READY");
  console.log("========================================");

  console.log(
    "Records:",
    currentBatch.map(
      x => x.record_id
    )
  );

  // ===================================================
  // SHA-256 LEAVES
  // ===================================================

  const leaves =
    currentBatch.map(record => {

      const canonical =
        JSON.stringify(record);

      const hash =
        sha256Hex(canonical);

      console.log(
        `Record ${record.record_id} SHA-256: ${hash}`
      );

      return hash;
    });

  // ===================================================
  // MERKLE ROOT
  // ===================================================

  const merkleRoot =
    buildMerkleTree(leaves);

  console.log();
  console.log("Merkle Root:");
  console.log(merkleRoot);

  // ===================================================
  // DEVICE ID
  // ===================================================

  const deviceId = DEVICE_ID;

  console.log();
  console.log("Device ID:");
  console.log(deviceId);

  // ===================================================
  // CHECK REGISTRATION BEFORE TRANSACTION
  // ===================================================

  try {

    const registered =
      await contract.registeredDevices(
        deviceId
      );

    console.log();
    console.log(
      "Device registered on-chain:",
      registered
    );

    if (!registered) {

      console.log();
      console.log(
        "❌ Device ID is NOT registered on this contract."
      );

      console.log(
        "Expected registered Device ID:"
      );

      console.log(deviceId);

      console.log();
      console.log(
        "Batch retained. No records discarded."
      );

      anchoring = false;

      return;
    }

  } catch (error) {

    console.log();
    console.log(
      "❌ Could not check device registration."
    );

    console.log(error.message);

    anchoring = false;

    return;
  }

  // ===================================================
  // BATCH ID
  // ===================================================

  const batchText =
    `${DEVICE_NAME}-BATCH-${Date.now()}`;

  const batchId =
    ethers.id(batchText);

  console.log();
  console.log("Batch ID:");
  console.log(batchId);

  // ===================================================
  // ANCHOR
  // ===================================================

  try {

    console.log();
    console.log(
      "Anchoring batch to Polygon Amoy..."
    );

    const tx =
      await contract.anchorBatch(
        deviceId,
        batchId,
        merkleRoot
      );

    console.log();
    console.log(
      "Transaction sent:"
    );

    console.log(tx.hash);

    console.log(
      "Waiting for confirmation..."
    );

    const receipt =
      await tx.wait();

    console.log();
    console.log("========================================");
    console.log(" BATCH ANCHORED SUCCESSFULLY");
    console.log("========================================");

    console.log(
      "Block:",
      receipt.blockNumber
    );

    console.log();
    console.log(
      "Transaction:"
    );

    console.log(tx.hash);

    console.log();
    console.log(
      "Merkle Root:"
    );

    console.log(merkleRoot);

    console.log();
    console.log(
      "Polygon Amoy Explorer:"
    );

    console.log(
      `https://amoy.polygonscan.com/tx/${tx.hash}`
    );

    // =================================================
    // MERKLE PROOF
    // =================================================

    const proof =
      getMerkleProof(
        leaves,
        0
      );

    console.log();
    console.log(
      "Proof for Record",
      currentBatch[0].record_id
    );

    console.log(proof);

    // =================================================
    // ON-CHAIN VERIFICATION
    // =================================================

    console.log();
    console.log(
      "Checking proof on blockchain..."
    );

    const valid =
      await contract.verifyLeaf(
        deviceId,
        batchId,
        hexToBytes32(leaves[0]),
        proof
      );

    console.log();

    if (valid) {

      console.log(
        "✅ TELEMETRY RECORD VERIFIED ON BLOCKCHAIN"
      );

    } else {

      console.log(
        "❌ TELEMETRY RECORD FAILED BLOCKCHAIN VERIFICATION"
      );
    }

    // =================================================
    // CLEAR SUCCESSFULLY ANCHORED BATCH
    // =================================================

    batch = [];

    console.log();
    console.log(
      "Batch cleared. Ready for next 5 records."
    );

  } catch (error) {

    console.log();
    console.log(
      "❌ BLOCKCHAIN ANCHORING FAILED"
    );

    console.log(
      error.shortMessage ||
      error.reason ||
      error.message
    );

    console.log();
    console.log(
      "Keeping the 5-record batch in memory."
    );

    console.log(
      "New records will NOT be added until this batch is successfully anchored."
    );
  }

  anchoring = false;
}

// =====================================================
// MQTT CONNECT
// =====================================================

mqttClient.on(
  "connect",
  () => {

    console.log(
      "Connected to MQTT broker"
    );

    mqttClient.subscribe(
      MQTT_TOPIC,
      error => {

        if (error) {

          console.log(
            "MQTT subscription error:",
            error.message
          );

          return;
        }

        console.log(
          "Subscribed to:",
          MQTT_TOPIC
        );
      }
    );
  }
);

// =====================================================
// MQTT MESSAGE
// =====================================================

mqttClient.on(
  "message",
  async (topic, message) => {

    if (topic !== MQTT_TOPIC) {
      return;
    }

    try {

      const telemetry =
        JSON.parse(
          message.toString()
        );

      latestTelemetry =
        telemetry;

      console.log();
      console.log(
        "Telemetry received:"
      );

      console.log(
        telemetry
      );

      // -----------------------------------------------
      // IMPORTANT:
      //
      // Never allow batch to become 6/5, 7/5, etc.
      // -----------------------------------------------

      if (
        batch.length >= BATCH_SIZE
      ) {

        return;
      }

      batch.push(
        telemetry
      );

      console.log(
        `Batch progress: ${batch.length}/${BATCH_SIZE}`
      );

      if (
        batch.length === BATCH_SIZE
      ) {

        await anchorBatch();
      }

    } catch (error) {

      console.log(
        "Invalid telemetry:",
        error.message
      );
    }
  }
);

// =====================================================
// MQTT ERROR
// =====================================================

mqttClient.on(
  "error",
  error => {

    console.log(
      "MQTT error:",
      error.message
    );
  }
);

// =====================================================
// HTTP API
// =====================================================

app.get(
  "/api/telemetry",
  (req, res) => {

    res.json({
      device_id: DEVICE_NAME,
      telemetry: latestTelemetry
    });
  }
);

// =====================================================
// SERVER
// =====================================================

app.listen(
  PORT,
  () => {

    console.log();
    console.log(
      `Backend running on http://localhost:${PORT}`
    );

    console.log(
      "Waiting for telemetry..."
    );
  }
);