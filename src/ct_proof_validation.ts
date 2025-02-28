import { b64DecodeBytes, b64EncodeBytes } from "./conversion";
import { CtMerkleProof } from "./ct_log_types";

/**
 * Validates a Merkle proof from a CT log server
 */
export async function validateProof(
  proof: CtMerkleProof,
  leafHash: Uint8Array,
  expectedRootHash: Uint8Array,
): Promise<boolean> {
  try {
    const calculatedRootHash = await calculateRootHash(
      leafHash,
      proof.leaf_index,
      proof.audit_path,
    );

    const calculatedRootHashHex = Array.from(new Uint8Array(calculatedRootHash))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

    const expectedRootHashHex = Array.from(new Uint8Array(expectedRootHash))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

    console.log("Comparing hashes", calculatedRootHashHex, expectedRootHashHex);

    return areArraysEqual(calculatedRootHash, expectedRootHash);
  } catch (error) {
    console.error("Error validating Merkle proof:", error);
    return false;
  }
}


async function calculateRootHash(
  leafHash: Uint8Array,
  leafIndex: number,
  auditPath: string[],
): Promise<Uint8Array> {
  let currentHash = leafHash;
  let nodeIndex = leafIndex; // Starting from the leaf's position

  for (const pathElement of auditPath) {
    const siblingHash = b64DecodeBytes(pathElement);

    // If nodeIndex is odd, sibling is on the left
    // If nodeIndex is even, sibling is on the right
    if (nodeIndex % 2 === 1) {
      currentHash = await hashChildren(siblingHash, currentHash);
    } else {
      currentHash = await hashChildren(currentHash, siblingHash);
    }

    // Move up to parent level
    nodeIndex = Math.floor(nodeIndex / 2);
  }

  return currentHash;
}

/**
 * Hashes two child nodes according to CT spec (0x01 prefix)
 */
async function hashChildren(
  left: Uint8Array,
  right: Uint8Array,
): Promise<Uint8Array> {
  const prefixedData = concatenateArrays(new Uint8Array([0x01]), left, right);
  const hashBuffer = await crypto.subtle.digest("SHA-256", prefixedData);
  return new Uint8Array(hashBuffer);
}

/**
 * Utility method to concatenate multiple Uint8Arrays
 */
function concatenateArrays(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;

  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

/**
 * Utility method to compare two Uint8Arrays
 */
function areArraysEqual(arr1: Uint8Array, arr2: Uint8Array): boolean {
  if (arr1.length !== arr2.length) {
    return false;
  }
  return arr1.every((value, index) => value === arr2[index]);
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}


async function hash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  const combined = new Uint8Array(left.length + right.length);
  combined.set(left,0);
  combined.set(right, left.length);

  const digest = await crypto.subtle.digest("SHA-256", combined);
  return new Uint8Array(digest);
}

// Hashes the account public key (valid_keys[0].bytes)
async function hashPublicKey(publicKeyB64: string): Promise<Uint8Array> {
  const publicKeyBytes = b64DecodeBytes(publicKeyB64);
  const digest = await crypto.subtle.digest("SHA-256", publicKeyBytes);
  return new Uint8Array(digest);
}

async function recomputeRoot(leafHex: string, siblings: string[], accountKeyB64: string): Promise<Uint8Array> {
  let currentHash = hexToBytes(leafHex);
  const accountKey = await hashPublicKey(accountKeyB64);  // Public key, 32 bytes long (256 bits)

  // Process each sibling hash with the corresponding bit from the key
  for (let level = 0; level < siblings.length; level++) {
      const siblingHash = hexToBytes(siblings[level]);

      // Figure out if we're the left or right child at this level
      const bit = (accountKey[Math.floor(level / 8)] >> (7 - (level % 8))) & 1;

      if (bit === 1) {
          // Current node is the right child, sibling is the left
          currentHash = await hash(siblingHash, currentHash);
      } else {
          // Current node is the left child, sibling is the right
          currentHash = await hash(currentHash, siblingHash);
      }
  }

  // Convert the final root hash to hex string
  // return Array.from(currentHash).map(b => b.toString(16).padStart(2, '0')).join('');
  return currentHash
}



async function verifyProof(account: any, proof: any, fetchedRoot: string): Promise<boolean> {
  const accountKey = account.id;
  const recomputedRoot = await recomputeRoot(proof.leaf, proof.siblings, accountKey);
  console.log("Recomputed root:", recomputedRoot);
  console.log("Fetched root:", fetchedRoot);

  return Array.from(recomputedRoot).join('') === Array.from(hexToBytes(fetchedRoot)).join('');
}

export async function checkProofAgainstPrism(account: any, proof: any, root_hash: any): Promise<boolean> {
  const result = await verifyProof(account, proof, root_hash);
  if (result) {
      console.log("Proof is valid!");
  } else {
      console.warn("Proof is invalid!");
  }
  return result;
}
