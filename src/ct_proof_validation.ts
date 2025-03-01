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