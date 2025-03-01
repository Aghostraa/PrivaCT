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

const hexDecode = (hex: string): Uint8Array => {
    const matches = hex.match(/.{1,2}/g) || [];
    return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
};

function bytesToBoolVec(bytes: Uint8Array): boolean[] {
    const bools: boolean[] = [];
    for (const byte of bytes) {
        // Iterate over bits from MSB (bit 7) to LSB (bit 0)
        for (let i = 0; i < 8; i++) {
            const bitPosition = 7 - i;
            const bitValue = (byte >> bitPosition) & 1;
            bools.push(bitValue === 1);
        }
    }
    return bools;
}

async function jmtHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
    // Create domain separator matching Rust's "JMT::IntrnalNode" bytes
    const domainSeparator = new TextEncoder().encode("JMT::IntrnalNode");
    // Concatenate in the exact same order as Rust code:
    const prefixedData = concatenateArrays(
        domainSeparator,
        left,
        right
    );

    // Calculate SHA-256 hash
    const hashBuffer = await crypto.subtle.digest("SHA-256", prefixedData);
    return new Uint8Array(hashBuffer);
}

export async function verifyJmtProof(
    key: string,
    leaf: string,
    siblings: string[],
    commitment: string
): Promise<boolean> {
    try {
        // Decode hex inputs
        const leafBytes = hexDecode(leaf);
        const commitmentBytes = hexDecode(commitment);

        // Validate lengths
        if (commitmentBytes.length !== 32) {
            throw new Error("Commitment hash must be 32 bytes");
        }
        if (leafBytes.length !== 32) {
            throw new Error("Leaf hash must be 32 bytes");
        }

        // Calculate address hash
        const addressHash = await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(key)
        );
        const addrBytes = new Uint8Array(addressHash);

        // Convert address to bit array
        const b2b = bytesToBoolVec(addrBytes);

        // Initialize current hash with leaf value
        let currentHash = leafBytes;

        // Process siblings in reverse order
        for (let i = 0; i < siblings.length; i++) {
            const siblingHex = siblings[i];
            const siblingBytes = hexDecode(siblingHex);

            if (siblingBytes.length !== 32) {
                throw new Error("Each sibling hash must be 32 bytes");
            }

            // Get corresponding bit (reverse index for siblings)
            const bitIndex = siblings.length - i - 1;
            const bit = b2b[bitIndex];

            // Combine hashes based on bit value
            currentHash = bit
                ? await jmtHash(siblingBytes, currentHash)
                : await jmtHash(currentHash, siblingBytes);
        }

        // Compare final hash with commitment
        return arraysEqual(currentHash, commitmentBytes);
        // return Buffer.from(currentHash).equals(Buffer.from(commitmentBytes));
    } catch (error) {
        // Convert to boolean error indication per Rust version
        console.error("Verification error:", error);
        return false;
    }
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}
