import init, { Verifier } from '../wasm/wasm_verifier.js';

let verifier: Verifier;

async function initializeWasm() {
  await init();
  verifier = new Verifier();
}

initializeWasm();

browser.runtime.onMessage.addListener(async (message, sender) => {
  if (message.type === 'VERIFY_SCTS') {
    const scts = message.scts; // Array of SCT objects
    // For each SCT, query the Prism backend for the latest STH and proof.
    // Example: (Replace with actual fetch call to your backend)
    const sthResponse = await fetch('https://your-backend.example.com/latest_sth?log_id=Xenon2024');
    const { sth, proof } = await sthResponse.json();

    // Convert values appropriately (e.g., hex strings to Uint8Arrays)
    const sthRoot = hexToUint8Array(sth.root_hash);
    let allValid = true;

    for (const sct of scts) {
      // Here, we pass the SCT bytes, STH root, and proof array to WASM for verification.
      const valid = verifier.verify_sct(sct.bytes, sthRoot, proof);
      if (!valid) {
        allValid = false;
        break;
      }
    }

    // Update the browser UI (e.g., lock icon) based on verification result.
    browser.action.setIcon({
      path: allValid ? "icons/lock-verified.png" : "icons/lock-warning.png"
    });
  }
});

function hexToUint8Array(hex: string): Uint8Array {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return new Uint8Array(bytes);
}
