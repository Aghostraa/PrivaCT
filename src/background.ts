import { b64DecodeBytes, b64EncodeBytes } from "./conversion";
import { CTLogClient } from "./ct_log_client";
import { CtLogStore } from "./ct_log_store";
import { leafHashForPreCert, sctsFromCertDer } from "./ct_parsing";
import { validateProof, checkProofAgainstPrism} from "./ct_proof_validation";
import { DomainVerificationStore } from "./verification_store";
import { PrismCtClient } from "./prism_ctclient";
import { CtMerkleProof } from "./ct_log_types";

// import init, { LightClientWorker, WasmLightClient } from 'wasm-lightclient';

const prism_client_url = "http://127.0.0.1:50524";

// Store domain verification states
const domainStates = new Map<string, boolean>();

async function updateIconForDomain(domain: string, isValid: boolean | null) {
  const iconPath = isValid === null ? {
    16: "images/icon16_gray.png",
    32: "images/icon32_gray.png",
    48: "images/icon48_gray.png",
    128: "images/icon128_gray.png"
  } : isValid ? {
    16: "images/icon16_valid.png",
    32: "images/icon32_valid.png",
    48: "images/icon48_valid.png",
    128: "images/icon128_valid.png"
  } : {
    16: "images/icon16_invalid.png",
    32: "images/icon32_invalid.png",
    48: "images/icon48_invalid.png",
    128: "images/icon128_invalid.png"
  };

  // Store the state if it's not null
  if (isValid !== null) {
    domainStates.set(domain, isValid);
  }

  const tabs = await browser.tabs.query({ url: domain + "/*" });
  for (const tab of tabs) {
    if (tab.id !== undefined) {
      await browser.action.setIcon({
        tabId: tab.id,
        path: iconPath
      });
    }
  }
}

async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function spawnWorker() {
  const worker = new Worker('worker.js');
  return worker;
}

let running = false;
let client = null;

// async function startLightClient() {
//   if (running) return;
//   try {
//     console.log("trying")
//     await init();
//     console.log('WASM initialized successfully');

//     const channel = new MessageChannel();

//     const worker = await spawnWorker();
//     console.log('Worker started successfully');

//     client = await new WasmLightClient(worker);
//     console.log('Light client connected');
//     console.log(client);

//     running = true;

//     worker.onmessage = console.log;
//     console.dir(client)
//     // const commitment = await client.getCurrentCommitment();
//     // console.log(commitment)
//     // console.dir(worker)
//   } catch (error) {
//     console.log(`Error: ${error}`);
//   }
// }

// startLightClient();



// Listen for tab activation to update icons
browser.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await browser.tabs.get(activeInfo.tabId);
    if (tab.url && tab.url.startsWith('https://')) {
      const domain = new URL(tab.url).origin;
      // Check stored state first
      if (domainStates.has(domain)) {
        await updateIconForDomain(domain, domainStates.get(domain)!);
      } else {
        const verificationStore = await DomainVerificationStore.getInstance();
        const verification = await verificationStore.verificationForDomain(domain);
        const isValid = verification?.logVerifications.some(v => v.valid) ?? null;
        await updateIconForDomain(domain, isValid);
      }
    } else {
      // Non-HTTPS sites get gray icon
      if (tab.id !== undefined) {
        await browser.action.setIcon({
          tabId: tab.id,
          path: {
            16: "images/icon16_gray.png",
            32: "images/icon32_gray.png",
            48: "images/icon48_gray.png",
            128: "images/icon128_gray.png"
          }
        });
      }
    }
  } catch (error) {
    console.error("Error updating icon on tab switch:", error);
  }
});

// Listen for tab updates
browser.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('https://')) {
    const domain = new URL(tab.url).origin;
    if (domainStates.has(domain)) {
      await updateIconForDomain(domain, domainStates.get(domain)!);
    }
  }
});

browser.webRequest.onHeadersReceived.addListener(
  async function (details) {
    if (details.url === CtLogStore.LOG_LIST_URL) {
      // Avoid deadlock for log list URL
      return;
    }

    const domain = new URL(details.url).origin;

    try {
      const securityInfo = await browser.webRequest.getSecurityInfo(
        details.requestId,
        { certificateChain: true, rawDER: true },
      );

      if (securityInfo.state !== "secure" && securityInfo.state !== "weak") {
        // Non-HTTPS requests can't be verified
        await updateIconForDomain(domain, null);
        return;
      }

      if (securityInfo.certificates.length < 2) {
        // 0 = No certificate at all - error
        // 1 = No issuer (e.g. self signed) - can't query CT log
        await updateIconForDomain(domain, false);
        return;
      }

      const certDer = new Uint8Array(securityInfo.certificates[0].rawDER);
      const issuerDer = new Uint8Array(securityInfo.certificates[1].rawDER);

      const ctLogStore = await CtLogStore.getInstance();

      const domainVerificationStore = await DomainVerificationStore.getInstance();
      await domainVerificationStore.clearVerificationForDomain(domain);

      // Set initial pending state
      await updateIconForDomain(domain, null);

      const scts = sctsFromCertDer(certDer);
      let STHValid = false;
      let hasInvalidCert = false; // Add this flag

      for (const sct of scts) {
        try {
          const b64LogId = b64EncodeBytes(new Uint8Array(sct.logId));
          const log = ctLogStore.getLogById(b64LogId);

          if (log === undefined) {
            console.log("CT Log", b64LogId, "not found");
            continue;
          }
          
          console.log("Cert in", log.url);
          const leafHash = await leafHashForPreCert(
            certDer,
            issuerDer,
            sct.timestamp,
            new Uint8Array(sct.extensions),
          );
          const b64LeafHash = b64EncodeBytes(leafHash);
          console.log(log.description, "B64 Leaf Hash:", b64LeafHash);

          const ctClient = new CTLogClient(log.url);
          // TODO: Acquire that from prism instead
          const prismClient = new PrismCtClient(prism_client_url);
          
          console.log(await prismClient.fetchAccount(b64LogId));
          const fetchedAccount = await prismClient.fetchAccount(b64LogId);
          const serializedData = atob(fetchedAccount['account']['signed_data']['0']['data']);
          if (!serializedData) {
            hasInvalidCert = true;
            await domainVerificationStore.reportLogVerification(
              domain, 
              log.description,
              false
            );
          } else {
          // Parse the string into a JSON object
          const prismSTH = JSON.parse(serializedData);
          // console.log(prismSTH['root_hash'])
          const rootHashPrism = b64EncodeBytes(prismSTH['root_hash']);
          
          // const latestCommitmentHex = await prismClient.getCommitment();

            let logSth;
            try {
            logSth = await ctClient.getSignedTreeHead();
            } catch (error) {
            console.error("Failed to fetch SignedTreeHead:", error);
            await domainVerificationStore.reportLogVerification(
              domain,
              log.description,
              false
            );
            continue;
            }
          const proof = await ctClient.getProofByHash(
            b64LeafHash,
            logSth.tree_size,
          );

          const prismProof = await ctClient.getProofByHash(
            b64LeafHash,
            prismSTH['tree_size']
          );

          const prismSTHValidity = await validateProof(
            prismProof,
            leafHash,
            prismSTH['root_hash']
          );
          console.log("prismValidity:",prismSTHValidity);


          const expectedRootHash = b64DecodeBytes(logSth.sha256_root_hash);
          const CTLogsValidity = await validateProof(
            proof,
            leafHash,
            expectedRootHash,
          );

          console.log('from xenon validity:',CTLogsValidity);

          await domainVerificationStore.reportLogVerification(
            domain,
            log.description,
            CTLogsValidity && prismSTHValidity
          );

          if (prismSTHValidity && CTLogsValidity) {
            STHValid = true;
          } else {
            hasInvalidCert = true; // Set flag if any cert is invalid
          }
        }

        } catch (error) {
          console.error("Error validating SCT:", error);
          hasInvalidCert = true;
        }
      }

      // Only show valid if we have at least one valid cert AND no invalid certs
      await updateIconForDomain(domain, STHValid && !hasInvalidCert);

    } catch (error) {
      console.error("Error validating cert:", error);
      await updateIconForDomain(domain, false);
    }

    return {};
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["blocking"],
);

browser.runtime.onMessage.addListener(async (request, sender, sendResponse) => {
  const domain = new URL(request.url).origin;
  if (request.action === "getDomainVerification") {
    const verificationStore = await DomainVerificationStore.getInstance();
    return await verificationStore.verificationForDomain(domain);
  }
});
