import { b64DecodeBytes, b64EncodeBytes } from "./conversion";
import { CTLogClient } from "./ct_log_client";
import { CtLogStore } from "./ct_log_store";
import { leafHashForPreCert, sctsFromCertDer } from "./ct_parsing";
import { validateProof } from "./ct_proof_validation";
import { DomainVerificationStore } from "./verification_store";

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

async function run_node() {
  // TODO: Replace with actually running a prism light node
  let i = 0;
  while (true) {
    await sleep(5000);
    i += 1;
    console.log(`Node is still running ... ${i}`);
  }
}

run_node();

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
      let anyValid = false;

      for (const sct of scts) {
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
        
        const logSth = await ctClient.getSignedTreeHead();
        const proof = await ctClient.getProofByHash(
          b64LeafHash,
          logSth.tree_size,
        );

        const expectedRootHash = b64DecodeBytes(logSth.sha256_root_hash);
        const verificationResult = await validateProof(
          proof,
          leafHash,
          expectedRootHash,
        );

        await domainVerificationStore.reportLogVerification(
          domain,
          log.description,
          verificationResult,
        );

        if (verificationResult) {
          anyValid = true;
          break; // Exit early if we find a valid verification
        }
      }

      // Update icon with final status
      await updateIconForDomain(domain, anyValid);

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