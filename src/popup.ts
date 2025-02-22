import {
  DomainVerification,
  DomainVerificationStore,
} from "./verification_store";

const CHECKMARK = "\u2705";
const CROSS = "\u274C";

document.addEventListener("DOMContentLoaded", async function () {
  const domainResultsTable = document.getElementById("domain-results");
  const domainHeadline = document.getElementById("domain");

  const tabs = await browser.tabs.query({
    active: true,
    currentWindow: true,
  });
  const currentTab = tabs[0];

  if (!currentTab.url) {
    document.body.setAttribute('data-has-content', 'false');
    return;
  }

  if (!currentTab.url.startsWith("https://")) {
    document.body.setAttribute('data-has-content', 'false');
    return;
  }

  const domainVerification = (await browser.runtime.sendMessage({
    action: "getDomainVerification",
    url: currentTab.url,
  })) as DomainVerification | undefined;

  if (domainVerification === undefined) {
    document.body.setAttribute('data-has-content', 'false');
    return;
  }

  // Set content state to true before updating the DOM
  document.body.setAttribute('data-has-content', 'true');

  domainHeadline.textContent = domainVerification.name;
  domainResultsTable.replaceChildren();

  for (const logVerification of domainVerification.logVerifications) {
    const domainRow = document.createElement("div");
    domainRow.className = "row";

    const nameCell = document.createElement("div");
    nameCell.textContent = logVerification.name;
    nameCell.classList.add("cell", "name-cell");

    const validCell = document.createElement("div");
    validCell.textContent = logVerification.valid ? CHECKMARK : CROSS;
    validCell.classList.add("cell", "valid-cell");

    const dateCell = document.createElement("div");
    dateCell.textContent = new Date(logVerification.date).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
    dateCell.classList.add("cell", "date-cell");

    domainRow.appendChild(nameCell);
    domainRow.appendChild(validCell);
    domainRow.appendChild(dateCell);

    domainResultsTable.appendChild(domainRow);
  }
});