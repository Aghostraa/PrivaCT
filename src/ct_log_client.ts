import { CtSignedTreeHead, CtMerkleProof, CtLogEntry } from './ct_log_types';

interface CtEntriesResponse {
  entries: CtLogEntry[];
}

export class CTLogClient {
  private baseUrl: URL;

  constructor(baseUrl: string | URL) {
    this.baseUrl = new URL(baseUrl);
  }

  async getSignedTreeHead(): Promise<CtSignedTreeHead> {
    return await this.fetchJson("/ct/v1/get-sth", {});
  }

  async getProofByHash(
    b64entryHash: string,
    treeSize: number,
  ): Promise<CtMerkleProof> {
    const params = {
      hash: b64entryHash,
      tree_size: treeSize,
    };
    return await this.fetchJson("/ct/v1/get-proof-by-hash", params);
  }

  async getEntries(start: number, end: number): Promise<CtEntriesResponse> {
    const params = {
      start,
      end,
    };
    return await this.fetchJson("/ct/v1/get-entries", params);
  }

  private async fetchJson<T>(
    endpoint: string,
    params: Record<string, string | number>,
  ): Promise<T> {
    const url = new URL(this.baseUrl);
    url.pathname = [url.pathname, endpoint].join("/").replace(/\/+/g, "/");
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.append(key, value.toString());
    }
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`CT Log request failed: ${response.statusText}`);
    }

    return await response.json();
  }

  async getConsistencyProof(
    first: number,
    second: number
  ): Promise<object> {
    const params = {
      first: first,
      second: second,
    };
    return await this.fetchJson("/ct/v1/get-sth-consistency", params);
  }


}
