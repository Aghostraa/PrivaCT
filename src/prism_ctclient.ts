import { AccountResponse, CommitmentResponse} from "./prism_types"
export class PrismCtClient {
  constructor(private baseUrl: string) {
    // Optionally, you can validate or process the baseUrl here.
  }

  // Helper to join the base URL and path correctly
  private joinUrl(path: string): string {
    // Remove any trailing slash from baseUrl and any leading slash from path
    return `${this.baseUrl.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
  }

  // Fetches the account data by sending a POST request with an account ID in the body.
  async fetchAccount(accountId: string): Promise<AccountResponse> {
    const url = this.joinUrl('/get-account');
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ id: accountId }),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch account: ${response.statusText}`);
    }

    const data: AccountResponse = await response.json();
    return data;
  }

  // Adding functionality to get commitment
  async getCommitment(): Promise<CommitmentResponse> {
    const url = this.joinUrl('/get-current-commitment');
    const response = await fetch(url, {
      method: 'GET'
      // headers: {
      //   'Content-Type': 'application/json',
      // }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch account: ${response.statusText}`);
    }

    const data: CommitmentResponse = await response.json();
    return data;
  }
}
