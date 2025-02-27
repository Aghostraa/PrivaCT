export type Key = {
  algorithm: string;
  bytes: string;
};

export type SignedData = {
  key: Key;
  data: string;
};

export type Account = {
  id: string;
  nonce: number;
  valid_keys: Key[];
  signed_data: SignedData[];
  service_challenge: string | null;
};

export type Proof = {
  leaf: string;
  siblings: string[];
};

export type AccountResponse = {
  account: Account;
  proof: Proof;
};

export type CommitmentResponse = {
  commitment: string;
};