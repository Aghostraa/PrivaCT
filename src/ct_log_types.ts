export interface CtUsableState {
  timestamp: string;
}

export interface CtReadonlyState {
  timestamp: string;
  final_tree_head: {
    sha256_root_hash: string;
    tree_size: number;
  };
}

export interface CtRetiredState {
  timestamp: string;
}

export interface CtLogState {
  usable?: CtUsableState;
  readonly?: CtReadonlyState;
  retired?: CtRetiredState;
}

export interface CtTemporalInterval {
  start_inclusive: string;
  end_exclusive: string;
}

export interface CtLog {
  description: string;
  log_id: string;
  key: string;
  url: string;
  mmd: number;
  state: CtLogState;
  temporal_interval?: CtTemporalInterval;
}

export interface CtLogOperator {
  name: string;
  email: string[];
  logs: CtLog[];
  tiled_logs: any[]; // unknown
}

export interface CtLogList {
  version: string;
  log_list_timestamp: string;
  operators: CtLogOperator[];
}

export interface CtMerkleProof {
  leaf_index: number;
  audit_path: string[];
}

export interface CtLogEntry {
  leaf_input: string;
  extra_data: string;
}

export interface CtSignedTreeHead {
  tree_size: number;
  timestamp: number;
  sha256_root_hash: string;
  tree_head_signature: string;
}

export interface SignedTreeHead {
    treeSize: number;
    timestamp: number;
    rootHash: Uint8Array;
    signature: Uint8Array;
}

export function deserializeSignedTreeHead(buffer: ArrayBuffer): SignedTreeHead {
    const dataView = new DataView(buffer);
    let offset = 0;

    const treeSize = dataView.getBigUint64(offset, true);
    offset += 8;

    const timestamp = dataView.getBigUint64(offset, true);
    offset += 8;

    const rootHash = new Uint8Array(buffer, offset, 32);
    offset += 32;

    const signature = new Uint8Array(buffer, offset);

    return {
        treeSize: Number(treeSize),
        timestamp: Number(timestamp),
        rootHash,
        signature,
    };
}

