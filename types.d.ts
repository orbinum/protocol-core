/**
 * Definiciones de tipos TypeScript para @orbinum/wallet-core-wasm
 * 
 * Estas definiciones mapean exactamente a los tipos Rust en wallet-core-wasm
 * para proporcionar type-safety en aplicaciones TypeScript.
 * 
 * @module @orbinum/wallet-core-wasm
 * @version 1.0.0
 */

// ============================================================================
// Tipos Primitivos
// ============================================================================

/** Commitment Poseidon de 32 bytes */
export type Commitment = Uint8Array; // 32 bytes

/** Nullifier para prevenir double-spending */
export type Nullifier = Uint8Array; // 32 bytes

/** Hash (Merkle root) */
export type Hash = Uint8Array; // 32 bytes

/** Dirección Ethereum/Substrate */
export type Address = Uint8Array; // 20 bytes

/** Asset ID */
export type AssetId = number; // u32

/** Amount en unidades base */
export type Amount = bigint; // u128 en Rust

/** Nonce de cuenta */
export type Nonce = number; // u32

/** Block number */
export type BlockNumber = number; // u32

/** Encrypted memo (variable, max 256 bytes) */
export type EncryptedMemo = Uint8Array;

/** ZK Proof (Groth16, ~256 bytes) */
export type ZKProof = Uint8Array;

// ============================================================================
// Parámetros de Extrinsics
// ============================================================================

/**
 * Parámetros para Shield (deposit)
 */
export interface ShieldParams {
  /** Cantidad a depositar en unidades base */
  amount: Amount;
  /** ID del asset (0 = nativo ORB) */
  assetId: AssetId;
  /** Commitment del note */
  commitment: Commitment;
  /** Memo encriptado (104 o 256 bytes) */
  encryptedMemo: EncryptedMemo;
}

/**
 * Una operación individual en shield batch
 */
export interface ShieldOperation {
  assetId: AssetId;
  amount: Amount;
  commitment: Commitment;
  encryptedMemo: EncryptedMemo;
}

/**
 * Parámetros para Shield Batch
 */
export interface ShieldBatchParams {
  /** Array de operaciones (max 20) */
  operations: ShieldOperation[];
}

/**
 * Parámetros para Private Transfer
 */
export interface PrivateTransferParams {
  /** ZK proof */
  proof: ZKProof;
  /** Merkle root histórico */
  merkleRoot: Hash;
  /** Nullifiers de inputs (2) */
  inputNullifiers: [Nullifier, Nullifier];
  /** Commitments de outputs (2) */
  outputCommitments: [Commitment, Commitment];
  /** Memos encriptados (2) */
  encryptedMemos: [EncryptedMemo, EncryptedMemo];
}

/**
 * Parámetros para Unshield (withdrawal)
 */
export interface UnshieldParams {
  /** ZK proof */
  proof: ZKProof;
  /** Merkle root histórico */
  merkleRoot: Hash;
  /** Nullifier del note */
  nullifier: Nullifier;
  /** Asset ID a retirar */
  assetId: AssetId;
  /** Cantidad a retirar */
  amount: Amount;
  /** Cuenta receptora */
  recipient: Address;
}

/**
 * Información de un auditor
 */
export interface AuditorInfo {
  /** Cuenta del auditor */
  account: Address;
  /** Public key opcional (viewing key) */
  publicKey?: Uint8Array; // 32 bytes
  /** Autorizado desde bloque */
  authorizedFrom: BlockNumber;
}

/**
 * Tipos de condiciones de disclosure
 */
export type DisclosureCondition =
  | { type: 'AmountAbove'; threshold: Amount }
  | { type: 'TimeElapsed'; blocks: BlockNumber }
  | { type: 'ManualApproval' };

/**
 * Parámetros para Set Audit Policy
 */
export interface SetAuditPolicyParams {
  /** Lista de auditores autorizados (max 10) */
  auditors: AuditorInfo[];
  /** Condiciones de disclosure (max 10) */
  conditions: DisclosureCondition[];
  /** Frecuencia máxima (bloques entre disclosures) */
  maxFrequency?: BlockNumber;
}

/**
 * Parámetros para Request Disclosure
 */
export interface RequestDisclosureParams {
  /** Cuenta objetivo */
  target: Address;
  /** Razón de la solicitud (max 256 bytes) */
  reason: Uint8Array;
  /** Evidencia opcional (max 1024 bytes) */
  evidence?: Uint8Array;
}

/**
 * Parámetros para Approve Disclosure
 */
export interface ApproveDisclosureParams {
  /** Auditor que solicitó */
  auditor: Address;
  /** Commitment a divulgar */
  commitment: Commitment;
  /** ZK proof */
  zkProof: ZKProof;
  /** Datos revelados */
  disclosedData: Uint8Array;
}

/**
 * Parámetros para Reject Disclosure
 */
export interface RejectDisclosureParams {
  /** Auditor que solicitó */
  auditor: Address;
  /** Razón del rechazo (max 256 bytes) */
  reason: Uint8Array;
}

/**
 * Parámetros para Submit Disclosure
 */
export interface SubmitDisclosureParams {
  /** Commitment siendo divulgado */
  commitment: Commitment;
  /** Groth16 proof (256 bytes) */
  proofBytes: Uint8Array;
  /** Public signals (76 bytes) */
  publicSignals: Uint8Array;
  /** Datos parciales revelados */
  partialData: Uint8Array;
  /** Auditor opcional */
  auditor?: Address;
}

/**
 * Una submisión individual de disclosure
 */
export interface DisclosureSubmission {
  commitment: Commitment;
  proof: Uint8Array;
  publicSignals: Uint8Array;
  disclosedData: Uint8Array;
}

/**
 * Parámetros para Batch Submit Disclosure
 */
export interface BatchSubmitDisclosureParams {
  /** Submisiones (max 10) */
  submissions: DisclosureSubmission[];
}

// ============================================================================
// API Principal de wallet-core-wasm
// ============================================================================

/**
 * Transaction Builder API (sin firma)
 * 
 * Construye call data sin firmar para cada extrinsic.
 * La firma se realiza externamente con wallet o extension.
 */
export interface WasmTransactionBuilder {
  /**
   * Construye transacción Shield sin firmar
   * 
   * @param amount - Cantidad en string (para JS bigint)
   * @param assetId - ID del asset
   * @param commitment - Commitment (32 bytes)
   * @param encryptedMemo - Memo encriptado
   * @param nonce - Nonce de la cuenta
   * @returns Call data encoded (Uint8Array)
   */
  buildShieldUnsigned(
    amount: string,
    assetId: number,
    commitment: Uint8Array,
    encryptedMemo: Uint8Array,
    nonce: number
  ): Uint8Array;

  /**
   * Construye transacción Shield Batch sin firmar
   */
  buildShieldBatchUnsigned(
    operations: ShieldOperation[],
    nonce: number
  ): Uint8Array;

  /**
   * Construye transacción Private Transfer sin firmar
   */
  buildTransferUnsigned(
    inputNullifiers: [Uint8Array, Uint8Array],
    outputCommitments: [Uint8Array, Uint8Array],
    root: Uint8Array,
    proof: Uint8Array,
    encryptedMemos: [Uint8Array, Uint8Array],
    nonce: number
  ): Uint8Array;

  /**
   * Construye transacción Unshield sin firmar
   */
  buildUnshieldUnsigned(
    nullifier: Uint8Array,
    amount: string,
    assetId: number,
    recipient: Uint8Array,
    root: Uint8Array,
    proof: Uint8Array,
    nonce: number
  ): Uint8Array;

  /**
   * Construye transacción Set Audit Policy sin firmar
   */
  buildSetAuditPolicyUnsigned(
    auditors: AuditorInfo[],
    conditions: DisclosureCondition[],
    maxFrequency: number | null,
    nonce: number
  ): Uint8Array;

  /**
   * Construye transacción Request Disclosure sin firmar
   */
  buildRequestDisclosureUnsigned(
    target: Uint8Array,
    reason: Uint8Array,
    evidence: Uint8Array | null,
    nonce: number
  ): Uint8Array;

  /**
   * Construye transacción Approve Disclosure sin firmar
   */
  buildApproveDisclosureUnsigned(
    auditor: Uint8Array,
    commitment: Uint8Array,
    zkProof: Uint8Array,
    disclosedData: Uint8Array,
    nonce: number
  ): Uint8Array;

  /**
   * Construye transacción Reject Disclosure sin firmar
   */
  buildRejectDisclosureUnsigned(
    auditor: Uint8Array,
    reason: Uint8Array,
    nonce: number
  ): Uint8Array;

  /**
   * Construye transacción Submit Disclosure sin firmar
   */
  buildSubmitDisclosureUnsigned(
    commitment: Uint8Array,
    proofBytes: Uint8Array,
    publicSignals: Uint8Array,
    partialData: Uint8Array,
    auditor: Uint8Array | null,
    nonce: number
  ): Uint8Array;

  /**
   * Construye transacción Batch Submit Disclosure sin firmar
   */
  buildBatchSubmitDisclosureUnsigned(
    submissions: DisclosureSubmission[],
    nonce: number
  ): Uint8Array;

  /**
   * Combina call data con firma externa
   * 
   * @param callData - Call data sin firmar
   * @param signature - Firma (65 bytes)
   * @param address - Dirección del firmante (20 bytes)
   * @param nonce - Nonce
   * @returns Extrinsic firmado completo
   */
  buildSignedExtrinsic(
    callData: Uint8Array,
    signature: Uint8Array,
    address: Uint8Array,
    nonce: number
  ): Uint8Array;
}

// ============================================================================
// Helpers y Utilidades
// ============================================================================

/**
 * Convierte hex string a Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array;

/**
 * Convierte Uint8Array a hex string
 */
export function bytesToHex(bytes: Uint8Array): string;

/**
 * Valida que un commitment tenga el tamaño correcto (32 bytes)
 */
export function isValidCommitment(commitment: Uint8Array): boolean;

/**
 * Valida que un nullifier tenga el tamaño correcto (32 bytes)
 */
export function isValidNullifier(nullifier: Uint8Array): boolean;

/**
 * Valida que una dirección tenga el tamaño correcto (20 bytes)
 */
export function isValidAddress(address: Uint8Array): boolean;

/**
 * Valida que un memo encriptado tenga tamaño válido (max 256 bytes)
 */
export function isValidEncryptedMemo(memo: Uint8Array): boolean;

// ============================================================================
// Inicialización WASM
// ============================================================================

/**
 * Inicializa el módulo WASM
 * Debe ser llamado antes de usar cualquier función
 * 
 * @example
 * ```typescript
 * import init from '@orbinum/wallet-core-wasm';
 * 
 * await init();
 * // Ahora se pueden usar las funciones
 * ```
 */
export default function init(input?: RequestInfo | URL): Promise<void>;

// ============================================================================
// Re-exports
// ============================================================================

export {
  WasmTransactionBuilder as TransactionBuilder,
};
