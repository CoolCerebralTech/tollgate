/**
 * @file index.ts
 * TollgateSigner — the only class a developer needs to import.
 *
 * Design note on viem clients:
 *   viem 2.x Base/OP Stack chains include deposit transaction types that
 *   create a type mismatch when storing PublicClient/WalletClient as class
 *   properties with generic types. The clean solution is to not store viem
 *   clients as properties — create them per-call from stored config.
 *   This is the correct pattern for an SDK library (no long-lived connections).
 */

import {
  createWalletClient,
  createPublicClient,
  http,
  parseAbi,
  type Hash,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { baseSepolia, base }   from 'viem/chains';

import { TollgateClient }      from './api.js';
import { injectTollgateToken } from './encoder.js';
import {
  type TollgateConfig,
  type TxRequest,
  type ActionRequest,
  type NotaryResponse,
  BASE_SEPOLIA_CHAIN_ID,
  BASE_MAINNET_CHAIN_ID,
} from './types.js';
import {
  TollgateConfigError,
  TollgateTransactionDeniedError,
  TollgateTokenExpiredError,
  TollgateOnChainError,
} from './errors.js';

// ── GNOSIS SAFE ABI (minimal) ─────────────────────────────────────────────────

const SAFE_ABI = parseAbi([
  'function execTransaction(address to, uint256 value, bytes calldata data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address payable refundReceiver, bytes memory signatures) public payable returns (bool)',
  'function nonce() public view returns (uint256)',
  'function getTransactionHash(address to, uint256 value, bytes calldata data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address payable refundReceiver, uint256 _nonce) public view returns (bytes32)',
]);

const ZERO_ADDR = '0x0000000000000000000000000000000000000000' as const;

// ── CHAIN SELECTION ───────────────────────────────────────────────────────────
// Typed as a discriminated helper so TypeScript infers the correct chain
// for each createPublicClient / createWalletClient call.

function selectChain(useMainnet: boolean | undefined) {
  return useMainnet ? base : baseSepolia;
}

// ── TOLLGATE SIGNER ───────────────────────────────────────────────────────────

export class TollgateSigner {
  // Only store serialisable config + derived primitives.
  // Viem clients are created fresh per-call to avoid OP Stack generic conflicts.
  private readonly config: TollgateConfig;
  private readonly chainId: number;
  private readonly notaryClient: TollgateClient;

  private constructor(config: TollgateConfig) {
    this.config  = config;
    this.chainId = config.useMainnet ? BASE_MAINNET_CHAIN_ID : BASE_SEPOLIA_CHAIN_ID;

    this.notaryClient = new TollgateClient(
      config.notaryUrl,
      config.agentToken,
      config.notaryTimeoutMs ?? 10_000,
      config.maxRetries      ?? 3,
    );
  }

  // ── VIEM CLIENT FACTORIES (private) ──────────────────────────────────────────

  private _publicClient() {
    return createPublicClient({
      chain:     selectChain(this.config.useMainnet),
      transport: http(),
    });
  }

  private _walletClient() {
    const account = privateKeyToAccount(this.config.ownerPrivateKey);
    return createWalletClient({
      account,
      chain:     selectChain(this.config.useMainnet),
      transport: http(),
    });
  }

  // ── FACTORY ──────────────────────────────────────────────────────────────────

  /**
   * Creates a TollgateSigner after validating config and health-checking
   * the Notary. Always use this instead of `new TollgateSigner()`.
   *
   * @throws TollgateConfigError            if any required field is missing
   * @throws TollgateNotaryUnreachableError  if the Notary is not reachable
   */
  static async create(config: TollgateConfig): Promise<TollgateSigner> {
    if (!config.notaryUrl)       throw new TollgateConfigError('notaryUrl is required');
    if (!config.agentToken)      throw new TollgateConfigError('agentToken is required');
    if (!config.agentId)         throw new TollgateConfigError('agentId is required');
    if (!config.safeAddress)     throw new TollgateConfigError('safeAddress is required');
    if (!config.ownerPrivateKey) throw new TollgateConfigError('ownerPrivateKey is required');
    if (!config.notaryUrl.startsWith('http')) {
      throw new TollgateConfigError('notaryUrl must start with http:// or https://');
    }

    const signer = new TollgateSigner(config);
    await signer.notaryClient.healthCheck();
    return signer;
  }

  // ── SEND TRANSACTION ─────────────────────────────────────────────────────────

  /**
   * The only method a developer calls.
   *
   * Requests Notary approval, encodes the token into calldata, and submits
   * the transaction through the Gnosis Safe on Base.
   *
   * @throws TollgateTransactionDeniedError    if Notary denies the request
   * @throws TollgateHumanApprovalTimeoutError if human approval times out
   * @throws TollgateTokenExpiredError          if token expires before submission
   * @throws TollgateOnChainError               if the Safe transaction reverts
   */
  async sendTransaction(params: TxRequest): Promise<Hash> {
    // ── Step 1: Build ActionRequest ───────────────────────────────────────────
    const purpose = params.purpose ?? this.config.defaultPurpose ?? '';
    if (!purpose) {
      throw new TollgateConfigError(
        'purpose is required — set it on TxRequest or TollgateConfig.defaultPurpose',
      );
    }

    const request: ActionRequest = {
      agent_id:    this.config.agentId,
      action:      'transfer',
      destination: params.to,
      amount_usd:  params.amountUsd,
      amount_raw:  params.value.toString(),
      purpose,
      chain_id:    this.chainId,
      nonce:       crypto.randomUUID(),
      timestamp:   new Date().toISOString(),
    };

    // ── Step 2: Request Notary approval ───────────────────────────────────────
    let response: NotaryResponse = await this.notaryClient.requestApproval(request);

    // ── Step 3: Handle human approval ─────────────────────────────────────────
    if (response.status === 'denied') {
      throw new TollgateTransactionDeniedError(response.code, response.message);
    }

    if (response.status === 'pending_human') {
      this.config.onPendingHumanApproval?.(response.decision_id);
      response = await this.notaryClient.pollDecision(
        response.decision_id,
        this.config.humanApprovalPollIntervalMs ?? 3_000,
        this.config.humanApprovalTimeoutMs      ?? 300_000,
      );
      if (response.status === 'denied') {
        throw new TollgateTransactionDeniedError(response.code, response.message);
      }
      if (response.status === 'approved') {
        this.config.onHumanApprovalReceived?.(response.decision_id);
      }
    }

    if (response.status !== 'approved') {
      throw new TollgateTransactionDeniedError('UNKNOWN', 'Unexpected Notary response');
    }

    const token = response.approval_token;

    // ── Step 4: Check token expiry ────────────────────────────────────────────
    const bufferSec = this.config.tokenExpiryBufferSeconds ?? 10;
    const expiresIn = new Date(token.expires_at).getTime() / 1000 - Date.now() / 1000;
    if (expiresIn < bufferSec) {
      throw new TollgateTokenExpiredError(token.token_id, token.expires_at);
    }

    // ── Step 5: Inject token into calldata ────────────────────────────────────
    const modifiedData = injectTollgateToken(params.data ?? '0x', token);

    // ── Steps 6-10: Chain interactions ───────────────────────────────────────
    // Create clients fresh — correct types inferred from selectChain().
    const publicClient = this._publicClient();
    const walletClient = this._walletClient();
    const account      = privateKeyToAccount(this.config.ownerPrivateKey);

    // Step 6: Read Safe nonce
    const safeNonce = await publicClient.readContract({
      address:      this.config.safeAddress,
      abi:          SAFE_ABI,
      functionName: 'nonce',
    });

    // Step 7: Get Safe transaction hash
    const safeTxHash = await publicClient.readContract({
      address:      this.config.safeAddress,
      abi:          SAFE_ABI,
      functionName: 'getTransactionHash',
      args: [
        params.to, params.value, modifiedData,
        0, 0n, 0n, 0n,
        ZERO_ADDR, ZERO_ADDR,
        safeNonce,
      ],
    });

    // Step 8: Sign the Safe tx hash
    const sig = await account.signMessage({
      message: { raw: safeTxHash as `0x${string}` },
    });

    // Step 9: Submit execTransaction
    const txHash = await walletClient.writeContract({
      address:      this.config.safeAddress,
      abi:          SAFE_ABI,
      functionName: 'execTransaction',
      args: [
        params.to, params.value, modifiedData,
        0, 0n, 0n, 0n,
        ZERO_ADDR, ZERO_ADDR,
        sig,
      ],
    });

    // Step 10: Wait for receipt
    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status === 'reverted') {
      throw new TollgateOnChainError(txHash, 'Transaction reverted at Guard');
    }

    return txHash;
  }

  // ── SIMULATE ──────────────────────────────────────────────────────────────────

  /**
   * Calls the Notary and returns the decision without submitting on-chain.
   * Useful for testing policy rules and verifying connectivity.
   */
  async simulate(params: TxRequest): Promise<NotaryResponse> {
    const purpose = params.purpose ?? this.config.defaultPurpose ?? '';
    const request: ActionRequest = {
      agent_id:    this.config.agentId,
      action:      'transfer',
      destination: params.to,
      amount_usd:  params.amountUsd,
      amount_raw:  params.value.toString(),
      purpose,
      chain_id:    this.chainId,
      nonce:       crypto.randomUUID(),
      timestamp:   new Date().toISOString(),
    };
    return this.notaryClient.requestApproval(request);
  }

  /** Returns the Safe address this signer is configured for. */
  getAddress(): `0x${string}` { return this.config.safeAddress; }

  /** Returns the chain ID (84532 = Base Sepolia, 8453 = Base Mainnet). */
  getChainId(): number { return this.chainId; }
}

// ── PUBLIC EXPORTS ────────────────────────────────────────────────────────────
export type {
  TollgateConfig,
  TxRequest,
  ApprovalToken,
  NotaryResponse,
} from './types.js';
export * from './errors.js';