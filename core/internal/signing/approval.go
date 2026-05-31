package signing

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	gocrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

// ApprovalToken is the signed artifact Tollgate returns on a successful evaluation.
// The Guard smart contract in Phase 2 verifies the Signature field on-chain
// using ecrecover to confirm Tollgate approved this exact transaction payload.
//
// SECURITY: Every field that is signed is also returned in the token so the
// Guard — and any auditor — can independently verify the signature covers
// exactly what was approved. Nothing is hidden.
type ApprovalToken struct {
	// Identity
	TokenID       string `json:"token_id"` // UUID v4 — unique per token
	AgentID       string `json:"agent_id"`
	PolicyVersion string `json:"policy_version"` // exact policy version that approved this
	PolicyHash    string `json:"policy_hash"`    // keccak256 of policy.yaml at decision time

	// What was approved
	Action      string  `json:"action"`
	Destination string  `json:"destination"`
	AmountUSD   float64 `json:"amount_usd"`
	AmountRaw   string  `json:"amount_raw"` // exact on-chain amount — string to avoid float errors
	Purpose     string  `json:"purpose"`
	ChainID     int64   `json:"chain_id"` // 8453 = Base mainnet, 84532 = Base testnet
	Nonce       string  `json:"nonce"`    // the nonce from the original request

	// Timing — critical for replay prevention
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"` // IssuedAt + TTL from config

	// Risk metadata
	RiskScore    float64 `json:"risk_score"`
	AutoApproved bool    `json:"auto_approved"`

	// Cryptographic proof — what the Guard verifies on-chain
	Signature string `json:"signature"` // hex-encoded 65-byte ECDSA sig over EIP-712 hash
}

// BuildRequest carries all inputs needed to construct and sign an ApprovalToken.
type BuildRequest struct {
	AgentID       string
	PolicyVersion string
	PolicyHash    string
	Action        string
	Destination   string
	AmountUSD     float64
	AmountRaw     string
	Purpose       string
	ChainID       int64
	Nonce         string
	TTLSeconds    int
	RiskScore     float64
	AutoApproved  bool
}

// BuildApprovalToken constructs an ApprovalToken, computes its EIP-712 hash,
// signs it with Tollgate's ECDSA key, and returns the complete signed token.
//
// EIP-712 is used instead of raw JSON hashing because:
//  1. The Guard contract verifies the hash cheaply on-chain using ecrecover.
//     Raw JSON string hashing would require expensive string parsing in Solidity.
//  2. EIP-712 is typed — it prevents cross-domain replay attacks by binding
//     the hash to a specific contract address and chain ID.
//  3. It is the Ethereum standard — wallets and tools understand it natively.
func (s *Signer) BuildApprovalToken(req BuildRequest) (*ApprovalToken, error) {
	now := time.Now().UTC()
	tokenID := uuid.New().String()

	token := &ApprovalToken{
		TokenID:       tokenID,
		AgentID:       req.AgentID,
		PolicyVersion: req.PolicyVersion,
		PolicyHash:    req.PolicyHash,
		Action:        req.Action,
		Destination:   req.Destination,
		AmountUSD:     req.AmountUSD,
		AmountRaw:     req.AmountRaw,
		Purpose:       req.Purpose,
		ChainID:       req.ChainID,
		Nonce:         req.Nonce,
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Duration(req.TTLSeconds) * time.Second),
		RiskScore:     req.RiskScore,
		AutoApproved:  req.AutoApproved,
	}

	// Compute the EIP-712 hash over the token fields.
	hash, err := eip712Hash(token)
	if err != nil {
		return nil, fmt.Errorf("signing: EIP-712 hash failed: %w", err)
	}

	// Sign the hash with Tollgate's ECDSA key.
	sig, err := s.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("signing: token signing failed: %w", err)
	}

	token.Signature = "0x" + hex.EncodeToString(sig)
	return token, nil
}

// ── EIP-712 Implementation ────────────────────────────────────────────────────
//
// EIP-712 structured data hashing follows this pipeline:
//
//   finalHash = keccak256(0x1901 ‖ domainSeparatorHash ‖ structHash(ApprovalToken))
//
// The domain separator binds the hash to this specific application (Tollgate)
// and chain, preventing a valid token on one chain from being replayed on another.
//
// The struct hash packs typed fields in ABI encoding order — exactly what the
// Guard's ecrecover verification expects in Phase 2.
//
// Field ordering and types are LOCKED. Changing them breaks on-chain verification.

// eip712DomainTypeHash is keccak256 of the EIP-712 domain type string.
// Computed once — this string is defined by EIP-712 and never changes.
var eip712DomainTypeHash = gocrypto.Keccak256Hash(
	[]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
)

// eip712TypeHash is keccak256 of the ApprovalToken type string.
// Field order and types are LOCKED — must match the Guard contract in Phase 2.
var eip712TypeHash = gocrypto.Keccak256Hash(
	[]byte("ApprovalToken(bytes32 tokenId,string agentId,address destination,uint256 amountRaw,uint256 chainId,bytes32 nonce,uint256 expiresAt,bytes32 policyHash)"),
)

// eip712Hash computes the final EIP-712 hash for the given token.
// This is the 32-byte value that gets signed with ECDSA.
func eip712Hash(token *ApprovalToken) ([]byte, error) {
	// ── Domain Separator ──────────────────────────────────────────────────────
	// Binds the signature to Tollgate specifically and to this chain.
	// verifyingContract is the zero address in Phase 1 (Guard not deployed yet).
	// In Phase 2, this is replaced with the actual Guard contract address.

	chainID := big.NewInt(token.ChainID)

	domainSeparator := gocrypto.Keccak256(
		concat(
			eip712DomainTypeHash.Bytes(),
			gocrypto.Keccak256([]byte("Tollgate")), // name
			gocrypto.Keccak256([]byte("1")),        // version
			padUint256(chainID),                    // chainId
			padAddress(common.Address{}),           // verifyingContract — zero in Phase 1
		),
	)

	// ── Struct Hash ───────────────────────────────────────────────────────────
	// Pack each ApprovalToken field in the exact type and order defined in
	// eip712TypeHash. The Guard contract must use the identical encoding.

	// tokenId: bytes32 — UUID string → keccak256 → bytes32
	tokenIDHash := gocrypto.Keccak256Hash([]byte(token.TokenID))

	// agentId: string — keccak256 of the UTF-8 bytes (EIP-712 string encoding)
	agentIDHash := gocrypto.Keccak256Hash([]byte(token.AgentID))

	// destination: address — parse as Ethereum address, zero-pad to 32 bytes
	dest := common.HexToAddress(token.Destination)

	// amountRaw: uint256 — parse from string to avoid float64 precision loss
	amountRaw := new(big.Int)
	if _, ok := amountRaw.SetString(token.AmountRaw, 10); !ok {
		return nil, fmt.Errorf("signing: invalid amountRaw %q — must be a decimal integer string", token.AmountRaw)
	}

	// chainId: uint256
	// (reuse chainID from above)

	// nonce: bytes32 — keccak256 of nonce string
	nonceHash := gocrypto.Keccak256Hash([]byte(token.Nonce))

	// expiresAt: uint256 — Unix timestamp
	expiresAt := big.NewInt(token.ExpiresAt.Unix())

	// policyHash: bytes32 — already a hex hash string, decode to bytes32
	policyHashBytes, err := hexToBytes32(token.PolicyHash)
	if err != nil {
		return nil, fmt.Errorf("signing: invalid policyHash: %w", err)
	}

	structHash := gocrypto.Keccak256(
		concat(
			eip712TypeHash.Bytes(),
			tokenIDHash.Bytes(),   // bytes32
			agentIDHash.Bytes(),   // bytes32 (keccak256 of string)
			padAddress(dest),      // address → 32 bytes
			padUint256(amountRaw), // uint256
			padUint256(chainID),   // uint256
			nonceHash.Bytes(),     // bytes32
			padUint256(expiresAt), // uint256
			policyHashBytes[:],    // bytes32
		),
	)

	// ── Final Hash ────────────────────────────────────────────────────────────
	// keccak256(0x1901 ‖ domainSeparator ‖ structHash)
	// 0x1901 is the EIP-712 magic prefix — required by the standard.

	finalHash := gocrypto.Keccak256(
		concat(
			[]byte{0x19, 0x01},
			domainSeparator,
			structHash,
		),
	)

	return finalHash, nil
}

// VerifyToken re-derives the EIP-712 hash from the token fields and verifies
// that the signature was produced by expectedAddress.
// Used in tests and the health check — not in the hot request path.
func VerifyToken(token *ApprovalToken, expectedAddress string) (bool, error) {
	hash, err := eip712Hash(token)
	if err != nil {
		return false, fmt.Errorf("signing: VerifyToken hash failed: %w", err)
	}

	sigBytes, err := hex.DecodeString(stripHexPrefix(token.Signature))
	if err != nil {
		return false, fmt.Errorf("signing: invalid signature hex: %w", err)
	}
	if len(sigBytes) != 65 {
		return false, fmt.Errorf("signing: signature must be 65 bytes, got %d", len(sigBytes))
	}

	// Adjust V back from Ethereum standard (27/28) to recovery ID (0/1)
	// before calling SigToPub.
	sigCopy := make([]byte, 65)
	copy(sigCopy, sigBytes)
	if sigCopy[64] >= 27 {
		sigCopy[64] -= 27
	}

	pubKey, err := gocrypto.SigToPub(hash, sigCopy)
	if err != nil {
		return false, fmt.Errorf("signing: public key recovery failed: %w", err)
	}

	recoveredAddress := gocrypto.PubkeyToAddress(*pubKey).Hex()
	return recoveredAddress == expectedAddress, nil
}

// ── ABI encoding helpers ──────────────────────────────────────────────────────

// padUint256 encodes a *big.Int as a 32-byte big-endian ABI uint256.
func padUint256(n *big.Int) []byte {
	b := make([]byte, 32)
	nb := n.Bytes()
	if len(nb) > 32 {
		nb = nb[len(nb)-32:] // truncate to 32 bytes (overflow protection)
	}
	copy(b[32-len(nb):], nb)
	return b
}

// padAddress encodes an Ethereum address as a 32-byte ABI word (left-zero-padded).
func padAddress(addr common.Address) []byte {
	b := make([]byte, 32)
	copy(b[12:], addr.Bytes()) // address is 20 bytes, padded to 32 with 12 leading zeros
	return b
}

// hexToBytes32 decodes a hex string (with or without 0x prefix) into [32]byte.
func hexToBytes32(h string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(stripHexPrefix(h))
	if err != nil {
		return out, fmt.Errorf("invalid hex string: %w", err)
	}
	if len(b) > 32 {
		return out, fmt.Errorf("hex value exceeds 32 bytes (got %d)", len(b))
	}
	copy(out[32-len(b):], b) // right-align in 32-byte word
	return out, nil
}

// stripHexPrefix removes a leading "0x" or "0X" prefix if present.
func stripHexPrefix(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}

// concat joins multiple byte slices into one. Avoids repeated append allocations.
func concat(slices ...[]byte) []byte {
	total := 0
	for _, s := range slices {
		total += len(s)
	}
	out := make([]byte, 0, total)
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}
