package signing

import (
	"crypto/ecdsa"
	"fmt"

	gocrypto "github.com/ethereum/go-ethereum/crypto"
)

// Signer holds Tollgate's ECDSA secp256k1 private key and exposes only
// what the rest of the application needs: a public key and a sign function.
//
// SECURITY CONTRACT:
//   - The private key is loaded once from the environment variable on startup.
//   - It is held in memory as *ecdsa.PrivateKey — never serialized, never logged,
//     never returned in any response, never written to disk again.
//   - The private key field is unexported. No code outside this package can read it.
//   - Sign() accepts a hash (32 bytes) and returns a signature. The key never leaves.
type Signer struct {
	privateKey *ecdsa.PrivateKey // unexported — never accessible outside this package
}

// New loads the ECDSA private key from privateKeyHex, validates it, and returns
// a ready-to-use Signer. Returns a fatal error if the key is invalid.
//
// SECURITY: privateKeyHex must come from the environment variable only.
// Never pass a hardcoded string. Never log the input value.
func New(privateKeyHex string) (*Signer, error) {
	if len(privateKeyHex) != 64 {
		// Report length only — never echo the key value itself in errors.
		return nil, fmt.Errorf(
			"signing: private key must be 64 hex characters (got %d) — check TOLLGATE_SIGNING_KEY_HEX",
			len(privateKeyHex),
		)
	}

	key, err := gocrypto.HexToECDSA(privateKeyHex)
	if err != nil {
		// Do not wrap the original error — it may contain key material in some
		// implementations. Return a generic message.
		return nil, fmt.Errorf("signing: ECDSA private key is invalid or malformed")
	}

	// Confirm the public key is derivable — a basic sanity check.
	pubKey, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || pubKey == nil {
		return nil, fmt.Errorf("signing: failed to derive public key from private key")
	}

	return &Signer{privateKey: key}, nil
}

// PublicKeyHex returns the uncompressed secp256k1 public key as a hex string.
// This is safe to share — it is the public half of the key pair.
// The Guard contract in Phase 2 will use the derived address (PublicAddress)
// to verify signatures via ecrecover.
func (s *Signer) PublicKeyHex() string {
	return fmt.Sprintf("%x", gocrypto.FromECDSAPub(&s.privateKey.PublicKey))
}

// PublicAddress returns Tollgate's Ethereum address (keccak256 of public key, last 20 bytes).
// This is the address the on-chain Guard will compare against ecrecover output.
func (s *Signer) PublicAddress() string {
	return gocrypto.PubkeyToAddress(s.privateKey.PublicKey).Hex()
}

// Sign signs a 32-byte hash using secp256k1 ECDSA.
// Returns a 65-byte [R(32) || S(32) || V(1)] signature where V is 27 or 28.
//
// SECURITY:
//   - Input must be exactly 32 bytes. Enforced — not a suggestion.
//   - V is adjusted from recovery ID (0/1) to Ethereum standard (27/28).
//     This is required for on-chain ecrecover compatibility in Phase 2.
//   - The private key never leaves this function.
func (s *Signer) Sign(hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf(
			"signing: Sign() requires exactly 32 bytes, got %d — pass a keccak256 hash",
			len(hash),
		)
	}

	sig, err := gocrypto.Sign(hash, s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("signing: ECDSA sign operation failed: %w", err)
	}

	// go-ethereum's crypto.Sign returns V as 0 or 1 (recovery ID).
	// Ethereum's ecrecover on-chain expects V as 27 or 28.
	// The Guard contract (Phase 2) uses standard ecrecover — must be 27/28.
	sig[64] += 27

	return sig, nil
}
