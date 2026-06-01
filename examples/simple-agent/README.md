# simple-agent

The minimum viable Tollgate integration — 20 lines of TypeScript.

## What it does

1. Creates a `TollgateSigner` connected to your local Notary
2. Calls `simulate()` with a sample transaction
3. Prints the Notary's decision — approved or denied

## Run it

```bash
# 1. Start the Notary (in another terminal)
cd ../../core
go run ./cmd/server/main.go

# 2. Copy the Bearer token from the startup log, then:
cd ../../examples/simple-agent
AGENT_TOKEN=your_token_here npx tsx index.ts
```

## Expected output

```
✓ Connected to Tollgate Notary
✓ Transaction approved by Tollgate
  Token ID  : 9692d4ac-...
  Expires   : 2026-05-28T...
  Risk score: 0
  Signature : 0x02b91613e3...
```

## Try a denial

Change `purpose` to `buy_nfts` — a purpose not in the policy:

```typescript
purpose: 'buy_nfts',
```

You will see:
```
✗ Transaction denied
  Code   : PURPOSE_MISMATCH
  Reason : Purpose "buy_nfts" is not in the agent's allowed_purposes list.
```

That is the policy engine working correctly.