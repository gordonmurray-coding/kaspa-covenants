# kaspa-covenants — a stateful agent-budget covenant, proven on-chain

Programmable, self-enforcing spending limits on Kaspa, built in raw script and verified
against live consensus on **testnet-10**, ahead of the **Toccata** mainnet activation
(June 30, 2026). The headline artifact is an agent-budget wallet whose rules — a rolling
per-period budget, a per-spend cap, a destination allowlist, an exact protocol fee, value
conservation, agent authentication, and an owner recovery path — are enforced by the
network, not by the wallet's software.

**The result that matters:** six transactions that each break one rule, every one signed
with the legitimate agent key and submitted directly to a node, were **all rejected by the
covenant script itself**. A compromised agent that holds the key still cannot exceed its
limits. See [`ARTICLE.md`](./ARTICLE.md) for the full writeup.

> Status: research / demonstration. Built on testnet-10, unaudited. Not for mainnet value as-is.

---

## What's here

This repo grew out of a build log: every covenant mechanism was implemented as the smallest
possible script, confirmed on-chain, and only then composed. The staged proofs are kept
because they're the clearest way to understand each primitive in isolation.

### What's included

```
kaspa-covenants/
├── ARTICLE.md                         # the writeup (publishable)
├── README.md                          # this file
├── LICENSE
├── probes/                            # consensus-semantics verification
│   ├── kaspa_sdk_discover.py          #   SDK surface discovery
│   ├── kaspa_primitive_probe.py       #   opcode enumeration
│   ├── kaspa_p2sh_covenant_probe.py   #   P2SH hash recipe + covenant-id model
│   └── kaspa_locktime_probe.py        #   lock_time = DAA clock semantics
├── covenant/                          # the staged build
│   ├── kaspa_selftemplate_counter.py  #   1  self-templating state (count++)
│   ├── kaspa_budget_step2a.py         #   2a budget decrement + floor
│   ├── kaspa_budget_step2b1.py        #   2b-1 two-field state
│   ├── kaspa_rolling_budget.py        #   2b-2 rolling budget + calendar reset
│   ├── kaspa_agent_covenant_step3a.py #   3a + agent auth + owner escape
│   └── kaspa_agent_covenant_step3b.py #   3b + cap + allowlist + fee + conservation  ← full covenant
└── adversarial/
    └── kaspa_agent_covenant_3b_adversarial.py   # the 6-attack battery
```

## How covenants do this

Toccata (KIP-17) adds **transaction-introspection opcodes**: a script can read the very
transaction spending it — output amounts and destinations, input value, lock time — and
refuse to validate unless they satisfy its conditions. State is carried by **self-templating**:
the mutable state sits at the front of the script, the immutable logic tail is read back from
the spending input at runtime, the successor script is reconstructed and hashed, and the
continuation output is bound to that hash. The reset clock uses `lock_time` interpreted as a
DAA score, made unforgeable by the fact that consensus won't mine a future-dated transaction,
plus a relative-timelock check that forces the lock time to be enforced. Full explanation in
[`ARTICLE.md`](./ARTICLE.md).

## Quickstart

Requires Python 3 and the `kaspa` SDK, and RPC access to a node on the current Toccata /
testnet-10 build (the script's `RPC_URL` constant — point it at your node).

```bash
pip install kaspa

# build the full hardened covenant (new keypairs -> new address)
python3 covenant/kaspa_agent_covenant_step3b.py build \
  --full-tkas 20 --period-daa 600 --cap-tkas 10 --dev-fee-tkas 2.0 \
  --whitelist <approved_payee_address> \
  --dev-addr <fee_address>

# fund the printed address, then:
python3 covenant/kaspa_agent_covenant_step3b.py info
python3 covenant/kaspa_agent_covenant_step3b.py spend <approved_payee_address> 8
python3 covenant/kaspa_agent_covenant_step3b.py sweep <your_own_address>   # owner escape

# prove the limits are enforced by consensus, not by the client:
python3 adversarial/kaspa_agent_covenant_3b_adversarial.py
```

Expected adversarial output: `6/6 blocked by the covenant script itself.`

## The staged proofs

Each step isolates one new mechanism and confirms it on-chain before the next builds on it.

| Step | Script | Proves |
|---|---|---|
| Probes | `probes/*.py` | P2SH hash recipe, opcode set, `lock_time` DAA semantics |
| 1 | `kaspa_selftemplate_counter.py` | self-templating: a coin that rebuilds itself with `count+1` |
| 2a | `kaspa_budget_step2a.py` | budget decrement with a `>= 0` floor |
| 2b-1 | `kaspa_budget_step2b1.py` | two-field state carried through the rebuild |
| 2b-2 | `kaspa_rolling_budget.py` | calendar reset: refill-per-period via the `lock_time` clock |
| 3a | `kaspa_agent_covenant_step3a.py` | two-path branch: agent auth + owner escape |
| 3b | `kaspa_agent_covenant_step3b.py` | cap + allowlist + exact fee + value conservation |
| Attack | `adversarial/...py` | every rule rejected by consensus, not the client |

## Practical notes (the gotchas)

- **Fee rate.** At Toccata the minimum fee rate rises to **100 sompi/gram**. A transaction
  that's accepted to a node's mempool can still fail to mine if it underpays for its mass.
- **Storage mass (KIP-9).** Cost scales with the sum of `1/output_value`, so *small outputs
  are expensive*. A tiny fee output inflates mass sharply. Production pattern: accrue small
  fees inside the covenant and pay them out in larger batches, so routine spends emit only
  large outputs.
- **Push encoding.** Redeem scripts over 75 bytes need `OP_PUSHDATA1`/`OP_PUSHDATA2`; a bare
  length byte silently corrupts the signature script.
- **CSV pops its argument** on Kaspa (unlike Bitcoin's non-popping CLTV/CSV) — no trailing
  `OP_DROP`.
- **Don't bake editable parameters into the address.** Anything in the redeem script (fees,
  caps) defines the P2SH address; changing such a constant after building orphans the coin.
  Keep tunables in config.

## Security model

The limits rest on Kaspa consensus, demonstrated adversarially: rule-violating transactions,
validly signed and submitted directly, are rejected by the script. This is a claim about the
*rules*, not about key custody, availability, or the surrounding software. The owner key is a
deliberate full bypass for recovery.

## Toccata context

Toccata activates on Kaspa mainnet on June 30, 2026 (DAA 474,165,565), adding native L1
covenants and transaction introspection (KIP-17), covenant IDs (KIP-20), ZK verification
opcodes (KIP-16), and sequencing commitments (KIP-21). **SilverScript** is the official
higher-level compiler; this repo works in raw opcodes for transparency and to verify each
primitive directly. The [rusty-kaspa Toccata guide](https://github.com/kaspanet/rusty-kaspa/blob/master/docs/toccata-guide.md)
is the authoritative node/operator reference.

## License

MIT (suggested — add a `LICENSE` file). Use at your own risk; unaudited research code.

## Acknowledgements

The Kaspa core developers behind Toccata, covenants, and SilverScript. The `kaspa` Python SDK.
And the consensus engine itself, which rejected every attack exactly as it should.
