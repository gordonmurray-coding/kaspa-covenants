# Arbitrated Escrow on Kaspa

An escrow covenant with three roles — buyer, seller, arbiter — and two spend paths. The
point of doing this with a covenant rather than a plain 2-of-3 multisig is one property
that multisig cannot express: **the arbiter can resolve a dispute but is structurally
unable to steal the funds.**

- **Settle** — buyer *and* seller co-sign. Mutual consent, so the output is unconstrained
  (release to the seller, a partial-refund split, whatever they agree). This is a
  two-signature path: N-of-M without `OpCheckMultiSig`.
- **Resolve** — the arbiter signs *alone*, but introspection forces the payout to be the
  buyer's or the seller's registered address, at (near) full value. The arbiter picks the
  winner of a dispute and cannot route the money anywhere else — not to themselves, not to
  a confederate. A compromised arbiter key's worst case is "paid the wrong legitimate
  party," never theft.

Everything but the two-signature settle path is lifted from the budget covenant
(`covenant/`): the selector branch, the output-SPK check, the amount conservation, and
`OpCheckSig`.

## The redeem script (202 bytes)

```
OpIf                                         # selector: 1 = settle, 0 = resolve
    <buyer_xonly>  OpCheckSigVerify          #   buyer signature
    <seller_xonly> OpCheckSig                #   seller signature
OpElse
    <arbiter_xonly> OpCheckSigVerify         #   arbiter signature
    OpTxOutputCount Op1 OpNumEqualVerify     #   exactly one output (no second, self-paying out)
    Op0 OpTxOutputSpk <buyer_spk>  OpEqual   #   payout == buyer?   (0x01 / empty)
    Op0 OpTxOutputSpk <seller_spk> OpEqual   #   payout == seller?
    OpAdd OpVerify                           #   sum >= 1  -> a whitelisted party
    Op0 OpTxOutputAmount <allowance> OpAdd    #   payout amount + allowance
    Op0 OpTxInputAmount OpGreaterThanOrEqual OpVerify   # ... >= input (no skimming)
    OpTrue
OpEndIf
```

No state is prepended, so witness items land on the stack in order. The settle witness is
`[seller_sig, buyer_sig, 1]` (buyer checked first); the resolve witness is `[arbiter_sig,
0]`. The settle path is deliberately *un*constrained on outputs — mutual consent means the
two parties can split the funds however they agree. Only the single-arbiter resolve path is
locked down, because that's the one untrusted actor.

## Proven on testnet-10

| Path | Scenario | Result | Tx |
|------|----------|--------|----|
| Settle | buyer + seller co-sign (two-sig path) | confirmed | `96850ad098fe1ba01a07682456c86d9ead88cb92726094076746106754915542` |
| Resolve | arbiter aims at a **non-whitelisted** address | **rejected** by the covenant | `94240bfa892b2406ef8552a5c20cd490d8e025b2136042d18a5639e416b15725` |
| Resolve | arbiter aims at the **seller** | confirmed | `58d2cbd52543d3894fd262dcde359d74796efcf8fa321cfebb1d59185092a28c` |

The two resolve attempts are the whole demonstration: **same arbiter, same key, same valid
signature** — one rejected and one accepted, differing only in where the money was aimed.
The rejected one fails with `script ran, but verification failed`: the signature is fine,
but the destination isn't in the whitelist, so `OpVerify` kills the transaction. The
arbiter holds adjudication power; the covenant holds the money.

Constraining `out0` alone isn't enough to make "the arbiter can't steal" literally true:
without an output-*count* check, a malicious arbiter could build a two-output transaction —
`out0` paying the seller the floor, `out1` paying themselves the leftover allowance. The
`OpTxOutputCount Op1 OpNumEqualVerify` guard closes that: exactly one output is permitted,
to a whitelisted party, at no less than `input − allowance`. The arbiter's worst case
collapses to overpaying the transaction fee (which goes to miners, not them). Capture: zero.
The budget covenant guards the same way with `OpTxOutputCount == 3`.

## Two consensus lessons from building it

**1. Multi-signature paths must declare their sig-op budget.** Kaspa makes each input
commit to a signature-operation count, and the script engine refuses to execute more sig-ops
than were committed (`script units exceeded the amount committed in the input`). Every
single-signature covenant rides the default of 1. The settle path is the first to do two
checks, so its input must set `sig_op_count = 2` — and it has to be set *before* signing,
because the field is part of the sighash. Same philosophy as the KIP-9 storage-mass and
fee-floor rules: push cost commitments into the transaction so validators can bound work
cheaply.

**2. Combine boolean results with `OpAdd`, not bitwise `OpOr`.** `OpEqual` pushes `0x01`
for true and an empty array for false. `OpOr` (0x85) is *bitwise* and requires
equal-length operands, so OR-ing a true (`0x01`, length 1) against a false (empty, length
0) hard-errors with `OR operands must be of equal length`. A two-entry whitelist hits this
the moment the payout matches the second entry. The fix is to treat the equality results as
numbers and **sum** them (`OpAdd`), then `OpVerify` the nonzero total — arithmetic
interprets each operand as a little-endian number (empty = 0), so length never matters. The
running total is just the match count. This same fix was applied to the budget covenant's
whitelist, which had the latent bug but only ever ran with a single entry.

## Extensions

- **Timeout default-resolution.** A real escrow wants a long-stop: if the arbiter is
  unresponsive, funds should resolve by a default rule after a deadline. That's the
  `OpTxLockTime` + CSV-non-finality clock from the budget and swap covenants, added as a
  third path.
- **Arbiter fee.** The resolve path can carry a protocol/arbiter fee with the exact
  dev-fee output constraint from the budget covenant — a paid, non-custodial dispute
  service with the fee enforced at consensus.

## Running it

```
python3 kaspa_escrow.py open --amount-tkas 5 \
    --buyer-payout  <addr> --seller-payout <addr>   # build + show the escrow
python3 kaspa_escrow.py info
python3 kaspa_escrow.py release [payout]            # SETTLE: buyer + seller co-sign
python3 kaspa_escrow.py resolve <payout>            # RESOLVE: arbiter; must be buyer or seller
```

`open` generates the buyer, seller, and arbiter keys and saves them to `escrow_config.json`
(gitignored — it holds private keys). Point `resolve` at any non-whitelisted address to see
the covenant refuse it.

> Unaudited research code on a testnet. Use at your own risk.
