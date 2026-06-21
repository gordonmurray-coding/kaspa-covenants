# Spending Limits the Agent Can't Override

### A stateful, self-enforcing agent-budget covenant on Kaspa — built in raw script and proven on-chain ahead of Toccata

> **TL;DR.** Using Kaspa's covenant opcodes on testnet-10, I built a wallet whose spending rules are enforced by the network instead of by the wallet's software: a per-period budget that automatically refills, a per-spend cap, a destination allowlist, an exact protocol fee, and an owner recovery path — all carried as state inside the script itself and rebuilt every time the funds move. Then I attacked it. Six transactions that each broke one rule, every one signed with the legitimate agent key and submitted straight to a node, were all rejected by the script. The limits hold even against an operator who controls the wallet's code. Everything here runs against Toccata-class consensus, which activates on Kaspa mainnet on **June 30, 2026**.

---

## Why this is newly possible

For most of its life Kaspa has been a deliberately minimal thing: a proof-of-work base layer with a BlockDAG and GHOSTDAG consensus, optimized for fast, cheap, final money at ten blocks per second. No virtual machine, no global contract state — by design.

The **Toccata** hard fork changes the surface area without changing that philosophy. Activating on mainnet on June 30, 2026 (at DAA score 474,165,565), Toccata adds *covenants* and *transaction introspection* to Kaspa's script engine, alongside zero-knowledge verification primitives and sequencing-commitment infrastructure. The relevant pieces are specified across several Kaspa Improvement Proposals: KIP-17 (the extended script-engine opcodes that form the covenant backbone), KIP-20 (covenant IDs for lineage tracking), KIP-16 (ZK verification opcodes), and KIP-21 (partitioned sequencing commitments). A higher-level language, **SilverScript**, is being built to compile down to these primitives.

A covenant is a simple idea with deep consequences: a set of programmable rules attached to a coin that constrain *how, when, and where* it can be spent next. Crucially, Kaspa's model is **UTXO-local**. A script can introspect the very transaction trying to spend it — its inputs, its outputs, their amounts and destinations, the transaction's lock time — and refuse to validate unless those satisfy its conditions. There is no global VM and no shared mutable state. Computation stays local to the coin being spent. That sounds restrictive, and in some ways it is, but as this project shows, it is enough to express genuinely stateful, multi-step, adversarially-robust behavior.

The work below was done in **raw script opcodes** rather than SilverScript. Not because raw is better — SilverScript is the path most builders should take — but because hand-assembling the bytes is the most direct way to understand exactly what the consensus engine will and won't enforce, and to verify each primitive against the live network rather than trusting a compiler or a memory of the spec.

## The problem worth solving: an agent you can't fully trust

Consider an autonomous agent — an AI process, a trading bot, a service account — that needs to spend money on your behalf. You want to bound it: no more than X per day, only to approved recipients, never above a single-transaction ceiling. The obvious place to put those limits is in the agent's code or the wallet wrapping it.

That's also the worst place to put them. The agent's code is the attack surface. A prompt injection, a dependency compromise, a bug, or a malicious operator turns "the wallet enforces a daily limit" into "the wallet *used to* enforce a daily limit." Anything checked in software the attacker can reach is a suggestion, not a guarantee.

The covenant approach inverts this. The limits live in the coin's spending conditions, checked by every node at consensus. The agent can hold the signing key, run arbitrary code, and craft any transaction it likes — and the network will still reject anything that exceeds the budget, pays an unlisted address, or skips the protocol fee. The trust boundary moves from "the agent's software" to "Kaspa's consensus rules," which the attacker does not control.

There's a business angle baked in, too. One of the enforced rules is an exact **protocol fee** paid to a designated address on every spend — a programmable, on-chain take-rate. It's not collected by a server that the agent could route around; it's a condition of the transaction validating at all.

## What the covenant does

The finished covenant is a self-replicating state machine with the following properties, every one of them enforced by the script:

- **Self-templating state.** The coin carries a two-field state — remaining budget and a period anchor — encoded directly in the front of its own script. Each spend reconstructs the *next* version of the covenant, advancing that state, and binds the change output to it. The funds can only move into another instance of the same covenant (or out via the owner path).
- **A rolling budget with automatic reset.** Up to a fixed amount may be spent per period. Multiple draws within a period share one budget; once a period has elapsed, the next spend refills the budget to full and re-anchors the clock. No off-chain bookkeeping, no oracle.
- **Two spending paths.** An *agent* path requires the agent's signature and enforces the full rule set. An *owner* path requires the owner's signature and can sweep the funds anywhere — an escape hatch for recovery, so the covenant is a guardrail, not a prison.
- **A per-spend cap.** No single payment may exceed a fixed ceiling.
- **A destination allowlist.** Payments may only go to pre-approved addresses.
- **An exact protocol fee.** Every spend must pay a precise amount to a designated fee address.
- **Value conservation.** The transaction may not bleed value into miner fees beyond a small allowance — closing off a "drain it through fees" attack.

All of this on a UTXO base layer with no global contract state, at ten blocks per second.

## How it works, without hand-waving

Three mechanisms do the heavy lifting. None of them is obvious, and getting each one right required testing against the live network rather than reasoning from the spec alone.

**Introspection is the foundation.** Toccata's covenant opcodes let a script read the transaction spending it. The script can ask: what is output 0's amount? what is output 1's destination script? what is the transaction's lock time? what is the input's value? It then imposes arithmetic and equality constraints on those answers and fails validation if they're not met. The cap is "output 0's amount must be ≤ the ceiling." The allowlist is "output 0's destination must equal one of these." The fee is "output 1 must pay exactly this much to exactly this address." These are direct.

**Self-templating is how state survives.** The hard part of a stateful UTXO covenant is continuity: when the coin is spent, how does the *new* coin know it must obey the same rules with updated numbers? The technique is to place the mutable state (fixed-width budget and anchor values) at the very front of the script, followed by an immutable "tail" of logic. A script cannot contain a literal copy of itself, so at spend time the tail is read back out of the spending input's own signature script via the introspection opcodes, the new state is encoded and prepended, and the script computes the hash of this reconstructed successor. It then requires that the transaction's continuation output pay to exactly that hash. The result is a coin that can only ever flow into a faithful copy of itself with legally-advanced state — a quine-like construction enforced by consensus.

**The clock has to be unforgeable.** The budget reset depends on time, and the only on-chain notion of time available is the transaction's lock time, interpreted as a DAA score (Kaspa's accumulated-work measure). Two facts, both verified on-chain, make it sound. First, consensus refuses to mine a transaction whose lock time is in the future relative to the chain — so a spender cannot fast-forward the clock to fake an early refill. Second, lock time is only enforced when the input's sequence is non-final, so the covenant includes a minimal relative-timelock check that forces non-finality. With those two in place, "has a period elapsed?" becomes a question the script can ask and the network will answer honestly.

**The economics are part of the design.** Two consensus-level cost mechanisms shaped every transaction. Kaspa's storage mass (KIP-9) charges a transaction by, roughly, the sum of the reciprocals of its output values — which means small outputs are expensive. And at Toccata, the minimum fee rate rises from 1 to **100 sompi per gram**. Together these have a concrete consequence: a tiny fee output (the kind a "small protocol fee" naturally produces) inflates storage mass dramatically and demands a correspondingly higher fee to get mined. The clean production pattern is to accrue small fees *inside* the covenant state and pay them out in occasional larger batches, so routine spends only ever create large outputs. This isn't a footnote; it's the difference between a transaction that confirms and one that sits unmined.

## Proving it — first that it works, then that it can't be broken

The build proceeded by isolation: each new mechanism — the self-templating counter, the budget decrement, the two-field state, the rolling reset, the auth branch, each rule — was implemented as the smallest possible covenant, confirmed on-chain, and only then composed with the rest. By the time the full covenant existed, every part underneath it had its own on-chain confirmation. A representative end-to-end agent spend (testnet-10 transaction `1d548160…`) confirmed with all rules satisfied in a single transaction: agent signature verified, three outputs, amount under cap, recipient on the allowlist, exact fee paid, value conserved, budget advanced, successor bound.

"It works" is not the same as "it's secure," though. Every confirming transaction so far was *well-behaved*. The real test is whether the network rejects *mis*-behaved ones — and specifically whether it rejects them because of the **script**, not because of the client's own sanity checks.

So I built an adversarial probe that does something a normal wallet never would: it constructs transactions that each deliberately violate one rule, **signs every one of them with the real agent key** (modeling a fully compromised agent that holds the key but tries to cheat), and submits them directly to a node, bypassing all client-side guards. A correct covenant must reject each one in consensus.

| Attack (validly signed, submitted directly) | Result |
|---|---|
| Spend above the per-transaction cap | Rejected by script |
| Pay an address not on the allowlist | Rejected by script |
| Pay the wrong protocol-fee amount | Rejected by script |
| Drain value into fees beyond the allowance | Rejected by script |
| Sign the agent path with the owner's key | Rejected by script |
| Redirect the continuation to an arbitrary address | Rejected by script |

**Six out of six, all blocked by the covenant itself.** The last two are the ones I find most telling. The signature test proves authentication is real, not cosmetic. The "redirect the continuation" test proves the agent cannot escape the covenant or rewrite its own budget — the state machine is sealed against the very operator running it. Limits enforced by the agent's code can be edited by whoever controls the agent. These cannot.

## What this says about Kaspa

It's easy to overstate what a covenant upgrade means, so let me be precise about what this does and doesn't show.

It does **not** make Kaspa an EVM. There is no global contract state, no shared world computer, no general account model. Computation is local to each coin. Many things that are natural on an account-based smart-contract platform are awkward or impossible here.

What it **does** show is that the UTXO-local model, given good introspection primitives, is far more expressive than its reputation suggests. A two-field state machine with a time-based reset, dual authorization paths, a programmable fee, and a hardened rule set — composed and adversarially verified — is not a toy. It's the kind of "surprisingly complex stateful multi-contract flow" Kaspa's own developers have pointed to as the target for L1 covenant programming. And it runs on a high-frequency proof-of-work base layer, with the security of the limits resting on consensus rather than on any server, multisig committee, or trusted operator.

The contrast with Bitcoin is hard to miss. Bitcoin's community has debated covenant proposals (OP_CTV, OP_CAT, and relatives) for years without activation. Kaspa, working partly in the slipstream of that same OP_CAT discussion, is shipping covenants — plus introspection, covenant IDs, and ZK verification — in a single coordinated upgrade. For builders who want programmable money that stays close to the metal and settles fast, that's a meaningfully different proposition.

## Reproduce it

All of the code — the staged proofs, the full covenant, the adversarial probe, and the consensus-semantics probes used to verify each primitive — is in the repository accompanying this article. Everything was built against Kaspa testnet-10 using the `kaspa` Python SDK, ahead of the June 30 mainnet activation. The covenant is research-grade and unaudited; treat it as a demonstration of what the primitives make possible, not as a drop-in production wallet.

If you want to go deeper on the language side rather than the bytes, SilverScript is the official high-level path to the same primitives, and the rusty-kaspa Toccata guide is the authoritative reference for node operators and the post-activation fee and mass rules.

---

### Caveats, honestly

- This ran on **testnet-10**, which already enforces Toccata-class rules, ahead of the June 30 mainnet activation. Mainnet behavior should match, but "tested on testnet" is not "audited for mainnet value."
- The covenant operates **per UTXO**; it does not aggregate multiple coins. A production design needs a deliberate UTXO-management strategy.
- The state lives in the script and is reconstructed each spend; the construction is sound in the cases tested here, but raw-opcode covenants are unforgiving and easy to get subtly wrong. Use SilverScript and an audit for anything holding real value.
- "Enforced by consensus" is a claim about the *rules*, not about availability, key management, or the surrounding software. The owner key, in particular, is a full bypass by design.

### References

- Michael Sutton, "Kaspa Covenants++ 'Toccata' Hard-Fork Outlook" — https://medium.com/@michaelsuttonil/kaspa-covenants-toccata-hard-fork-outlook-a4d81a40900c
- rusty-kaspa Toccata guide (node operators, fee/mass rules) — https://github.com/kaspanet/rusty-kaspa/blob/master/docs/toccata-guide.md
- Kaspa Improvement Proposals: KIP-16 (ZK opcodes), KIP-17 (covenant opcodes), KIP-20 (covenant IDs), KIP-21 (sequencing commitments)
- Toccata mainnet activation: June 30, 2026, DAA score 474,165,565

*Built and verified on Kaspa testnet-10. Author: Gordon Murray, Kaspa Researcher*
