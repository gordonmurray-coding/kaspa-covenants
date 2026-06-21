#!/usr/bin/env python3
"""
Probe the installed Kaspa SDK for the primitives needed to build:

  (1) a destination WHITELIST
        - small list:   uses OpTxOutputSpk + OpEqual + OpAdd  (already confirmed working)
        - large list:   needs a HASHING opcode (Merkle-root membership)

  (2) a per-period RATE LIMIT, which needs BOTH of:
        (a) a CLOCK  -> a lock-time / sequence / DAA-score introspection opcode
        (b) STATE-CARRY across the self-replicating loop, via either
              - KIP-20 covenant-ID opcodes (program identity separate from state), or
              - child-script templating: a HASHING opcode (+ likely OpCat, often disabled)

No network is required -- this only introspects the `kaspa` module, so it returns
instantly. Paste the full output back and we'll design the covenant on facts.
"""
import kaspa
from kaspa import Opcodes


def opcode_table():
    rows = []
    for n in dir(Opcodes):
        if not (n.startswith("Op") or n.startswith("OP")):
            continue
        try:
            iv = int(getattr(Opcodes, n))
        except Exception:
            iv = -1
        rows.append((iv, n))
    rows.sort()
    print(f"=== {len(rows)} opcodes exposed by the SDK ===")
    for iv, n in rows:
        print(f"  0x{iv:02x}  {n}" if iv >= 0 else f"  ????  {n}")
    # lower-name -> value map for keyword hunting
    return {n.lower(): iv for iv, n in rows if iv >= 0}


def hunt(opmap, label, needles):
    print(f"\n--- {label} ---")
    hits = sorted(
        ((n, v) for n, v in opmap.items() if any(k in n for k in needles)),
        key=lambda x: x[1],
    )
    if hits:
        for n, v in hits:
            print(f"  FOUND  0x{v:02x}  {n}")
    else:
        print(f"  (nothing matching {needles})")


def attrs(name):
    cls = getattr(kaspa, name, None)
    if cls is None:
        print(f"\n--- {name}: NOT in module ---")
        return
    print(f"\n--- {name} attributes ---")
    print("  ", sorted(a for a in dir(cls) if not a.startswith("__")))


if __name__ == "__main__":
    print("kaspa SDK version:", getattr(kaspa, "__version__", "unknown"))
    print("module symbols of interest:",
          sorted(s for s in dir(kaspa)
                 if any(k in s.lower() for k in
                        ("covenant", "seq", "commit", "lane", "merkle", "lock", "daa"))))

    opmap = opcode_table()

    # (2a) the CLOCK
    hunt(opmap, "CLOCK: lock-time / sequence (CLTV/CSV equivalents)",
         ["lock", "time", "sequence", "csv", "cltv", "maturity"])
    hunt(opmap, "CLOCK: DAA score / blue score / height",
         ["daa", "blue", "height", "score"])

    # (2b) STATE-CARRY: covenant identity + tx introspection
    hunt(opmap, "COVENANT-ID (KIP-20: identity separate from state)",
         ["covenant", "cid", "program"])
    hunt(opmap, "TX INTROSPECTION (inputs / outputs / spk / amount)",
         ["txinput", "txoutput", "inputspk", "outputspk", "inputamount",
          "outputamount", "inputindex", "outputcount", "introspect", "push"])

    # (1) + (2b fallback) HASHING and concat
    hunt(opmap, "HASHING (Merkle whitelist / child-script templating)",
         ["hash", "blake", "sha", "ripemd"])
    hunt(opmap, "CONCAT / SPLIT (needed for script templating)",
         ["cat", "split", "substr", "left", "right"])

    # stack/bool helpers (in case we want the simple OR form differently)
    hunt(opmap, "STACK / BOOL helpers",
         ["dup", "swap", "pick", "roll", "rot", "bool", "ifdup", "over"])

    # KIP-21 sequencing-commitment opcodes (the thing that bit us earlier)
    hunt(opmap, "SEQUENCING-COMMITMENT (KIP-21)",
         ["seq", "commit", "lane", "smt", "merkle"])

    # which tx fields expose a per-input clock (lock_time / sequence)
    for n in ("Transaction", "TransactionInput", "TransactionOutput",
              "ScriptBuilder", "UtxoEntryReference"):
        attrs(n)

    print("\n=== done ===")
    print("Key questions this answers:")
    print("  - Is there a lock-time/DAA opcode?      -> enables Tier-1 buckets (or Tier-2 clock)")
    print("  - Are there covenant-ID opcodes?        -> enables clean Tier-2 stateful budget")
    print("  - Is there a hashing opcode (+ OpCat)?  -> enables Merkle whitelist / templated state")
