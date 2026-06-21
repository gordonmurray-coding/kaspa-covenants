#!/usr/bin/env python3
"""
Discover the script/covenant/transaction toolbox in YOUR installed Kaspa SDK.
No network needed — this just introspects the module.

    python kaspa_sdk_discover.py

Paste the output back and we'll write the vault builder against what's real.
"""

import kaspa
import inspect

def names(obj):
    return [n for n in dir(obj) if not n.startswith("_")]

# 1) Top-level module exports
top = names(kaspa)
print("=" * 70)
print(f"kaspa module exports ({len(top)}):")
print("  " + ", ".join(sorted(top)))

# 2) Anything opcode-related (constants or an Opcodes/OpCodes container)
print("\n" + "=" * 70)
print("OPCODE-related symbols:")
op_syms = [n for n in top if "op" in n.lower() or "script" in n.lower()]
for n in sorted(op_syms):
    obj = getattr(kaspa, n)
    kind = type(obj).__name__
    print(f"  {n}  ({kind})")
    # If it's a class/container, peek inside for opcode constants/methods
    members = names(obj)
    if members:
        sample = members[:40]
        print("      -> " + ", ".join(sample) + (" ..." if len(members) > 40 else ""))

# 3) Classes we care about for a covenant vault
print("\n" + "=" * 70)
print("KEY CLASSES (methods):")
targets = ["ScriptBuilder", "Opcodes", "OpCodes", "Opcode",
           "ScriptPublicKey", "Address",
           "Transaction", "TransactionInput", "TransactionOutput",
           "PrivateKey", "PublicKey", "Keypair", "Generator",
           "PendingTransaction", "SighashType", "UtxoEntry", "UtxoEntryReference"]
for t in targets:
    obj = getattr(kaspa, t, None)
    if obj is None:
        continue
    m = names(obj)
    print(f"  {t}: " + ", ".join(m[:30]) + (" ..." if len(m) > 30 else ""))

# 4) Module-level helper functions (address<->script, signing, unit conversion)
print("\n" + "=" * 70)
print("HELPER FUNCTIONS (module-level):")
for n in sorted(top):
    obj = getattr(kaspa, n)
    if inspect.isfunction(obj) or inspect.isbuiltin(obj) or callable(obj) and not inspect.isclass(obj):
        if any(k in n.lower() for k in
               ("script","address","sign","sompi","kas","pay_to","create_transaction","tx")):
            print(f"  {n}")
