#!/usr/bin/env python3
"""
Discovery probe for the ROLLING-BUDGET covenant upgrade.

A rolling budget carries mutable state (budget_remaining, period_start) across the
self-replicating loop. The covenant must verify each child UTXO is "the same program
with updated state" -- i.e. recompute the child's P2SH hash ON-STACK and check it
equals the hash in the child's scriptPublicKey. To build that we must know EXACTLY
what create_pay_to_script_hash_script does:
  - which hash op (the spk's leading byte: 0xaa OpBlake2b = unkeyed, 0xa7 = keyed)
  - over which preimage (raw redeem bytes? framed?)
We also inspect the covenant-ID model, which -- if identity is stable across state
changes -- is a cleaner alternative to on-stack templating.

No node required.
"""
import hashlib, inspect
import kaspa
from kaspa import ScriptBuilder, Opcodes, Keypair

def OP(sb, op):
    try: sb.add_op(op)
    except Exception: sb.add_op(int(op))

def sample_redeem():
    kp = Keypair.random()
    xonly = kp.xonly_public_key
    xb = bytes.fromhex(xonly) if isinstance(xonly, str) else bytes(xonly)
    sb = ScriptBuilder()
    sb.add_data(xb); OP(sb, Opcodes.OpCheckSig)
    return sb

def describe_spk(spk_hex):
    b = bytes.fromhex(spk_hex)
    print("  raw p2sh script :", spk_hex)
    if not b:
        return None
    lead = b[0]
    names = {0xaa: "OpBlake2b (UNKEYED)", 0xa7: "OpBlake2bWithKey (KEYED)",
             0xa8: "OpSHA256", 0xd9: "OpBlake3"}
    print(f"  leading opcode  : 0x{lead:02x}  {names.get(lead, '?')}")
    # pull the 32-byte field
    for i in range(len(b) - 1):
        if b[i] == 0x20 and i + 33 <= len(b):
            h = b[i+1:i+33]
            tail = b[i+33:]
            print(f"  embedded hash   : {h.hex()}")
            print(f"  trailing bytes  : {tail.hex()}  (expect 87 = OpEqual)")
            return h
    print("  (no 32-byte push found)")
    return None

def candidates(preimage):
    out = {"blake2b-256": hashlib.blake2b(preimage, digest_size=32).hexdigest(),
           "sha256": hashlib.sha256(preimage).hexdigest()}
    for key in (b"TransactionSigningHash", b"ScriptPublicKey", b"PayToScriptHash",
                b"TransactionHash", b"ScriptHash"):
        try:
            out[f"blake2b-256 key={key.decode()}"] = hashlib.blake2b(
                preimage, digest_size=32, key=key).hexdigest()
        except Exception:
            pass
    try:
        import blake3
        out["blake3"] = blake3.blake3(preimage).hexdigest()
    except Exception:
        out["blake3"] = "(pip install blake3 to test this one)"
    return out

def main():
    print("=== P2SH hash-recipe identification ===")
    sb = sample_redeem()
    redeem_hex = sb.to_string()
    redeem = bytes.fromhex(redeem_hex)
    print("sample redeem   :", redeem_hex)
    p2sh = sb.create_pay_to_script_hash_script()
    spk = p2sh.script
    spk_hex = spk if isinstance(spk, str) else bytes(spk).hex()
    target = describe_spk(spk_hex)

    if target:
        t = target.hex()
        print("\n  hash(redeem) candidates vs embedded hash:")
        for name, h in candidates(redeem).items():
            print(f"    {name:32s} {h}{'   <== MATCH' if h == t else ''}")
        print("\n  framed-preimage fallbacks (blake2b-256):")
        frames = {}
        if len(redeem) < 256: frames["lenbyte||redeem"] = bytes([len(redeem)]) + redeem
        frames["u64le-len||redeem"] = len(redeem).to_bytes(8, "little") + redeem
        frames["redeem||u64le-len"] = redeem + len(redeem).to_bytes(8, "little")
        for name, pre in frames.items():
            h = hashlib.blake2b(pre, digest_size=32).hexdigest()
            print(f"    {name:32s} {h}{'   <== MATCH' if h == t else ''}")

    print("\n=== covenant-ID model ===")
    cid = getattr(kaspa, "covenant_id", None)
    print("kaspa.covenant_id:", cid)
    if cid is not None:
        try: print("  signature:", inspect.signature(cid))
        except Exception as e: print("  (no introspectable signature:", e, ")")
        print("  doc:", (cid.__doc__ or "(none)")[:400])
    for nm in ("CovenantBinding", "GenesisCovenantGroup", "CommitRevealAddressKind"):
        obj = getattr(kaspa, nm, None)
        print(f"\n{nm}: {obj}")
        if obj is not None:
            print("  attrs:", [a for a in dir(obj) if not a.startswith("_")])
            print("  doc  :", (getattr(obj, "__doc__", "") or "(none)")[:300])
    pg = getattr(kaspa.Transaction, "populate_genesis_covenants", None)
    if pg is not None:
        try: print("\nTransaction.populate_genesis_covenants:", inspect.signature(pg))
        except Exception: print("\nTransaction.populate_genesis_covenants: (no sig)")
        print("  doc:", (pg.__doc__ or "(none)")[:400])

    print("\n=== clock for period reset ===")
    print("Available: OpTxInputDaaScore (input UTXO creation DAA), OpTxLockTime +")
    print("OpCheckLockTimeVerify (tx lock_time, consensus-gated). No 'current DAA' opcode,")
    print("so the clock is: script forces tx.lock_time >= X via CLTV, OpTxLockTime reads it,")
    print("and consensus refuses to mine the tx before DAA X. Spender can't future-date it.")

    print("\n=== what this decides ===")
    print(" - hash recipe MATCH  -> templated stateful covenant is buildable (recompute child")
    print("   hash on-stack with OpCat + OpNum2Bin + the matched hash op, verify vs out.spk)")
    print(" - covenant_id stable across state -> cleaner: assert OpOutputCovenantId ==")
    print("   OpInputCovenantId, carry state in the script, skip the hash reconstruction")

if __name__ == "__main__":
    main()
