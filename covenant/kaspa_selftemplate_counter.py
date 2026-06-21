#!/usr/bin/env python3
"""
Step 1 -- self-templating COUNTER covenant (TN10), hand-rolled to mirror the exact
byte layout SilverScript's `validateOutputState` emits.

Purpose: prove the hard mechanic in isolation -- a UTXO that can ONLY be spent into a
child paying the same covenant code with `count` incremented by 1. No budget logic, no
branches, no auth yet. If this spends on-chain, the state-machine foundation is real and
we layer the rolling budget + existing rules on top.

State layout (front of redeem, fixed width -- matches compiler's state_layout):
    08 <count : 8 bytes LE>            # one int field, OpData8-prefixed

Tail logic (mirrors the compiler lowering, single-field version):
    OpTrue OpAdd                       # count + 1
    Op8 OpNum2Bin <08> OpSwap OpCat    # re-encode as 08||bin8(count+1)  = new_state
    OpTxInputIndex OpDup OpTxInputScriptSigLen OpDup
    <SCRIPT_LEN> OpSub <STATE_LEN> OpAdd OpSwap OpTxInputScriptSigSubstr
                                       # tail = own redeem tail, read from the input
    OpCat                              # child_redeem = new_state || tail
    OpBlake2b                          # 32-byte blake2b (confirmed P2SH hash)
    <0000> <aa> OpCat <20> OpCat OpSwap OpCat <87> OpCat
                                       # expected spk = 0000 || aa20 || hash || 87
    Op0 OpTxOutputSpk OpEqual OpVerify # require output[0].spk == child P2SH
    OpTrue

NOTE: this minimal counter does NOT check value or output count (neither does the
reference Counter); it only binds output[0] to the next state. That's fine for proving
the mechanic. The empirical risk points to watch on the first spend are flagged below.
"""
import asyncio, json, argparse, inspect, hashlib
import kaspa
from kaspa import (RpcClient, ScriptBuilder, PaymentOutput,
                   address_from_script_public_key, create_transaction)

CFG_PATH = "selftemplate_counter_config.json"
NETWORK  = "testnet"
RPC_URL  = "ws://159.195.64.93:8080/kaspa/testnet-10/wrpc/borsh"
FEE_SOMPI = 1_000_000
SOMPI = 100_000_000

# ---- exact byte layout ------------------------------------------------------
STATE_LEN  = 9            # one field: 0x08 push-prefix + 8 data bytes
# TAIL is identical every generation; SCRIPT_LEN is constant because state is fixed-width.
def build_tail(script_len):
    return bytes([
        0x51,                   # OpTrue            -> count + 1
        0x93,                   # OpAdd
        0x58,                   # Op8  (width)
        0xcd,                   # OpNum2Bin
        0x01, 0x08,             # push 0x08         (length prefix byte)
        0x7c,                   # OpSwap
        0x7e,                   # OpCat             -> new_state = 08||bin8(count+1)
        0xb9,                   # OpTxInputIndex
        0x76,                   # OpDup
        0xc9,                   # OpTxInputScriptSigLen
        0x76,                   # OpDup
        0x01, script_len,       # push SCRIPT_LEN
        0x94,                   # OpSub
        0x01, STATE_LEN,        # push STATE_LEN
        0x93,                   # OpAdd             -> begin = siglen - SCRIPT_LEN + STATE_LEN
        0x7c,                   # OpSwap
        0xbc,                   # OpTxInputScriptSigSubstr  -> tail
        0x7e,                   # OpCat             -> child_redeem = new_state || tail
        0xaa,                   # OpBlake2b
        0x02, 0x00, 0x00,       # push 0x0000       (version prefix, LE)
        0x01, 0xaa,             # push 0xaa         (OpBlake2b opcode byte)
        0x7e,                   # OpCat
        0x01, 0x20,             # push 0x20         (OpData32)
        0x7e,                   # OpCat             -> 0000 aa 20
        0x7c,                   # OpSwap
        0x7e,                   # OpCat             -> 0000aa20 || hash
        0x01, 0x87,             # push 0x87         (OpEqual)
        0x7e,                   # OpCat             -> expected spk
        0x00,                   # Op0  (output index 0)
        0xc3,                   # OpTxOutputSpk
        0x87,                   # OpEqual
        0x69,                   # OpVerify
        0x51,                   # OpTrue
    ])

# SCRIPT_LEN fixed point: STATE_LEN(9) + len(tail). tail length is constant (all pushes
# fixed-size), so we compute it once and bake it. Assert it closes.
_SCRIPT_LEN = STATE_LEN + len(build_tail(0))
TAIL = build_tail(_SCRIPT_LEN)
assert STATE_LEN + len(TAIL) == _SCRIPT_LEN, "script-length fixed point did not close"

def redeem_for(count):
    return bytes([0x08]) + int(count).to_bytes(8, "little") + TAIL

# ---- helpers ----------------------------------------------------------------
def to_hex(x):
    if isinstance(x, str): return x
    if isinstance(x, (bytes, bytearray)): return bytes(x).hex()
    for m in ("to_string", "to_hex"):
        if hasattr(x, m): return getattr(x, m)()
    return str(x)
async def aw(x): return await x if inspect.isawaitable(x) else x
def get_amount(u):
    if not isinstance(u, dict):
        a = getattr(u, "amount", None); return int(a) if a is not None else None
    if "amount" in u: return int(u["amount"])
    ue = u.get("utxoEntry") or u.get("entry") or {}
    return int(ue["amount"]) if isinstance(ue, dict) and "amount" in ue else None

def p2sh_for(redeem_bytes):
    """SDK-computed P2SH (address + spk hex) for a raw redeem script."""
    rhex = redeem_bytes.hex()
    sb = None
    for arg in (rhex, redeem_bytes):
        try: sb = ScriptBuilder.from_script(arg); break
        except Exception: pass
    if sb is None:
        raise SystemExit("ScriptBuilder.from_script rejected both hex and bytes")
    p2sh = sb.create_pay_to_script_hash_script()
    addr = None
    for net in (NETWORK, "testnet-10"):
        try: addr = address_from_script_public_key(p2sh, net); break
        except Exception: pass
    # local sanity: SDK P2SH script should be aa20<blake2b(redeem)>87
    local = "aa20" + hashlib.blake2b(redeem_bytes, digest_size=32).hexdigest() + "87"
    return addr.to_string(), to_hex(p2sh.script), local

async def with_client():
    enc = getattr(kaspa.Encoding, "Borsh", None)
    c = RpcClient(url=RPC_URL, encoding=enc) if enc else RpcClient(url=RPC_URL)
    await asyncio.wait_for(aw(c.connect()), timeout=8)
    info = await aw(c.get_server_info())
    if "testnet" not in str(info.get("networkId")):
        raise SystemExit(f"connected to {info.get('networkId')}, not testnet")
    return c

async def utxos_for(c, addr):
    r = await aw(c.get_utxos_by_addresses({"addresses": [addr]}))
    return r.get("entries", r) if isinstance(r, dict) else r

# ---- commands ---------------------------------------------------------------
def cmd_build(args):
    count = int(args.count)
    redeem = redeem_for(count)
    addr, spk, local = p2sh_for(redeem)
    print("redeem (hex)  :", redeem.hex())
    print("redeem length :", len(redeem), "(SCRIPT_LEN baked =", _SCRIPT_LEN, ")")
    print("SDK p2sh spk  :", spk)
    print("local  p2sh   :", local, "(MATCH)" if spk.endswith(local) or local in spk else "(!! mismatch)")
    print("count         :", count)
    print("ADDRESS       :", addr)
    json.dump({"network": NETWORK, "count": count, "address": addr},
              open(CFG_PATH, "w"), indent=2)
    print("\nSaved. Fund the address, then: info / step")

async def cmd_info(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    addr, _, _ = p2sh_for(redeem_for(cfg["count"]))
    entries = await utxos_for(c, addr)
    bal = sum(get_amount(u) or 0 for u in entries)
    print("count  :", cfg["count"])
    print("address:", addr)
    print("balance:", bal/SOMPI, "TKAS across", len(entries), "UTXO(s)")
    await aw(c.disconnect())

async def cmd_step(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    count = cfg["count"]
    redeem = redeem_for(count)
    cur_addr, _, _ = p2sh_for(redeem)
    entries = await utxos_for(c, cur_addr)
    if not entries: raise SystemExit(f"no UTXO at count={count} address {cur_addr}")
    u = entries[0]; in_amt = get_amount(u)

    child_addr, _, _ = p2sh_for(redeem_for(count + 1))
    out0 = PaymentOutput(child_addr, in_amt - FEE_SOMPI)
    print(f"step: count {count} -> {count+1} | {in_amt/SOMPI} TKAS -> {child_addr}")

    entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)
    tx = create_transaction([entry], [out0], 0)
    # sig script = just the redeem push (no args, no selector, no signature)
    sig_script = bytes([len(redeem)]) + redeem          # len(50) < 0x4c -> 1-byte push
    tx.inputs[0].signature_script = sig_script.hex()
    try:
        r = await aw(c.submit_transaction({"transaction": tx, "allowOrphan": False}))
        print("*** SUBMITTED ***:", r)
        cfg["count"] = count + 1; cfg["address"] = child_addr
        json.dump(cfg, open(CFG_PATH, "w"), indent=2)
        print(f"config advanced to count={count+1}; funds now at {child_addr}")
    except Exception as e:
        print("error:", repr(e))
    await aw(c.disconnect())

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build"); b.add_argument("--count", type=int, default=0); b.set_defaults(fn=cmd_build)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    sub.add_parser("step").set_defaults(fn=cmd_step)
    args = p.parse_args()
    if args.cmd == "build": args.fn(args)
    else: asyncio.run(args.fn(args))

if __name__ == "__main__":
    main()
