#!/usr/bin/env python3
"""
lock_time semantics probe (TN10).

2b-2's calendar reset needs tx.lock_time to behave as a raw DAA score that the
script can compare (OpTxLockTime) and that consensus refuses to future-date. Your
node's DAA (~4.96e8) sits near the classic 5e8 lock-time threshold, so before
building the reset on lock_time, confirm:

  1. OpTxLockTime reads the tx's lock_time, comparable as a DAA number
  2. consensus rejects a tx whose lock_time is in the FUTURE (can't fake "now")

Covenant (no state, single path):
    OpTxLockTime <THRESHOLD> OpGreaterThanOrEqual OpVerify OpTrue
i.e. "spendable only if the tx declares lock_time >= THRESHOLD".

Commands:
  daa                                  # print the node's current virtual DAA score
  build --threshold <N>                # covenant requiring lock_time >= N
  info
  spend <payee> <locktime>             # spend, setting tx.lock_time = <locktime>
"""
import asyncio, json, argparse, inspect, hashlib
import kaspa
from kaspa import (RpcClient, ScriptBuilder, PaymentOutput,
                   address_from_script_public_key, create_transaction)

CFG_PATH = "locktime_probe_config.json"
NETWORK  = "testnet"
RPC_URL  = "ws://159.195.64.93:8080/kaspa/testnet-10/wrpc/borsh"
FEE_SOMPI = 1_000_000
SOMPI = 100_000_000

def push_num(n):
    """Minimal CScriptNum push of a non-negative int as OpData{len} || LE bytes."""
    if n == 0: return bytes([0x00])
    b = bytearray()
    while n: b.append(n & 0xff); n >>= 8
    if b[-1] & 0x80: b.append(0x00)
    return bytes([len(b)]) + bytes(b)

def push_redeem(redeem):
    n = len(redeem)
    if n < 0x4c:    return bytes([n]) + redeem
    elif n <= 0xff: return bytes([0x4c, n]) + redeem
    else:           return bytes([0x4d]) + n.to_bytes(2, "little") + redeem

def redeem_for(threshold):
    return bytes([0xb5]) + push_num(threshold) + bytes([0xa2, 0x69, 0x51])
    #            OpTxLockTime  <threshold>        OpGreaterThanOrEqual OpVerify OpTrue

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
    rhex = redeem_bytes.hex(); sb = None
    for arg in (rhex, redeem_bytes):
        try: sb = ScriptBuilder.from_script(arg); break
        except Exception: pass
    if sb is None: raise SystemExit("ScriptBuilder.from_script rejected hex and bytes")
    p2sh = sb.create_pay_to_script_hash_script()
    addr = None
    for net in (NETWORK, "testnet-10"):
        try: addr = address_from_script_public_key(p2sh, net); break
        except Exception: pass
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

async def cmd_daa(args):
    c = await with_client()
    for m in ("get_block_dag_info", "get_server_info", "get_sink_blue_score"):
        try: print(m, "->", await aw(getattr(c, m)()))
        except Exception as e: print(m, "err:", e)
    await aw(c.disconnect())

def cmd_build(args):
    th = int(args.threshold)
    redeem = redeem_for(th)
    addr, spk, local = p2sh_for(redeem)
    print("redeem (hex):", redeem.hex())
    print("p2sh check  :", "MATCH" if local in spk else "!! MISMATCH")
    print("threshold   :", th, "(spendable only if tx.lock_time >= this)")
    print("ADDRESS     :", addr)
    json.dump({"network": NETWORK, "threshold": th, "address": addr},
              open(CFG_PATH, "w"), indent=2)
    print("\nSaved. Fund, then: spend <payee> <locktime>")

async def cmd_info(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    addr, _, _ = p2sh_for(redeem_for(cfg["threshold"]))
    entries = await utxos_for(c, addr)
    print("threshold:", cfg["threshold"], "| address:", addr)
    print("balance  :", sum(get_amount(u) or 0 for u in entries)/SOMPI, "TKAS across", len(entries), "UTXO(s)")
    await aw(c.disconnect())

async def cmd_spend(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    th = cfg["threshold"]; redeem = redeem_for(th)
    addr, _, _ = p2sh_for(redeem)
    entries = await utxos_for(c, addr)
    if not entries: raise SystemExit("not funded")
    u = entries[0]; in_amt = get_amount(u)
    L = int(args.locktime)
    out0 = PaymentOutput(args.payee, in_amt - FEE_SOMPI)
    entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)
    tx = create_transaction([entry], [out0], 0)
    try: tx.lock_time = L
    except Exception as e: print("(could not set lock_time:", repr(e), ")")
    tx.inputs[0].signature_script = push_redeem(redeem).hex()
    print(f"spend with tx.lock_time = {L} (threshold {th}); script wants lock_time >= threshold")
    try:
        print("*** SUBMITTED ***:", await aw(c.submit_transaction({"transaction": tx, "allowOrphan": False})))
    except Exception as e:
        print("rejected:", repr(e)[:160])
    await aw(c.disconnect())

def main():
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("daa").set_defaults(fn=cmd_daa)
    b = sub.add_parser("build"); b.add_argument("--threshold", type=int, required=True); b.set_defaults(fn=cmd_build)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    s = sub.add_parser("spend"); s.add_argument("payee"); s.add_argument("locktime"); s.set_defaults(fn=cmd_spend)
    args = p.parse_args()
    if args.cmd == "build": args.fn(args)
    else: asyncio.run(args.fn(args))

if __name__ == "__main__":
    main()
