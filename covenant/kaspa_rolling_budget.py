#!/usr/bin/env python3
"""
Step 2b-2 -- ROLLING BUDGET covenant (TN10). The full thing.

Two-field self-templating state [budget_remaining, period_anchor], with a calendar
reset driven by tx.lock_time (confirmed to be a sound DAA clock by the lock_time probe).

Per spend:
  (non-finality guard) Op1 OpCheckSequenceVerify   # forces lock_time to be enforced
  spent  = output[0].value
  L      = tx.lock_time                              # DAA "now" (consensus caps L <= now)
  reset  = L >= period_anchor + PERIOD
  new_budget = reset ? FULL - spent : budget - spent    (require >= 0)
  new_anchor = reset ? L            : period_anchor
  bind output[1] to child(new_budget, new_anchor) via the proven templating tail

=> spendable per period is bounded by FULL; once a PERIOD has elapsed since the anchor,
   the next spend refills to FULL and re-anchors. Multiple spends per period draw down
   the same budget. A spender can't force an early refill (can't future-date L).

State (front, two fixed-width ints): 08 <budget:8 LE> 08 <anchor:8 LE>
Outputs: output[0] = payee (draws down budget), output[1] = child covenant.

Still to layer (Step 3): per-spend cap, destination whitelist, dev fee, owner escape,
agent auth. This proves the rolling-budget mechanic itself.
"""
import asyncio, json, argparse, inspect, hashlib
import kaspa
from kaspa import (RpcClient, ScriptBuilder, PaymentOutput,
                   address_from_script_public_key, create_transaction)

CFG_PATH = "rolling_budget_config.json"
NETWORK  = "testnet"
RPC_URL  = "ws://159.195.64.93:8080/kaspa/testnet-10/wrpc/borsh"
FEE_SOMPI = 1_000_000
MIN_OUT_SOMPI = 5_000_000
SOMPI = 100_000_000
STATE_LEN = 18
LOCKTIME_MARGIN = 200   # declare lock_time this many DAA in the past so the tx is final
                        # (virtual DAA leads the finality-check DAA; margin covers the gap)

def push_num(n):
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

def build_tail(script_len, full, period):
    b = bytearray()
    b += bytes([0x51, 0xb1])                            # Op1 OpCheckSequenceVerify (force non-final)
    b += bytes([0x00, 0xc2])                            # Op0 OpTxOutputAmount -> spent
    b += bytes([0xb5])                                  # OpTxLockTime -> L
    # reset = L >= anchor + PERIOD  (preserve L, anchor)
    b += bytes([0x00, 0x79])                            # Op0 OpPick (copy L)
    b += bytes([0x53, 0x79])                            # Op3 OpPick (copy anchor)
    b += push_num(period)
    b += bytes([0x93])                                  # OpAdd -> anchor+PERIOD
    b += bytes([0xa2])                                  # OpGreaterThanOrEqual -> reset
    b += bytes([0x63])                                  # OpIf
    #   reset: nb = FULL - spent ; na = L
    b += push_num(full)
    b += bytes([0x52, 0x79])                            # Op2 OpPick (copy spent)
    b += bytes([0x94])                                  # OpSub -> nb
    b += bytes([0x51, 0x79])                            # Op1 OpPick (copy L) -> na
    b += bytes([0x6b, 0x6b, 0x6d, 0x6d, 0x6c, 0x6c])    # park na,nb; 2drop 2drop; restore nb,na
    b += bytes([0x67])                                  # OpElse
    #   continue: nb = budget - spent ; na = anchor
    b += bytes([0x53, 0x79])                            # Op3 OpPick (copy budget)
    b += bytes([0x52, 0x79])                            # Op2 OpPick (copy spent)
    b += bytes([0x94])                                  # OpSub -> nb
    b += bytes([0x53, 0x79])                            # Op3 OpPick (copy anchor) -> na
    b += bytes([0x6b, 0x6b, 0x6d, 0x6d, 0x6c, 0x6c])
    b += bytes([0x68])                                  # OpEndIf   -> stack [nb, na]
    # require nb >= 0
    b += bytes([0x51, 0x79, 0x00, 0xa2, 0x69])          # Op1 OpPick Op0 OpGreaterThanOrEqual OpVerify
    # new_state = budgetpush || anchorpush   (stack [nb, na], na on top)
    b += bytes([0x58, 0xcd, 0x01, 0x08, 0x7c, 0x7e])    # encode na -> anchorpush
    b += bytes([0x7c])                                  # OpSwap  -> [anchorpush, nb]
    b += bytes([0x58, 0xcd, 0x01, 0x08, 0x7c, 0x7e])    # encode nb -> budgetpush
    b += bytes([0x7c, 0x7e])                            # OpSwap OpCat -> new_state
    # templating tail (STATE_LEN = 18)
    b += bytes([0xb9, 0x76, 0xc9, 0x76])                # OpTxInputIndex OpDup OpTxInputScriptSigLen OpDup
    b += bytes([0x01, script_len, 0x94])                # push SCRIPT_LEN OpSub
    b += bytes([0x01, STATE_LEN, 0x93])                 # push 18 OpAdd -> begin
    b += bytes([0x7c, 0xbc, 0x7e])                      # OpSwap OpTxInputScriptSigSubstr OpCat
    b += bytes([0xaa])                                  # OpBlake2b
    b += bytes([0x02, 0x00, 0x00])                      # push 0x0000
    b += bytes([0x01, 0xaa, 0x7e])                      # push 0xaa OpCat
    b += bytes([0x01, 0x20, 0x7e])                      # push 0x20 OpCat
    b += bytes([0x7c, 0x7e])                            # OpSwap OpCat -> 0000aa20||hash
    b += bytes([0x01, 0x87, 0x7e])                      # push 0x87 OpCat -> expected spk
    b += bytes([0x51, 0xc3])                            # Op1 OpTxOutputSpk (output index 1)
    b += bytes([0x87, 0x69])                            # OpEqual OpVerify
    b += bytes([0x51])                                  # OpTrue
    return bytes(b)

# fixed point: state(18) + tail; tail length is constant for fixed full/period and a
# 1-byte SCRIPT_LEN push, so compute once and bake.
def make_tail(full, period):
    sl = STATE_LEN + len(build_tail(0, full, period))
    if sl >= 256: raise SystemExit("script length >= 256; SCRIPT_LEN push needs 2 bytes (not handled)")
    t = build_tail(sl, full, period)
    assert STATE_LEN + len(t) == sl, "fixed point did not close"
    return t, sl

def redeem_for(budget, anchor, full, period):
    tail, _ = make_tail(full, period)
    return (bytes([0x08]) + int(budget).to_bytes(8, "little")
            + bytes([0x08]) + int(anchor).to_bytes(8, "little") + tail)

# ---- helpers ----------------------------------------------------------------
def to_hex(x):
    if isinstance(x, str): return x
    if isinstance(x, (bytes, bytearray)): return bytes(x).hex()
    for m in ("to_string", "to_hex"):
        if hasattr(x, m): return getattr(x, m)()
    return str(x)
async def aw(x): return await x if inspect.isawaitable(x) else x
def tkas_to_sompi(v): return int(round(float(v) * SOMPI))
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

async def current_daa(c):
    r = await aw(c.get_block_dag_info())
    return int(r["virtualDaaScore"])

async def utxos_for(c, addr):
    r = await aw(c.get_utxos_by_addresses({"addresses": [addr]}))
    return r.get("entries", r) if isinstance(r, dict) else r

# ---- commands ---------------------------------------------------------------
def cmd_build(args):
    full = tkas_to_sompi(args.full_tkas); period = int(args.period_daa)
    budget = full; anchor = int(args.anchor)
    redeem = redeem_for(budget, anchor, full, period)
    addr, spk, local = p2sh_for(redeem)
    _, sl = make_tail(full, period)
    print("redeem (hex)  :", redeem.hex())
    print("redeem length :", len(redeem), "(SCRIPT_LEN =", sl, ")")
    print("p2sh check    :", "MATCH" if local in spk else "!! MISMATCH")
    print(f"FULL/period   : {full/SOMPI} TKAS per {period} DAA ; budget={budget/SOMPI} anchor={anchor}")
    print("ADDRESS       :", addr)
    json.dump({"network": NETWORK, "full_sompi": full, "period_daa": period,
               "budget_sompi": budget, "anchor": anchor, "address": addr},
              open(CFG_PATH, "w"), indent=2)
    print("\nSaved. Fund the address, then: info / spend <payee> <amount_tkas>")

async def cmd_info(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    addr, _, _ = p2sh_for(redeem_for(cfg["budget_sompi"], cfg["anchor"], cfg["full_sompi"], cfg["period_daa"]))
    entries = await utxos_for(c, addr); D = await current_daa(c)
    bal = sum(get_amount(u) or 0 for u in entries)
    nxt = cfg["anchor"] + cfg["period_daa"]
    print(f"budget {cfg['budget_sompi']/SOMPI} / FULL {cfg['full_sompi']/SOMPI} TKAS ; period {cfg['period_daa']} DAA")
    print(f"anchor {cfg['anchor']} ; next reset at DAA {nxt} ; now {D} ->",
          "RESET available" if D >= nxt else f"{nxt-D} DAA to reset")
    print("address:", addr, "| balance:", bal/SOMPI, "TKAS across", len(entries), "UTXO(s)")
    await aw(c.disconnect())

async def cmd_spend(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    full = cfg["full_sompi"]; period = cfg["period_daa"]
    budget = cfg["budget_sompi"]; anchor = cfg["anchor"]
    cur_addr, _, _ = p2sh_for(redeem_for(budget, anchor, full, period))
    entries = await utxos_for(c, cur_addr)
    if not entries: raise SystemExit(f"no UTXO at {cur_addr}")
    u = entries[0]; in_amt = get_amount(u)
    D = await current_daa(c)

    L = D - LOCKTIME_MARGIN                # lock_time safely in the past -> tx is final
    reset = L >= anchor + period
    avail = full if reset else budget
    amount = tkas_to_sompi(args.amount_tkas)
    if amount < MIN_OUT_SOMPI: raise SystemExit(f"amount below ~{MIN_OUT_SOMPI/SOMPI} TKAS floor")
    if amount > avail:
        raise SystemExit(f"amount {amount/SOMPI} exceeds available {avail/SOMPI} TKAS "
                         f"({'reset->FULL' if reset else 'remaining budget'}); covenant would reject")
    change = in_amt - amount - FEE_SOMPI
    if change < MIN_OUT_SOMPI: raise SystemExit(f"change {change/SOMPI} below floor")

    new_budget = (full if reset else budget) - amount
    new_anchor = L if reset else anchor
    child_addr, _, _ = p2sh_for(redeem_for(new_budget, new_anchor, full, period))
    out0 = PaymentOutput(args.payee, amount)
    out1 = PaymentOutput(child_addr, change)
    print(f"spend {amount/SOMPI} -> {args.payee} | lock_time={L} reset={reset}")
    print(f"  budget {budget/SOMPI} -> {new_budget/SOMPI} | anchor {anchor} -> {new_anchor} | change {change/SOMPI} -> child")

    entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)
    redeem = redeem_for(budget, anchor, full, period)
    tx = create_transaction([entry], [out0, out1], 0)
    try: tx.lock_time = L
    except Exception as e: print("(lock_time set failed:", repr(e), ")")
    try: tx.inputs[0].sequence = 1            # non-final + satisfies OpCheckSequenceVerify 1
    except Exception as e: print("(sequence set failed:", repr(e), ")")
    tx.inputs[0].signature_script = push_redeem(redeem).hex()
    try:
        r = await aw(c.submit_transaction({"transaction": tx, "allowOrphan": False}))
        print("*** SUBMITTED ***:", r)
        cfg["budget_sompi"] = new_budget; cfg["anchor"] = new_anchor; cfg["address"] = child_addr
        json.dump(cfg, open(CFG_PATH, "w"), indent=2)
        print(f"-> budget {new_budget/SOMPI} TKAS, anchor {new_anchor}; funds at {child_addr}")
    except Exception as e:
        print("error:", repr(e)[:200])
    await aw(c.disconnect())

def main():
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--full-tkas", type=float, default=20.0)
    b.add_argument("--period-daa", type=int, default=600)
    b.add_argument("--anchor", type=int, default=0)
    b.set_defaults(fn=cmd_build)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    s = sub.add_parser("spend"); s.add_argument("payee"); s.add_argument("amount_tkas"); s.set_defaults(fn=cmd_spend)
    args = p.parse_args()
    if args.cmd == "build": args.fn(args)
    else: asyncio.run(args.fn(args))

if __name__ == "__main__":
    main()
