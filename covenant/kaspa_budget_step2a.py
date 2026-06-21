#!/usr/bin/env python3
"""
Step 2a -- self-templating BUDGET covenant (TN10).

Builds directly on the proven Step-1 counter. Same self-templating scaffolding
(tail read from the spending input, blake2b-over-new_state||tail, aa20..87 wrap),
but the transition is now a budget draw-down instead of a counter increment:

State (front of redeem, one fixed-width int):
    08 <budget_remaining : 8 bytes LE>

Per spend, two outputs:
    output[0] = payee   (value = amount spent; this is what draws down the budget)
    output[1] = child covenant (remaining funds, carrying budget_remaining - amount)

Tail logic:
    Op0 OpTxOutputAmount          # spent = output[0].value
    OpSub                         # new_budget = budget - spent
    OpDup Op0 OpGreaterThanOrEqual OpVerify   # require new_budget >= 0
    Op8 OpNum2Bin <08> OpSwap OpCat           # encode new_state = 08||bin8(new_budget)
    <tail-read from input> OpCat              # child_redeem = new_state || tail
    OpBlake2b <wrap to 0000 aa20 hash 87>     # expected child P2SH spk
    Op1 OpTxOutputSpk OpEqual OpVerify        # require output[1].spk == child
    OpTrue

NOT yet present (deliberately, coming in 2b / Step 3): period reset, value
conservation / fee cap, per-spend cap, whitelist, dev fee, owner escape, auth.
=> With no reset and no escape, once budget hits 0 the remaining funds are stuck.
   Test with SMALL amounts on testnet.
"""
import asyncio, json, argparse, inspect, hashlib
import kaspa
from kaspa import (RpcClient, ScriptBuilder, PaymentOutput,
                   address_from_script_public_key, create_transaction)

CFG_PATH = "budget_step2a_config.json"
NETWORK  = "testnet"
RPC_URL  = "ws://159.195.64.93:8080/kaspa/testnet-10/wrpc/borsh"
FEE_SOMPI = 1_000_000
MIN_OUT_SOMPI = 5_000_000
SOMPI = 100_000_000

STATE_LEN = 9   # one field: 0x08 + 8 bytes

def build_tail(script_len):
    return bytes([
        0x00,                   # Op0
        0xc2,                   # OpTxOutputAmount      -> spent = output[0].value
        0x94,                   # OpSub                 -> new_budget = budget - spent
        0x76,                   # OpDup
        0x00,                   # Op0
        0xa2,                   # OpGreaterThanOrEqual
        0x69,                   # OpVerify              -> require new_budget >= 0
        0x58,                   # Op8 (width)
        0xcd,                   # OpNum2Bin
        0x01, 0x08,             # push 0x08
        0x7c,                   # OpSwap
        0x7e,                   # OpCat                 -> new_state = 08||bin8(new_budget)
        0xb9,                   # OpTxInputIndex
        0x76,                   # OpDup
        0xc9,                   # OpTxInputScriptSigLen
        0x76,                   # OpDup
        0x01, script_len,       # push SCRIPT_LEN
        0x94,                   # OpSub
        0x01, STATE_LEN,        # push STATE_LEN
        0x93,                   # OpAdd                 -> begin = siglen - SCRIPT_LEN + STATE_LEN
        0x7c,                   # OpSwap
        0xbc,                   # OpTxInputScriptSigSubstr -> tail
        0x7e,                   # OpCat                 -> child_redeem
        0xaa,                   # OpBlake2b
        0x02, 0x00, 0x00,       # push 0x0000 (version)
        0x01, 0xaa,             # push 0xaa
        0x7e,                   # OpCat
        0x01, 0x20,             # push 0x20
        0x7e,                   # OpCat
        0x7c,                   # OpSwap
        0x7e,                   # OpCat                 -> 0000aa20||hash
        0x01, 0x87,             # push 0x87
        0x7e,                   # OpCat                 -> expected child spk
        0x51,                   # Op1 (OUTPUT INDEX 1 -- the child/change output)
        0xc3,                   # OpTxOutputSpk
        0x87,                   # OpEqual
        0x69,                   # OpVerify
        0x51,                   # OpTrue
    ])

_SCRIPT_LEN = STATE_LEN + len(build_tail(0))
TAIL = build_tail(_SCRIPT_LEN)
assert STATE_LEN + len(TAIL) == _SCRIPT_LEN, "script-length fixed point did not close"

def redeem_for(budget_sompi):
    return bytes([0x08]) + int(budget_sompi).to_bytes(8, "little") + TAIL

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

async def utxos_for(c, addr):
    r = await aw(c.get_utxos_by_addresses({"addresses": [addr]}))
    return r.get("entries", r) if isinstance(r, dict) else r

# ---- commands ---------------------------------------------------------------
def cmd_build(args):
    budget = tkas_to_sompi(args.budget_tkas)
    redeem = redeem_for(budget)
    addr, spk, local = p2sh_for(redeem)
    print("redeem (hex)  :", redeem.hex())
    print("redeem length :", len(redeem), "(SCRIPT_LEN baked =", _SCRIPT_LEN, ")")
    print("p2sh check    :", "MATCH" if local in spk else "!! MISMATCH",
          "\n  sdk  :", spk, "\n  local:", local)
    print("budget        :", budget/SOMPI, "TKAS")
    print("ADDRESS       :", addr)
    json.dump({"network": NETWORK, "budget_sompi": budget, "address": addr},
              open(CFG_PATH, "w"), indent=2)
    print("\nSaved. Fund the address, then: info / spend <payee> <amount_tkas>")

async def cmd_info(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    addr, _, _ = p2sh_for(redeem_for(cfg["budget_sompi"]))
    entries = await utxos_for(c, addr)
    bal = sum(get_amount(u) or 0 for u in entries)
    print("budget remaining:", cfg["budget_sompi"]/SOMPI, "TKAS")
    print("address         :", addr)
    print("balance         :", bal/SOMPI, "TKAS across", len(entries), "UTXO(s)")
    await aw(c.disconnect())

async def cmd_spend(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    budget = cfg["budget_sompi"]
    cur_addr, _, _ = p2sh_for(redeem_for(budget))
    entries = await utxos_for(c, cur_addr)
    if not entries: raise SystemExit(f"no UTXO at current address {cur_addr}")
    u = entries[0]; in_amt = get_amount(u)

    amount = tkas_to_sompi(args.amount_tkas)
    if amount < MIN_OUT_SOMPI:
        raise SystemExit(f"amount below storage-mass floor (~{MIN_OUT_SOMPI/SOMPI} TKAS)")
    if amount > budget:
        raise SystemExit(f"amount {amount/SOMPI} exceeds remaining budget {budget/SOMPI} TKAS "
                         f"(covenant would reject: new_budget < 0)")
    change = in_amt - amount - FEE_SOMPI
    if change < MIN_OUT_SOMPI:
        raise SystemExit(f"change {change/SOMPI} below storage-mass floor; fund more or spend less")

    new_budget = budget - amount
    child_addr, _, _ = p2sh_for(redeem_for(new_budget))
    out0 = PaymentOutput(args.payee, amount)           # payee: draws down the budget
    out1 = PaymentOutput(child_addr, change)           # child covenant: carries new_budget
    print(f"spend: {amount/SOMPI} -> {args.payee}")
    print(f"       budget {budget/SOMPI} -> {new_budget/SOMPI} TKAS | change {change/SOMPI} -> child")

    entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)
    redeem = redeem_for(budget)
    tx = create_transaction([entry], [out0, out1], 0)
    tx.inputs[0].signature_script = (bytes([len(redeem)]) + redeem).hex()  # just the redeem push
    try:
        r = await aw(c.submit_transaction({"transaction": tx, "allowOrphan": False}))
        print("*** SUBMITTED ***:", r)
        cfg["budget_sompi"] = new_budget; cfg["address"] = child_addr
        json.dump(cfg, open(CFG_PATH, "w"), indent=2)
        print(f"budget advanced to {new_budget/SOMPI} TKAS; funds now at {child_addr}")
    except Exception as e:
        print("error:", repr(e))
    await aw(c.disconnect())

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build"); b.add_argument("--budget-tkas", type=float, default=20.0); b.set_defaults(fn=cmd_build)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    s = sub.add_parser("spend"); s.add_argument("payee"); s.add_argument("amount_tkas"); s.set_defaults(fn=cmd_spend)
    args = p.parse_args()
    if args.cmd == "build": args.fn(args)
    else: asyncio.run(args.fn(args))

if __name__ == "__main__":
    main()
