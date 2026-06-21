#!/usr/bin/env python3
"""
Step 2b-1 -- two-field self-templating budget (TN10).

Plumbing step before the period reset. State grows from one int to two:
    08 <budget_remaining : 8 bytes LE>
    08 <period_anchor    : 8 bytes LE>
budget decrements by output[0].value exactly as in 2a; the anchor is CARRIED
UNCHANGED. This isolates everything new about two fields (STATE_LEN=18, two-field
encode order, alt-stack cleanup, OpPick access) with no reset arithmetic yet.

A confirmed spend proves both fields survive the rebuild round-trip. Step 2b-2
swaps the inert carry for the live lock-time reset.

Tail logic:
    Op0 OpTxOutputAmount                       # spent = output[0].value
    Op2 OpPick Op1 OpPick OpSub                # new_budget = budget - spent
    Op0 OpPick Op0 OpGreaterThanOrEqual OpVerify   # require new_budget >= 0
    Op2 OpPick                                 # new_anchor = anchor  (unchanged)
    <encode new_anchor as 08||bin8> <encode new_budget as 08||bin8> OpCat   # new_state
    <drop working values via alt stack>
    <tail-read from input, STATE_LEN=18> OpCat OpBlake2b <wrap 0000 aa20 .. 87>
    Op1 OpTxOutputSpk OpEqual OpVerify          # bind output[1] (the child)
    OpTrue

Still absent (Step 2b-2 / Step 3): the reset, fee/value conservation, per-spend cap,
whitelist, dev fee, owner escape, auth. Test with small amounts.
"""
import asyncio, json, argparse, inspect, hashlib
import kaspa
from kaspa import (RpcClient, ScriptBuilder, PaymentOutput,
                   address_from_script_public_key, create_transaction)

CFG_PATH = "budget_step2b1_config.json"
NETWORK  = "testnet"
RPC_URL  = "ws://159.195.64.93:8080/kaspa/testnet-10/wrpc/borsh"
FEE_SOMPI = 1_000_000
MIN_OUT_SOMPI = 5_000_000
SOMPI = 100_000_000

STATE_LEN = 18   # two fields, each 0x08 + 8 bytes

def build_tail(script_len):
    return bytes([
        # --- compute new_budget = budget - spent, require >= 0 ---
        0x00,             # Op0
        0xc2,             # OpTxOutputAmount        -> spent = output[0].value
        0x52, 0x79,       # Op2 OpPick              -> copy budget (depth 2)
        0x51, 0x79,       # Op1 OpPick              -> copy spent  (depth 1)
        0x94,             # OpSub                   -> new_budget = budget - spent
        0x00, 0x79,       # Op0 OpPick              -> copy new_budget
        0x00,             # Op0
        0xa2,             # OpGreaterThanOrEqual
        0x69,             # OpVerify                -> require new_budget >= 0
        # --- new_anchor = anchor (unchanged) ---
        0x52, 0x79,       # Op2 OpPick              -> copy anchor (depth 2) = new_anchor
        # --- encode new_anchor -> anchorpush (08 || bin8) ---
        0x58,             # Op8
        0xcd,             # OpNum2Bin
        0x01, 0x08,       # push 0x08
        0x7c,             # OpSwap
        0x7e,             # OpCat                   -> anchorpush
        # --- encode new_budget -> budgetpush ---
        0x7c,             # OpSwap                  -> bring new_budget to top
        0x58,             # Op8
        0xcd,             # OpNum2Bin
        0x01, 0x08,       # push 0x08
        0x7c,             # OpSwap
        0x7e,             # OpCat                   -> budgetpush
        # --- new_state = budgetpush || anchorpush (budget field first) ---
        0x7c,             # OpSwap
        0x7e,             # OpCat                   -> new_state
        # --- drop the 3 working values (budget, anchor, spent) under new_state ---
        0x6b,             # OpToAltStack            (park new_state)
        0x6d,             # Op2Drop
        0x75,             # OpDrop
        0x6c,             # OpFromAltStack          -> new_state
        # --- templating tail (STATE_LEN = 18) ---
        0xb9,             # OpTxInputIndex
        0x76,             # OpDup
        0xc9,             # OpTxInputScriptSigLen
        0x76,             # OpDup
        0x01, script_len, # push SCRIPT_LEN
        0x94,             # OpSub
        0x01, STATE_LEN,  # push STATE_LEN (18)
        0x93,             # OpAdd                   -> begin
        0x7c,             # OpSwap
        0xbc,             # OpTxInputScriptSigSubstr-> tail
        0x7e,             # OpCat                   -> child_redeem
        0xaa,             # OpBlake2b
        0x02, 0x00, 0x00, # push 0x0000 (version)
        0x01, 0xaa,       # push 0xaa
        0x7e,             # OpCat
        0x01, 0x20,       # push 0x20
        0x7e,             # OpCat
        0x7c,             # OpSwap
        0x7e,             # OpCat                   -> 0000aa20 || hash
        0x01, 0x87,       # push 0x87
        0x7e,             # OpCat                   -> expected child spk
        0x51,             # Op1 (OUTPUT INDEX 1)
        0xc3,             # OpTxOutputSpk
        0x87,             # OpEqual
        0x69,             # OpVerify
        0x51,             # OpTrue
    ])

_SCRIPT_LEN = STATE_LEN + len(build_tail(0))
TAIL = build_tail(_SCRIPT_LEN)
assert STATE_LEN + len(TAIL) == _SCRIPT_LEN, "script-length fixed point did not close"

def redeem_for(budget_sompi, anchor):
    return (bytes([0x08]) + int(budget_sompi).to_bytes(8, "little")
            + bytes([0x08]) + int(anchor).to_bytes(8, "little") + TAIL)

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

def push_redeem(redeem):
    """Sig script = a single data push of the redeem. Lengths >= 0x4c need OpPushData1,
    not a bare length byte (a bare 0x54 would be parsed as Op4, not a push)."""
    n = len(redeem)
    if n < 0x4c:    return bytes([n]) + redeem
    elif n <= 0xff: return bytes([0x4c, n]) + redeem
    else:           return bytes([0x4d]) + n.to_bytes(2, "little") + redeem

# ---- commands ---------------------------------------------------------------
def cmd_build(args):
    budget = tkas_to_sompi(args.budget_tkas); anchor = int(args.anchor)
    redeem = redeem_for(budget, anchor)
    addr, spk, local = p2sh_for(redeem)
    print("redeem (hex)  :", redeem.hex())
    print("redeem length :", len(redeem), "(SCRIPT_LEN baked =", _SCRIPT_LEN, ")")
    print("p2sh check    :", "MATCH" if local in spk else "!! MISMATCH")
    print("budget        :", budget/SOMPI, "TKAS ; anchor:", anchor, "(carried, inert in 2b-1)")
    print("ADDRESS       :", addr)
    json.dump({"network": NETWORK, "budget_sompi": budget, "anchor": anchor, "address": addr},
              open(CFG_PATH, "w"), indent=2)
    print("\nSaved. Fund the address, then: info / spend <payee> <amount_tkas>")

async def cmd_info(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    addr, _, _ = p2sh_for(redeem_for(cfg["budget_sompi"], cfg["anchor"]))
    entries = await utxos_for(c, addr)
    bal = sum(get_amount(u) or 0 for u in entries)
    print("budget remaining:", cfg["budget_sompi"]/SOMPI, "TKAS ; anchor:", cfg["anchor"])
    print("address         :", addr)
    print("balance         :", bal/SOMPI, "TKAS across", len(entries), "UTXO(s)")
    await aw(c.disconnect())

async def cmd_spend(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    budget = cfg["budget_sompi"]; anchor = cfg["anchor"]
    cur_addr, _, _ = p2sh_for(redeem_for(budget, anchor))
    entries = await utxos_for(c, cur_addr)
    if not entries: raise SystemExit(f"no UTXO at current address {cur_addr}")
    u = entries[0]; in_amt = get_amount(u)

    amount = tkas_to_sompi(args.amount_tkas)
    if amount < MIN_OUT_SOMPI: raise SystemExit(f"amount below ~{MIN_OUT_SOMPI/SOMPI} TKAS floor")
    if amount > budget: raise SystemExit(f"amount exceeds budget {budget/SOMPI} (covenant would reject)")
    change = in_amt - amount - FEE_SOMPI
    if change < MIN_OUT_SOMPI: raise SystemExit(f"change {change/SOMPI} below floor; fund more / spend less")

    new_budget = budget - amount
    child_addr, _, _ = p2sh_for(redeem_for(new_budget, anchor))    # anchor unchanged
    out0 = PaymentOutput(args.payee, amount)
    out1 = PaymentOutput(child_addr, change)
    print(f"spend: {amount/SOMPI} -> {args.payee}")
    print(f"       budget {budget/SOMPI} -> {new_budget/SOMPI} | anchor {anchor} (carried) | change {change/SOMPI} -> child")

    entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)
    redeem = redeem_for(budget, anchor)
    tx = create_transaction([entry], [out0, out1], 0)
    tx.inputs[0].signature_script = push_redeem(redeem).hex()
    try:
        r = await aw(c.submit_transaction({"transaction": tx, "allowOrphan": False}))
        print("*** SUBMITTED ***:", r)
        cfg["budget_sompi"] = new_budget; cfg["address"] = child_addr
        json.dump(cfg, open(CFG_PATH, "w"), indent=2)
        print(f"budget advanced to {new_budget/SOMPI} TKAS (anchor still {anchor}); funds at {child_addr}")
    except Exception as e:
        print("error:", repr(e))
    await aw(c.disconnect())

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--budget-tkas", type=float, default=20.0)
    b.add_argument("--anchor", type=int, default=0)
    b.set_defaults(fn=cmd_build)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    s = sub.add_parser("spend"); s.add_argument("payee"); s.add_argument("amount_tkas"); s.set_defaults(fn=cmd_spend)
    args = p.parse_args()
    if args.cmd == "build": args.fn(args)
    else: asyncio.run(args.fn(args))

if __name__ == "__main__":
    main()
