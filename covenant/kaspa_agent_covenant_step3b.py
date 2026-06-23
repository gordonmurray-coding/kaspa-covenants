#!/usr/bin/env python3
"""
Step 3b -- FULL HARDENED AGENT-BUDGET COVENANT (TN10).

Everything composed: the proven 3a two-path scaffold (agent auth + owner escape over
the self-templating rolling budget), now with the agent path enforcing the full rule
set ahead of the budget transition. All rules are proven placements from the v2
covenant; the only structural change vs 3a is that the child binds at output[2] and
the output shape is pinned to exactly three outputs.

AGENT path (selector truthy, agent signature), outputs [payee, dev, child]:
  - output count == 3
  - per-spend CAP        : output[0].amount <= CAP
  - destination WHITELIST : output[0].spk in {approved spks}        (OpAdd sum-chain)
  - exact DEV FEE        : output[1].spk == dev  AND  output[1].amount == DEV_FEE
  - value CONSERVATION   : output[0]+output[1]+output[2] + FEE_ALLOWANCE >= input
                           (agent can't bleed the covenant via inflated fees)
  - rolling budget       : spent = output[0].amount; lock_time reset; >= 0 floor
  - templating           : bind output[2] = child covenant (state advanced)

OWNER path (selector falsy, owner signature): sweep anywhere, no rules.

Limits live in the script: an agent that ignores its own client code still cannot
exceed the cap, pay an unlisted address, skip the dev fee, drain via fees, or
out-spend the per-period budget. Only the owner key can break the pattern.
"""
import asyncio, json, argparse, inspect, hashlib
import kaspa
from kaspa import (RpcClient, ScriptBuilder, PaymentOutput, Keypair, PrivateKey,
                   SighashType, address_from_script_public_key, pay_to_address_script,
                   create_transaction, create_input_signature,
                   pay_to_script_hash_signature_script)

CFG_PATH = "agent_covenant_3b_config.json"
NETWORK  = "testnet"
RPC_URL  = "ws://159.195.64.93:8080/kaspa/testnet-10/wrpc/borsh"
FEE_SOMPI = 10_000_000              # 0.1 TKAS network fee
FEE_ALLOWANCE_SOMPI = 20_000_000    # 0.2 TKAS baked ceiling
MIN_OUT_SOMPI = 5_000_000
SOMPI = 100_000_000
STATE_LEN = 18
LOCKTIME_MARGIN = 200

# ---- byte helpers -----------------------------------------------------------
def to_hex(x):
    if isinstance(x, str): return x
    if isinstance(x, (bytes, bytearray)): return bytes(x).hex()
    for m in ("to_string", "to_hex"):
        if hasattr(x, m): return getattr(x, m)()
    return str(x)
def to_bytes(x): return x if isinstance(x, (bytes, bytearray)) else bytes.fromhex(to_hex(x))
async def aw(x): return await x if inspect.isawaitable(x) else x
def tkas_to_sompi(v): return int(round(float(v) * SOMPI))

def push_num(n):
    if n == 0: return bytes([0x00])
    b = bytearray()
    while n: b.append(n & 0xff); n >>= 8
    if b[-1] & 0x80: b.append(0x00)
    return bytes([len(b)]) + bytes(b)
def push_data(bs):
    n = len(bs)
    if n < 0x4c:    return bytes([n]) + bs
    elif n <= 0xff: return bytes([0x4c, n]) + bs
    else:           return bytes([0x4d]) + n.to_bytes(2, "little") + bs

def spk_full(addr):
    """Full consensus SPK as OpTxOutputSpk returns it: 2-byte version (LE) || script."""
    spk = pay_to_address_script(addr)
    return int(spk.version).to_bytes(2, "little") + to_bytes(spk.script)

# ---- the script -------------------------------------------------------------
def build_tail(script_len, p):
    SL = bytes([0x02]) + int(script_len).to_bytes(2, "little")
    ax = to_bytes(p["agent_x"]); ox = to_bytes(p["owner_x"])
    wls = [to_bytes(w) for w in p["whitelist"]]; dev = to_bytes(p["dev_spk"])
    cap = p["cap_sompi"]; dev_fee = p["dev_fee_sompi"]
    full = p["full_sompi"]; period = p["period_daa"]
    b = bytearray()
    b += bytes([0x52, 0x7a, 0x63])                       # Op2 OpRoll (selector->top) ; OpIf
    # ===================== AGENT PATH =====================
    b += bytes([0x52, 0x7a])                             # Op2 OpRoll (sig -> top)
    b += bytes([0x20]) + ax + bytes([0xad])              # push agent xonly ; OpCheckSigVerify
    b += bytes([0x51, 0xb1])                             # Op1 OpCheckSequenceVerify (force non-final)
    # ---- rule: exactly 3 outputs ----
    b += bytes([0xb4, 0x53, 0x9d])                       # OpTxOutputCount Op3 OpNumEqualVerify
    # ---- rule: per-spend cap  out0.amount <= CAP ----
    b += bytes([0x00, 0xc2]) + push_num(cap) + bytes([0xa1, 0x69])
    # ---- rule: whitelist  out0.spk in {wls}  (re-read spk per entry, sum-chain) ----
    # Combine equality results with OpAdd, not bitwise OpOr: OpEqual pushes 0x01 / empty,
    # whose lengths differ, and bitwise ops require equal-length operands (would hard-error
    # on a real match across >1 entry). Summing the booleans is length-agnostic; the running
    # total is the match count, and OpVerify passes on any nonzero total.
    for i, wl in enumerate(wls):
        b += bytes([0x00, 0xc3]) + push_data(wl) + bytes([0x87])   # Op0 OpTxOutputSpk wl OpEqual
        if i: b += bytes([0x93])                                   # OpAdd (running sum of matches)
    b += bytes([0x69])                                             # OpVerify (>=1 match -> nonzero)
    # ---- rule: dev fee  out1.spk == dev  &&  out1.amount == DEV_FEE ----
    b += bytes([0x51, 0xc3]) + push_data(dev) + bytes([0x88])      # Op1 OpTxOutputSpk dev OpEqualVerify
    b += bytes([0x51, 0xc2]) + push_num(dev_fee) + bytes([0x9d])   # Op1 OpTxOutputAmount DEV_FEE OpNumEqualVerify
    # ---- rule: value conservation  out0+out1+out2 + ALLOWANCE >= input ----
    b += bytes([0x00, 0xc2])                             # Op0 OpTxOutputAmount
    b += bytes([0x51, 0xc2, 0x93])                       # Op1 OpTxOutputAmount OpAdd
    b += bytes([0x52, 0xc2, 0x93])                       # Op2 OpTxOutputAmount OpAdd -> total_out
    b += push_num(FEE_ALLOWANCE_SOMPI) + bytes([0x93])   # + FEE_ALLOWANCE
    b += bytes([0x00, 0xbe])                             # Op0 OpTxInputAmount -> input.amount
    b += bytes([0xa2, 0x69])                             # OpGreaterThanOrEqual OpVerify (total+allow >= input)
    # ---- rolling budget transition (spent = out0.value), bind output[2] ----
    b += bytes([0x00, 0xc2])                             # Op0 OpTxOutputAmount -> spent
    b += bytes([0xb5])                                   # OpTxLockTime -> L
    b += bytes([0x00, 0x79, 0x53, 0x79])                 # Op0 OpPick(L) ; Op3 OpPick(anchor)
    b += push_num(period) + bytes([0x93, 0xa2])          # PERIOD OpAdd OpGreaterThanOrEqual -> reset
    b += bytes([0x63])                                   # OpIf
    b += push_num(full) + bytes([0x52, 0x79, 0x94])      #   reset: FULL Op2 OpPick(spent) OpSub -> nb
    b += bytes([0x51, 0x79])                             #   Op1 OpPick(L) -> na
    b += bytes([0x6b, 0x6b, 0x6d, 0x6d, 0x6c, 0x6c])
    b += bytes([0x67])                                   # OpElse
    b += bytes([0x53, 0x79, 0x52, 0x79, 0x94])           #   continue: Op3 OpPick(budget) Op2 OpPick(spent) OpSub
    b += bytes([0x53, 0x79])                             #   Op3 OpPick(anchor) -> na
    b += bytes([0x6b, 0x6b, 0x6d, 0x6d, 0x6c, 0x6c])
    b += bytes([0x68])                                   # OpEndIf -> [nb, na]
    b += bytes([0x51, 0x79, 0x00, 0xa2, 0x69])           # require nb >= 0
    b += bytes([0x58, 0xcd, 0x01, 0x08, 0x7c, 0x7e])     # encode na -> anchorpush
    b += bytes([0x7c])
    b += bytes([0x58, 0xcd, 0x01, 0x08, 0x7c, 0x7e])     # encode nb -> budgetpush
    b += bytes([0x7c, 0x7e])                             # -> new_state
    b += bytes([0xb9, 0x76, 0xc9, 0x76])                 # OpTxInputIndex OpDup OpTxInputScriptSigLen OpDup
    b += SL + bytes([0x94])                              # push SCRIPT_LEN OpSub
    b += bytes([0x01, STATE_LEN, 0x93])                  # push 18 OpAdd
    b += bytes([0x7c, 0xbc, 0x7e])                       # OpSwap OpTxInputScriptSigSubstr OpCat
    b += bytes([0xaa])                                   # OpBlake2b
    b += bytes([0x02, 0x00, 0x00])                       # push 0x0000
    b += bytes([0x01, 0xaa, 0x7e, 0x01, 0x20, 0x7e])     # aa OpCat ; 20 OpCat
    b += bytes([0x7c, 0x7e])                             # OpSwap OpCat
    b += bytes([0x01, 0x87, 0x7e])                       # 87 OpCat -> expected spk
    b += bytes([0x52, 0xc3, 0x87, 0x69])                 # Op2 OpTxOutputSpk OpEqual OpVerify (bind out2)
    b += bytes([0x51])                                   # OpTrue
    b += bytes([0x67])                                   # OpElse
    # ===================== OWNER PATH =====================
    b += bytes([0x52, 0x7a])                             # Op2 OpRoll (sig -> top)
    b += bytes([0x20]) + ox + bytes([0xad])              # push owner xonly ; OpCheckSigVerify
    b += bytes([0x6d, 0x51])                             # Op2Drop OpTrue
    b += bytes([0x68])                                   # OpEndIf
    return bytes(b)

def make_tail(p):
    sl = STATE_LEN + len(build_tail(0, p))
    t = build_tail(sl, p)
    assert STATE_LEN + len(t) == sl, "fixed point did not close"
    return t, sl
def redeem_for(budget, anchor, p):
    tail, _ = make_tail(p)
    return (bytes([0x08]) + int(budget).to_bytes(8, "little")
            + bytes([0x08]) + int(anchor).to_bytes(8, "little") + tail)

def p2sh_for(redeem_bytes):
    sb = None
    for arg in (redeem_bytes.hex(), redeem_bytes):
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

def p2sh_sig_script(redeem_hex, sig, selector):
    full = to_hex(pay_to_script_hash_signature_script(redeem_hex, sig))
    rpush = push_data(to_bytes(redeem_hex)).hex()
    if not full.endswith(rpush): raise SystemExit("unexpected sig-script layout")
    return full[:-len(rpush)] + ("51" if selector else "00") + rpush

# ---- rpc --------------------------------------------------------------------
async def with_client():
    enc = getattr(kaspa.Encoding, "Borsh", None)
    c = RpcClient(url=RPC_URL, encoding=enc) if enc else RpcClient(url=RPC_URL)
    await asyncio.wait_for(aw(c.connect()), timeout=8)
    info = await aw(c.get_server_info())
    if "testnet" not in str(info.get("networkId")):
        raise SystemExit(f"connected to {info.get('networkId')}, not testnet")
    return c
async def current_daa(c): return int((await aw(c.get_block_dag_info()))["virtualDaaScore"])
async def utxos_for(c, addr):
    r = await aw(c.get_utxos_by_addresses({"addresses": [addr]}))
    return r.get("entries", r) if isinstance(r, dict) else r
def get_amount(u):
    if not isinstance(u, dict):
        a = getattr(u, "amount", None); return int(a) if a is not None else None
    if "amount" in u: return int(u["amount"])
    ue = u.get("utxoEntry") or u.get("entry") or {}
    return int(ue["amount"]) if isinstance(ue, dict) and "amount" in ue else None
def addr_for(cfg): return p2sh_for(redeem_for(cfg["budget_sompi"], cfg["anchor"], cfg))[0]

# ---- commands ---------------------------------------------------------------
def cmd_build(args):
    agent = Keypair.random(); owner = Keypair.random()
    wl = [a.strip() for a in args.whitelist.split(",") if a.strip()]
    cfg = {"network": NETWORK,
           "full_sompi": tkas_to_sompi(args.full_tkas), "period_daa": int(args.period_daa),
           "budget_sompi": tkas_to_sompi(args.full_tkas), "anchor": int(args.anchor),
           "cap_sompi": tkas_to_sompi(args.cap_tkas),
           "whitelist": [spk_full(a).hex() for a in wl], "whitelist_addrs": wl,
           "dev_spk": spk_full(args.dev_addr).hex(), "dev_addr": args.dev_addr,
           "dev_fee_sompi": tkas_to_sompi(args.dev_fee_tkas),
           "agent_priv": agent.private_key, "owner_priv": owner.private_key,
           "agent_x": agent.xonly_public_key, "owner_x": owner.xonly_public_key}
    redeem = redeem_for(cfg["budget_sompi"], cfg["anchor"], cfg)
    addr, spk, local = p2sh_for(redeem); _, sl = make_tail(cfg)
    cfg["address"] = addr
    print("redeem length :", len(redeem), "(SCRIPT_LEN =", sl, ")")
    print("p2sh check    :", "MATCH" if local in spk else "!! MISMATCH")
    print(f"FULL/period   : {cfg['full_sompi']/SOMPI} TKAS per {cfg['period_daa']} DAA")
    print(f"cap/spend     : {cfg['cap_sompi']/SOMPI} TKAS ; dev fee {cfg['dev_fee_sompi']/SOMPI} TKAS -> {args.dev_addr}")
    print(f"whitelist     : {wl}")
    print("agent xonly   :", cfg["agent_x"]); print("owner xonly   :", cfg["owner_x"])
    print("ADDRESS       :", addr)
    json.dump(cfg, open(CFG_PATH, "w"), indent=2)
    print("\nSaved. Fund the address, then: info / spend <payee> <amt> / sweep <dest>")

async def cmd_info(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    addr = addr_for(cfg); entries = await utxos_for(c, addr); D = await current_daa(c)
    bal = sum(get_amount(u) or 0 for u in entries); nxt = cfg["anchor"] + cfg["period_daa"]
    print(f"budget {cfg['budget_sompi']/SOMPI} / FULL {cfg['full_sompi']/SOMPI} TKAS ; period {cfg['period_daa']} DAA")
    print(f"cap {cfg['cap_sompi']/SOMPI} ; dev fee {cfg['dev_fee_sompi']/SOMPI} -> {cfg['dev_addr']}")
    print(f"whitelist {cfg['whitelist_addrs']}")
    print(f"anchor {cfg['anchor']} ; next reset at {nxt} ; now {D} ->",
          "RESET available" if D >= nxt else f"{nxt-D} DAA to reset")
    print("address:", addr, "| balance:", bal/SOMPI, "TKAS across", len(entries), "UTXO(s)")
    await aw(c.disconnect())

async def cmd_spend(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    budget = cfg["budget_sompi"]; anchor = cfg["anchor"]
    full = cfg["full_sompi"]; period = cfg["period_daa"]
    cap = cfg["cap_sompi"]; dev_fee = cfg["dev_fee_sompi"]
    cur = addr_for(cfg); entries = await utxos_for(c, cur)
    if not entries: raise SystemExit(f"no UTXO at {cur}")
    u = entries[0]; in_amt = get_amount(u); D = await current_daa(c)
    L = D - LOCKTIME_MARGIN
    reset = L >= anchor + period; avail = full if reset else budget
    amount = tkas_to_sompi(args.amount_tkas)
    # local guards mirroring the covenant
    if args.payee not in cfg["whitelist_addrs"]: raise SystemExit("payee not in whitelist (covenant would reject)")
    if amount > cap: raise SystemExit(f"amount {amount/SOMPI} exceeds cap {cap/SOMPI} (covenant would reject)")
    if amount < MIN_OUT_SOMPI: raise SystemExit("amount below floor")
    if amount > avail: raise SystemExit(f"amount {amount/SOMPI} exceeds available {avail/SOMPI} TKAS")
    change = in_amt - amount - dev_fee - FEE_SOMPI
    if change < MIN_OUT_SOMPI: raise SystemExit(f"change {change/SOMPI} below floor (fund more)")
    new_budget = (full if reset else budget) - amount; new_anchor = L if reset else anchor
    child = p2sh_for(redeem_for(new_budget, new_anchor, cfg))[0]
    print(f"AGENT spend {amount/SOMPI} -> {args.payee} | dev {dev_fee/SOMPI} | lock_time={L} reset={reset}")
    print(f"  budget {budget/SOMPI} -> {new_budget/SOMPI} | anchor {anchor} -> {new_anchor} | child gets {change/SOMPI}")
    entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)
    redeem = redeem_for(budget, anchor, cfg)
    outs = [PaymentOutput(args.payee, amount), PaymentOutput(cfg["dev_addr"], dev_fee), PaymentOutput(child, change)]
    tx = create_transaction([entry], outs, 0)
    try: tx.lock_time = L
    except Exception as e: print("(lock_time set failed:", repr(e), ")")
    try: tx.inputs[0].sequence = 1
    except Exception as e: print("(sequence set failed:", repr(e), ")")
    sig = create_input_signature(tx, 0, PrivateKey(cfg["agent_priv"]), SighashType.All)
    tx.inputs[0].signature_script = p2sh_sig_script(redeem.hex(), sig, True)
    try:
        r = await aw(c.submit_transaction({"transaction": tx, "allowOrphan": False}))
        txid = r.get("transactionId") if isinstance(r, dict) else r
        print("*** SUBMITTED ***:", txid, "- waiting for confirmation (up to ~2.5 min, node may lag)...")
        confirmed = False
        for _ in range(50):
            await asyncio.sleep(3)
            if await utxos_for(c, child): confirmed = True; break
        if confirmed:
            cfg["budget_sompi"] = new_budget; cfg["anchor"] = new_anchor; cfg["address"] = child
            json.dump(cfg, open(CFG_PATH, "w"), indent=2)
            print(f"-> CONFIRMED. budget {new_budget/SOMPI}, anchor {new_anchor}; funds at {child}")
        else:
            print("!! not seen at child within ~2.5 min. State NOT advanced (config unchanged).")
            print(f"   The node may just be lagging. Check the explorer for tx {txid} and the")
            print(f"   child address {child} ; if it confirmed, re-run with the node caught up.")
    except Exception as e:
        print("error:", repr(e)[:220])
    await aw(c.disconnect())

async def cmd_sweep(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    cur = addr_for(cfg); entries = await utxos_for(c, cur)
    if not entries: raise SystemExit(f"no UTXO at {cur}")
    u = entries[0]; in_amt = get_amount(u)
    entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)
    redeem = redeem_for(cfg["budget_sompi"], cfg["anchor"], cfg)
    tx = create_transaction([entry], [PaymentOutput(args.dest, in_amt - FEE_SOMPI)], 0)
    sig = create_input_signature(tx, 0, PrivateKey(cfg["owner_priv"]), SighashType.All)
    tx.inputs[0].signature_script = p2sh_sig_script(redeem.hex(), sig, False)
    print(f"OWNER sweep {(in_amt-FEE_SOMPI)/SOMPI} TKAS -> {args.dest}")
    try:
        print("*** SUBMITTED ***:", await aw(c.submit_transaction({"transaction": tx, "allowOrphan": False})))
    except Exception as e:
        print("error:", repr(e)[:220])
    await aw(c.disconnect())

def main():
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--full-tkas", type=float, default=20.0)
    b.add_argument("--period-daa", type=int, default=600)
    b.add_argument("--anchor", type=int, default=0)
    b.add_argument("--cap-tkas", type=float, default=10.0)
    b.add_argument("--whitelist", required=True, help="comma-separated payee addresses")
    b.add_argument("--dev-addr", required=True)
    b.add_argument("--dev-fee-tkas", type=float, default=0.1)
    b.set_defaults(fn=cmd_build)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    s = sub.add_parser("spend"); s.add_argument("payee"); s.add_argument("amount_tkas"); s.set_defaults(fn=cmd_spend)
    w = sub.add_parser("sweep"); w.add_argument("dest"); w.set_defaults(fn=cmd_sweep)
    args = p.parse_args()
    if args.cmd == "build": args.fn(args)
    else: asyncio.run(args.fn(args))

if __name__ == "__main__":
    main()
