#!/usr/bin/env python3
"""
Step 3a -- AGENT-AUTH rolling budget + OWNER escape-hatch.

Takes the proven 2b-2 rolling budget and wraps it in a two-path branch:
  AGENT path  (selector truthy): agent key must sign; then the full rolling-budget
              transition runs (CSV non-finality guard, lock_time reset, two-field
              conditional update, templating bind of output[1] = child covenant).
  OWNER path  (selector falsy):  owner key must sign; sweep anywhere, no rules.

Structural note: state lives at the FRONT of the redeem (offset 0) so the templating
tail-read can find it. That means when the redeem starts executing, the sig-script
items [sig, selector] are already on the stack and the state pushes land ON TOP of
them. So the script reorders with OpRoll before it can branch:

  redeem = [08 budget][08 anchor] TAIL
  sig script leaves [sig, selector]; state pushes -> [sig, selector, budget, anchor]
  TAIL:
    Op2 OpRoll                 # selector -> top -> [sig, budget, anchor, selector]
    OpIf                       # AGENT
      Op2 OpRoll               # sig -> top -> [budget, anchor, sig]
      <agent xonly> OpCheckSigVerify          -> [budget, anchor]
      ... verbatim 2b-2 rolling budget, bind output[1] ...
      OpTrue
    OpElse                     # OWNER
      Op2 OpRoll               # sig -> top -> [budget, anchor, sig]
      <owner xonly> OpCheckSigVerify          -> [budget, anchor]
      Op2Drop OpTrue
    OpEndIf

Outputs (agent): output[0] = payee (draws down budget), output[1] = child covenant.
3b will add the per-spend cap, destination whitelist, and exact dev fee (3rd output).

Commands:
  build [--full-tkas --period-daa --anchor]
  info
  spend <payee> <amount_tkas>      # agent path
  sweep <dest>                     # owner path (recover everything)
"""
import asyncio, json, argparse, inspect, hashlib
import kaspa
from kaspa import (RpcClient, ScriptBuilder, PaymentOutput, Keypair, PrivateKey,
                   SighashType, address_from_script_public_key, create_transaction,
                   create_input_signature, pay_to_script_hash_signature_script)

CFG_PATH = "agent_covenant_3a_config.json"
NETWORK  = "testnet"
RPC_URL  = "ws://159.195.64.93:8080/kaspa/testnet-10/wrpc/borsh"
FEE_SOMPI = 1_000_000
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

def push_redeem_bytes(rb):
    n = len(rb)
    if n < 0x4c:    return bytes([n]) + rb
    elif n <= 0xff: return bytes([0x4c, n]) + rb
    else:           return bytes([0x4d]) + n.to_bytes(2, "little") + rb

# ---- the script -------------------------------------------------------------
def build_tail(script_len, full, period, agent_x, owner_x):
    SL = bytes([0x02]) + int(script_len).to_bytes(2, "little")   # fixed 3-byte push of redeem length
    ax = to_bytes(agent_x); ox = to_bytes(owner_x)
    b = bytearray()
    b += bytes([0x52, 0x7a])                              # Op2 OpRoll  (selector -> top)
    b += bytes([0x63])                                    # OpIf  (AGENT if truthy)
    # ===== AGENT =====
    b += bytes([0x52, 0x7a])                              # Op2 OpRoll  (sig -> top)
    b += bytes([0x20]) + ax + bytes([0xad])               # push agent xonly ; OpCheckSigVerify
    b += bytes([0x51, 0xb1])                              # Op1 OpCheckSequenceVerify (force non-final)
    b += bytes([0x00, 0xc2])                              # Op0 OpTxOutputAmount -> spent
    b += bytes([0xb5])                                    # OpTxLockTime -> L
    b += bytes([0x00, 0x79])                              # Op0 OpPick (copy L)
    b += bytes([0x53, 0x79])                              # Op3 OpPick (copy anchor)
    b += push_num(period) + bytes([0x93, 0xa2])           # PERIOD OpAdd OpGreaterThanOrEqual -> reset
    b += bytes([0x63])                                    # OpIf
    b += push_num(full) + bytes([0x52, 0x79, 0x94])       # FULL Op2 OpPick(spent) OpSub -> nb
    b += bytes([0x51, 0x79])                              # Op1 OpPick (copy L) -> na
    b += bytes([0x6b, 0x6b, 0x6d, 0x6d, 0x6c, 0x6c])      # park na,nb; 2drop 2drop; restore nb,na
    b += bytes([0x67])                                    # OpElse
    b += bytes([0x53, 0x79, 0x52, 0x79, 0x94])            # Op3 OpPick(budget) Op2 OpPick(spent) OpSub -> nb
    b += bytes([0x53, 0x79])                              # Op3 OpPick (copy anchor) -> na
    b += bytes([0x6b, 0x6b, 0x6d, 0x6d, 0x6c, 0x6c])
    b += bytes([0x68])                                    # OpEndIf -> [nb, na]
    b += bytes([0x51, 0x79, 0x00, 0xa2, 0x69])            # require nb >= 0
    b += bytes([0x58, 0xcd, 0x01, 0x08, 0x7c, 0x7e])      # encode na -> anchorpush
    b += bytes([0x7c])                                    # OpSwap
    b += bytes([0x58, 0xcd, 0x01, 0x08, 0x7c, 0x7e])      # encode nb -> budgetpush
    b += bytes([0x7c, 0x7e])                              # OpSwap OpCat -> new_state
    b += bytes([0xb9, 0x76, 0xc9, 0x76])                  # OpTxInputIndex OpDup OpTxInputScriptSigLen OpDup
    b += SL + bytes([0x94])                               # push SCRIPT_LEN OpSub
    b += bytes([0x01, STATE_LEN, 0x93])                   # push 18 OpAdd
    b += bytes([0x7c, 0xbc, 0x7e])                        # OpSwap OpTxInputScriptSigSubstr OpCat
    b += bytes([0xaa])                                    # OpBlake2b
    b += bytes([0x02, 0x00, 0x00])                        # push 0x0000
    b += bytes([0x01, 0xaa, 0x7e, 0x01, 0x20, 0x7e])      # aa OpCat ; 20 OpCat
    b += bytes([0x7c, 0x7e])                              # OpSwap OpCat -> 0000aa20||hash
    b += bytes([0x01, 0x87, 0x7e])                        # 87 OpCat -> expected spk
    b += bytes([0x51, 0xc3, 0x87, 0x69])                  # Op1 OpTxOutputSpk OpEqual OpVerify (bind out1)
    b += bytes([0x51])                                    # OpTrue
    b += bytes([0x67])                                    # OpElse
    # ===== OWNER =====
    b += bytes([0x52, 0x7a])                              # Op2 OpRoll (sig -> top)
    b += bytes([0x20]) + ox + bytes([0xad])               # push owner xonly ; OpCheckSigVerify
    b += bytes([0x6d, 0x51])                              # Op2Drop OpTrue
    b += bytes([0x68])                                    # OpEndIf
    return bytes(b)

def make_tail(full, period, agent_x, owner_x):
    sl = STATE_LEN + len(build_tail(0, full, period, agent_x, owner_x))   # SL push is fixed-width -> closes in one step
    t = build_tail(sl, full, period, agent_x, owner_x)
    assert STATE_LEN + len(t) == sl, "fixed point did not close"
    return t, sl

def redeem_for(budget, anchor, full, period, agent_x, owner_x):
    tail, _ = make_tail(full, period, agent_x, owner_x)
    return (bytes([0x08]) + int(budget).to_bytes(8, "little")
            + bytes([0x08]) + int(anchor).to_bytes(8, "little") + tail)

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

def p2sh_sig_script(redeem_hex, sig, agent_path):
    """[push sig+sighash][selector][push redeem]; selector 0x51 = agent, 0x00 = owner."""
    full = to_hex(pay_to_script_hash_signature_script(redeem_hex, sig))
    rpush = push_redeem_bytes(to_bytes(redeem_hex)).hex()
    if not full.endswith(rpush): raise SystemExit("unexpected sig-script layout")
    return full[:-len(rpush)] + ("51" if agent_path else "00") + rpush

# ---- rpc --------------------------------------------------------------------
async def with_client():
    enc = getattr(kaspa.Encoding, "Borsh", None)
    c = RpcClient(url=RPC_URL, encoding=enc) if enc else RpcClient(url=RPC_URL)
    await asyncio.wait_for(aw(c.connect()), timeout=8)
    info = await aw(c.get_server_info())
    if "testnet" not in str(info.get("networkId")): raise SystemExit(f"connected to {info.get('networkId')}")
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

def cfg_redeem(cfg, budget, anchor):
    return redeem_for(budget, anchor, cfg["full_sompi"], cfg["period_daa"], cfg["agent_x"], cfg["owner_x"])

# ---- commands ---------------------------------------------------------------
def cmd_build(args):
    agent = Keypair.random(); owner = Keypair.random()
    agent_x = agent.xonly_public_key; owner_x = owner.xonly_public_key
    full = tkas_to_sompi(args.full_tkas); period = int(args.period_daa)
    budget = full; anchor = int(args.anchor)
    redeem = redeem_for(budget, anchor, full, period, agent_x, owner_x)
    addr, spk, local = p2sh_for(redeem)
    _, sl = make_tail(full, period, agent_x, owner_x)
    print("redeem length :", len(redeem), "(SCRIPT_LEN =", sl, ")")
    print("p2sh check    :", "MATCH" if local in spk else "!! MISMATCH")
    print(f"FULL/period   : {full/SOMPI} TKAS per {period} DAA ; budget={budget/SOMPI} anchor={anchor}")
    print("agent xonly   :", agent_x)
    print("owner xonly   :", owner_x)
    print("ADDRESS       :", addr)
    json.dump({"network": NETWORK, "full_sompi": full, "period_daa": period,
               "budget_sompi": budget, "anchor": anchor, "address": addr,
               "agent_x": agent_x, "owner_x": owner_x,
               "agent_priv": agent.private_key, "owner_priv": owner.private_key},
              open(CFG_PATH, "w"), indent=2)
    print("\nSaved. Fund the address, then: info / spend <payee> <amt> / sweep <dest>")

async def cmd_info(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    addr, _, _ = p2sh_for(cfg_redeem(cfg, cfg["budget_sompi"], cfg["anchor"]))
    entries = await utxos_for(c, addr); D = await current_daa(c)
    bal = sum(get_amount(u) or 0 for u in entries); nxt = cfg["anchor"] + cfg["period_daa"]
    print(f"budget {cfg['budget_sompi']/SOMPI} / FULL {cfg['full_sompi']/SOMPI} TKAS ; period {cfg['period_daa']} DAA")
    print(f"anchor {cfg['anchor']} ; next reset at DAA {nxt} ; now {D} ->",
          "RESET available" if D >= nxt else f"{nxt-D} DAA to reset")
    print("address:", addr, "| balance:", bal/SOMPI, "TKAS across", len(entries), "UTXO(s)")
    await aw(c.disconnect())

async def cmd_spend(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    full = cfg["full_sompi"]; period = cfg["period_daa"]
    budget = cfg["budget_sompi"]; anchor = cfg["anchor"]
    cur_addr, _, _ = p2sh_for(cfg_redeem(cfg, budget, anchor))
    entries = await utxos_for(c, cur_addr)
    if not entries: raise SystemExit(f"no UTXO at {cur_addr}")
    u = entries[0]; in_amt = get_amount(u); D = await current_daa(c)
    L = D - LOCKTIME_MARGIN
    reset = L >= anchor + period; avail = full if reset else budget
    amount = tkas_to_sompi(args.amount_tkas)
    if amount < MIN_OUT_SOMPI: raise SystemExit("amount below storage floor")
    if amount > avail: raise SystemExit(f"amount {amount/SOMPI} exceeds available {avail/SOMPI} TKAS")
    change = in_amt - amount - FEE_SOMPI
    if change < MIN_OUT_SOMPI: raise SystemExit(f"change {change/SOMPI} below floor (fund more)")
    new_budget = avail - amount; new_anchor = L if reset else anchor
    child_addr, _, _ = p2sh_for(cfg_redeem(cfg, new_budget, new_anchor))
    out0 = PaymentOutput(args.payee, amount); out1 = PaymentOutput(child_addr, change)
    print(f"AGENT spend {amount/SOMPI} -> {args.payee} | lock_time={L} reset={reset}")
    print(f"  budget {budget/SOMPI} -> {new_budget/SOMPI} | anchor {anchor} -> {new_anchor} | change {change/SOMPI} -> child")
    entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)
    redeem = cfg_redeem(cfg, budget, anchor)
    tx = create_transaction([entry], [out0, out1], 0)
    try: tx.lock_time = L
    except Exception as e: print("(lock_time:", repr(e), ")")
    try: tx.inputs[0].sequence = 1
    except Exception as e: print("(sequence:", repr(e), ")")
    sig = create_input_signature(tx, 0, PrivateKey(cfg["agent_priv"]), SighashType.All)
    tx.inputs[0].signature_script = p2sh_sig_script(redeem.hex(), sig, agent_path=True)
    try:
        print("*** SUBMITTED ***:", await aw(c.submit_transaction({"transaction": tx, "allowOrphan": False})))
        cfg["budget_sompi"] = new_budget; cfg["anchor"] = new_anchor; cfg["address"] = child_addr
        json.dump(cfg, open(CFG_PATH, "w"), indent=2)
        print(f"-> budget {new_budget/SOMPI} TKAS, anchor {new_anchor}; funds at {child_addr}")
    except Exception as e:
        print("error:", repr(e)[:200])
    await aw(c.disconnect())

async def cmd_sweep(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    budget = cfg["budget_sompi"]; anchor = cfg["anchor"]
    cur_addr, _, _ = p2sh_for(cfg_redeem(cfg, budget, anchor))
    entries = await utxos_for(c, cur_addr)
    if not entries: raise SystemExit(f"no UTXO at {cur_addr}")
    u = entries[0]; in_amt = get_amount(u)
    out0 = PaymentOutput(args.dest, in_amt - FEE_SOMPI)
    print(f"OWNER sweep {(in_amt-FEE_SOMPI)/SOMPI} TKAS -> {args.dest}")
    entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)
    redeem = cfg_redeem(cfg, budget, anchor)
    tx = create_transaction([entry], [out0], 0)
    sig = create_input_signature(tx, 0, PrivateKey(cfg["owner_priv"]), SighashType.All)
    tx.inputs[0].signature_script = p2sh_sig_script(redeem.hex(), sig, agent_path=False)
    try:
        print("*** SUBMITTED ***:", await aw(c.submit_transaction({"transaction": tx, "allowOrphan": False})))
        print("swept; covenant emptied")
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
    w = sub.add_parser("sweep"); w.add_argument("dest"); w.set_defaults(fn=cmd_sweep)
    args = p.parse_args()
    if args.cmd == "build": args.fn(args)
    else: asyncio.run(args.fn(args))

if __name__ == "__main__":
    main()
