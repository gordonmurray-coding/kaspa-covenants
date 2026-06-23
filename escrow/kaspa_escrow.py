#!/usr/bin/env python3
"""
Arbitrated escrow covenant on Kaspa (testnet-10).

Three roles -- buyer, seller, arbiter -- and two spend paths:

  SETTLE   buyer AND seller co-sign. Mutual consent, so the output is unconstrained
           (release to seller, partial refund split, whatever they agree). A two-signature
           path: N-of-M without OpCheckMultiSig.

  RESOLVE  the arbiter signs ALONE, but introspection forces the payout to be either the
           buyer's or the seller's registered address, at (near) full value. The arbiter
           adjudicates a dispute but CANNOT send funds anywhere else -- not to themselves,
           not to a confederate. A compromised arbiter key's worst case is "paid the wrong
           legitimate party," never theft. This is the property plain 2-of-3 multisig
           cannot give you.

Pure composition of primitives already proven on-chain in this repo: the selector branch
(agent covenant), the output-SPK whitelist + amount conservation (budget covenant), and
OpCheckSig. The only mechanic new to consensus here is the two-signature settle path.

Commands:
  open    --amount-tkas N [--buyer-payout ADDR] [--seller-payout ADDR]
  info
  release [payout_address]     # SETTLE: buyer + seller co-sign (default payout = seller)
  resolve  <payout_address>    # RESOLVE: arbiter signs; payout MUST be buyer or seller
"""
import asyncio, json, argparse, inspect, hashlib
import kaspa
from kaspa import (RpcClient, ScriptBuilder, PaymentOutput, Keypair, PrivateKey,
                   SighashType, address_from_script_public_key, pay_to_address_script,
                   create_transaction, create_input_signature,
                   pay_to_script_hash_signature_script)

CFG_PATH = "escrow_config.json"
NETWORK  = "testnet"
RPC_URL  = "ws://159.195.64.93:8080/kaspa/testnet-10/wrpc/borsh"
FEE_SOMPI       = 1_000_000
FEE_ALLOWANCE   = 2_000_000      # arbiter payout may fall short of input by at most this (covers fee)
SOMPI = 100_000_000

# ---- helpers ----------------------------------------------------------------
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
    """Full consensus SPK = 2-byte version (LE) || script -- what OpTxOutputSpk pushes."""
    spk = pay_to_address_script(addr)
    ver = int(spk.version)
    return ver.to_bytes(2, "little") + to_bytes(spk.script)

def kp_address(kp):
    for net in (NETWORK, "testnet-10"):
        try: return kp.to_address(net).to_string()
        except Exception: pass
    raise SystemExit("could not derive address from keypair; pass --buyer-payout / --seller-payout")

def set_sig_ops(tx, n):
    """Commit the input's signature-op budget. Each OpCheckSig(Verify) in the spending
    path costs one; the script engine rejects execution exceeding the committed count.
    Must be set before signing -- the field is part of the sighash."""
    for attr in ("sig_op_count", "sigOpCount", "sig_ops", "sigOps"):
        try:
            setattr(tx.inputs[0], attr, n)
            if getattr(tx.inputs[0], attr) == n: return attr
        except Exception: pass
    return None

# ---- the escrow script ------------------------------------------------------
def escrow_redeem(buyer_x, seller_x, arbiter_x, buyer_spk, seller_spk, allowance):
    b = bytearray()
    b += bytes([0x63])                                   # OpIf  (selector 1=settle, 0=resolve)
    # --- SETTLE: buyer AND seller ---
    b += push_data(buyer_x)  + bytes([0xad])             # OpCheckSigVerify (buyer)
    b += push_data(seller_x) + bytes([0xac])             # OpCheckSig       (seller)
    b += bytes([0x67])                                   # OpElse
    # --- RESOLVE: arbiter, bounded ---
    b += push_data(arbiter_x) + bytes([0xad])            # OpCheckSigVerify (arbiter)
    # exactly one output: stops the arbiter adding a second output that pays themselves the
    # allowance slack. With one output + the value floor below, the arbiter captures nothing.
    b += bytes([0xb4, 0x51, 0x9d])                       # OpTxOutputCount Op1 OpNumEqualVerify
    # payout SPK must be buyer's or seller's. Combine the two equality results with OpAdd
    # (arithmetic, length-agnostic) not bitwise OpOr: OpEqual pushes 0x01 / empty, whose
    # lengths differ, and bitwise ops require equal-length operands. Sum >= 1 == a match.
    b += bytes([0x00, 0xc3]) + push_data(buyer_spk)  + bytes([0x87])   # Op0 OpTxOutputSpk ==buyer
    b += bytes([0x00, 0xc3]) + push_data(seller_spk) + bytes([0x87])   #          ==seller
    b += bytes([0x93, 0x69])                             # OpAdd OpVerify  (>=1 match -> nonzero)
    # payout amount must be >= input - allowance  (no skimming)
    b += bytes([0x00, 0xc2])                             # Op0 OpTxOutputAmount
    b += push_num(allowance) + bytes([0x93])             # + allowance   (OpAdd)
    b += bytes([0x00, 0xbe])                             # Op0 OpTxInputAmount
    b += bytes([0xa2, 0x69])                             # OpGreaterThanOrEqual OpVerify
    b += bytes([0x51])                                   # OpTrue
    b += bytes([0x68])                                   # OpEndIf
    return bytes(b)

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

def _sig_push(redeem_hex, sig):
    """Reuse the SDK's signature encoding (correct sighash byte), minus its redeem push."""
    full = to_hex(pay_to_script_hash_signature_script(redeem_hex, sig))
    rpush = push_data(to_bytes(redeem_hex)).hex()
    if not full.endswith(rpush): raise SystemExit("unexpected sig-script layout")
    return full[:-len(rpush)], rpush

def settle_sig_script(redeem_hex, seller_sig, buyer_sig):
    sp_s, rpush = _sig_push(redeem_hex, seller_sig)      # stack: [seller_sig, buyer_sig, 1]
    sp_b, _     = _sig_push(redeem_hex, buyer_sig)
    return sp_s + sp_b + "51" + rpush
def resolve_sig_script(redeem_hex, arbiter_sig):
    sp_a, rpush = _sig_push(redeem_hex, arbiter_sig)     # stack: [arbiter_sig, 0]
    return sp_a + "00" + rpush

# ---- rpc --------------------------------------------------------------------
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
def get_amount(u):
    if not isinstance(u, dict):
        a = getattr(u, "amount", None); return int(a) if a is not None else None
    if "amount" in u: return int(u["amount"])
    ue = u.get("utxoEntry") or u.get("entry") or {}
    return int(ue["amount"]) if isinstance(ue, dict) and "amount" in ue else None

def cfg_redeem(cfg):
    return escrow_redeem(bytes.fromhex(cfg["buyer_x"]), bytes.fromhex(cfg["seller_x"]),
                         bytes.fromhex(cfg["arbiter_x"]), spk_full(cfg["buyer_payout"]),
                         spk_full(cfg["seller_payout"]), cfg["allowance"])

addr_cache = [None]
async def _submit_and_wait(c, tx, label):
    try:
        r = await aw(c.submit_transaction({"transaction": tx, "allowOrphan": False}))
        txid = r.get("transactionId") if isinstance(r, dict) else r
        print(f"*** {label} SUBMITTED ***: {txid} - waiting...")
        for _ in range(40):
            await asyncio.sleep(3)
            try:
                if not await utxos_for(c, addr_cache[0]): print(f"-> {label} CONFIRMED (escrow spent)"); return
            except Exception: pass
        print(f"-> {label} submitted; confirmation not observed in ~2 min (node may lag). Check explorer for {txid}.")
    except Exception as e:
        print(f"{label} error:", repr(e)[:240])

# ---- commands ---------------------------------------------------------------
async def cmd_open(args):
    buyer = Keypair.random(); seller = Keypair.random(); arbiter = Keypair.random()
    buyer_payout  = args.buyer_payout  or kp_address(buyer)
    seller_payout = args.seller_payout or kp_address(seller)
    redeem = escrow_redeem(bytes.fromhex(buyer.xonly_public_key), bytes.fromhex(seller.xonly_public_key),
                           bytes.fromhex(arbiter.xonly_public_key),
                           spk_full(buyer_payout), spk_full(seller_payout), FEE_ALLOWANCE)
    addr, spk, local = p2sh_for(redeem)
    print("redeem length :", len(redeem))
    print("p2sh check    :", "MATCH" if local in spk else "!! MISMATCH")
    print("amount        :", args.amount_tkas, "TKAS")
    print("buyer payout  :", buyer_payout)
    print("seller payout :", seller_payout)
    print("ESCROW ADDRESS:", addr)
    json.dump({"network": NETWORK, "amount_sompi": tkas_to_sompi(args.amount_tkas),
               "allowance": FEE_ALLOWANCE,
               "buyer_priv": buyer.private_key, "seller_priv": seller.private_key,
               "arbiter_priv": arbiter.private_key,
               "buyer_x": buyer.xonly_public_key, "seller_x": seller.xonly_public_key,
               "arbiter_x": arbiter.xonly_public_key,
               "buyer_payout": buyer_payout, "seller_payout": seller_payout,
               "address": addr}, open(CFG_PATH, "w"), indent=2)
    print("\nSaved. Fund the escrow address, then: info / release [addr] / resolve <addr>")

async def cmd_info(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    addr, _, _ = p2sh_for(cfg_redeem(cfg)); entries = await utxos_for(c, addr)
    bal = sum(get_amount(u) or 0 for u in entries)
    print("escrow address:", addr)
    print("balance       :", bal/SOMPI, "TKAS across", len(entries), "UTXO(s)")
    print("buyer payout  :", cfg["buyer_payout"])
    print("seller payout :", cfg["seller_payout"])
    print("arbiter may only release to one of those two addresses.")
    await aw(c.disconnect())

async def _spend(args, path):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    redeem = cfg_redeem(cfg); addr, _, _ = p2sh_for(redeem); addr_cache[0] = addr
    entries = await utxos_for(c, addr)
    if not entries: raise SystemExit(f"no escrow UTXO at {addr}")
    u = entries[0]; in_amt = get_amount(u)
    entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)
    payout = args.payout or cfg["seller_payout"]
    out = PaymentOutput(payout, in_amt - FEE_SOMPI)
    tx = create_transaction([entry], [out], 0)
    if path == "settle":
        used = set_sig_ops(tx, 2)                       # two signature checks in this path
        print("sig_op_count  :", "committed=2 via " + used if used else "WARN: could not set (will likely fail)")
        seller_sig = create_input_signature(tx, 0, PrivateKey(cfg["seller_priv"]), SighashType.All)
        buyer_sig  = create_input_signature(tx, 0, PrivateKey(cfg["buyer_priv"]),  SighashType.All)
        tx.inputs[0].signature_script = settle_sig_script(redeem.hex(), seller_sig, buyer_sig)
        print(f"SETTLE (buyer+seller) {(in_amt-FEE_SOMPI)/SOMPI} TKAS -> {payout}")
        await _submit_and_wait(c, tx, "SETTLE")
    else:
        set_sig_ops(tx, 1)                              # single signature check
        arbiter_sig = create_input_signature(tx, 0, PrivateKey(cfg["arbiter_priv"]), SighashType.All)
        tx.inputs[0].signature_script = resolve_sig_script(redeem.hex(), arbiter_sig)
        wl = payout in (cfg["buyer_payout"], cfg["seller_payout"])
        print(f"RESOLVE (arbiter) {(in_amt-FEE_SOMPI)/SOMPI} TKAS -> {payout}")
        if not wl:
            print("   note: this payout is NOT buyer or seller -- the covenant should REJECT it.")
        await _submit_and_wait(c, tx, "RESOLVE")
    await aw(c.disconnect())

def main():
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("open"); o.add_argument("--amount-tkas", type=float, default=5.0)
    o.add_argument("--buyer-payout", default=None); o.add_argument("--seller-payout", default=None)
    o.set_defaults(fn=cmd_open)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    r = sub.add_parser("release"); r.add_argument("payout", nargs="?", default=None)
    r.set_defaults(fn=lambda a: _spend(a, "settle"))
    rs = sub.add_parser("resolve"); rs.add_argument("payout"); rs.set_defaults(fn=lambda a: _spend(a, "resolve"))
    args = p.parse_args()
    asyncio.run(args.fn(args))

if __name__ == "__main__":
    main()
