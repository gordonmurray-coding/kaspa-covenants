#!/usr/bin/env python3
"""
HTLC atomic-swap primitive on Kaspa (testnet-10).

A Hash Time-Locked Contract: funds locked to a two-path script.
  CLAIM  (taker): reveal a secret `s` with blake2b(s) == H, plus the taker's signature.
                  Available immediately. Revealing `s` on-chain is what lets a
                  counterparty unlock the mirror leg of a swap on another chain.
  REFUND (maker): the maker's signature, but only once the timeout DAA has passed.
                  The safety valve if the swap never completes.

This is the KAS leg of a cross-chain atomic swap and the foundation of non-custodial
orders. Two parties lock mirror HTLCs (same H, taker's timeout shorter); whoever claims
first reveals `s`, which the other then uses to claim their leg. Neither can cheat:
claim requires the secret, refund requires the wait.

Reuses the proven covenant machinery (two-path selector, CSV non-finality guard,
OpTxLockTime clock, OpCheckSig, P2SH). The only new primitive is the hashlock
(OpBlake2b + OpEqualVerify) -- and blake2b is the same hash behind every P2SH address.

Hash note: blake2b is Kaspa-native and proven here. For a BTC-compatible cross-chain
swap you'd switch the hashlock opcode to OpSHA256 so both legs share SHA-256.

Commands:
  lock  --amount-tkas N [--timeout-daa 600] [--secret HEX]   build + show the HTLC
  info
  claim  <payout_address>     spend via the claim path (reveals the secret)
  refund <payout_address>     spend via the refund path (after timeout)
"""
import asyncio, json, argparse, inspect, hashlib, os
import kaspa
from kaspa import (RpcClient, ScriptBuilder, PaymentOutput, Keypair, PrivateKey,
                   SighashType, address_from_script_public_key, create_transaction,
                   create_input_signature, pay_to_script_hash_signature_script)

CFG_PATH = "htlc_swap_config.json"
NETWORK  = "testnet"
RPC_URL  = "ws://159.195.64.93:8080/kaspa/testnet-10/wrpc/borsh"
FEE_SOMPI = 1_000_000
MIN_OUT_SOMPI = 5_000_000
SOMPI = 100_000_000
LOCKTIME_MARGIN = 200

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

def hashlock(secret):  # blake2b-256, the same hash OpBlake2b computes
    return hashlib.blake2b(secret, digest_size=32).digest()

# ---- the HTLC script --------------------------------------------------------
def htlc_redeem(H, timeout, maker_x, taker_x):
    b = bytearray()
    b += bytes([0x63])                       # OpIf   (selector 1=claim, 0=refund)
    # --- CLAIM: blake2b(preimage)==H ; taker sig ---
    b += bytes([0xaa])                       # OpBlake2b  (hash the preimage on the stack)
    b += push_data(H)                        # push H (32 bytes)
    b += bytes([0x88])                       # OpEqualVerify
    b += push_data(taker_x)                  # push taker x-only pubkey
    b += bytes([0xac])                       # OpCheckSig
    b += bytes([0x67])                       # OpElse
    # --- REFUND: lock_time >= timeout ; maker sig ---
    b += bytes([0x51, 0xb1])                 # Op1 OpCheckSequenceVerify (force non-final -> lock_time enforced)
    b += bytes([0xb5])                       # OpTxLockTime
    b += push_num(timeout)                   # push timeout (DAA)
    b += bytes([0xa2, 0x69])                 # OpGreaterThanOrEqual OpVerify  (lock_time >= timeout)
    b += push_data(maker_x)                  # push maker x-only pubkey
    b += bytes([0xac])                       # OpCheckSig
    b += bytes([0x68])                       # OpEndIf
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

def claim_sig_script(redeem_hex, sig, preimage):
    sig_push, rpush = _sig_push(redeem_hex, sig)          # stack: [sig, preimage, selector]
    return sig_push + push_data(preimage).hex() + "51" + rpush
def refund_sig_script(redeem_hex, sig):
    sig_push, rpush = _sig_push(redeem_hex, sig)          # stack: [sig, selector]
    return sig_push + "00" + rpush

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

def cfg_redeem(cfg):
    return htlc_redeem(bytes.fromhex(cfg["hash"]), cfg["timeout"],
                       bytes.fromhex(cfg["maker_x"]), bytes.fromhex(cfg["taker_x"]))

async def _submit_and_wait(c, tx, label):
    try:
        r = await aw(c.submit_transaction({"transaction": tx, "allowOrphan": False}))
        txid = r.get("transactionId") if isinstance(r, dict) else r
        print(f"*** {label} SUBMITTED ***: {txid} - waiting...")
        for _ in range(40):
            await asyncio.sleep(3)
            try:
                if not await utxos_for(c, cfg_addr_cache[0]): print(f"-> {label} CONFIRMED (HTLC spent)"); return
            except Exception: pass
        print(f"-> {label} submitted; confirmation not observed in ~2 min (node may lag). Check explorer for {txid}.")
    except Exception as e:
        print(f"{label} error:", repr(e)[:200])

cfg_addr_cache = [None]

# ---- commands ---------------------------------------------------------------
async def cmd_lock(args):
    c = await with_client(); D = await current_daa(c)
    maker = Keypair.random(); taker = Keypair.random()
    secret = bytes.fromhex(args.secret) if args.secret else os.urandom(32)
    H = hashlock(secret); timeout = D + int(args.timeout_daa)
    redeem = htlc_redeem(H, timeout, bytes.fromhex(maker.xonly_public_key), bytes.fromhex(taker.xonly_public_key))
    addr, spk, local = p2sh_for(redeem)
    print("redeem length :", len(redeem))
    print("p2sh check    :", "MATCH" if local in spk else "!! MISMATCH")
    print("amount        :", args.amount_tkas, "TKAS")
    print("hash H        :", H.hex())
    print("secret s      :", secret.hex(), "  (taker reveals this to claim)")
    print(f"timeout       : DAA {timeout}  (now {D}; refund opens in ~{int(args.timeout_daa)} DAA)")
    print("ADDRESS       :", addr)
    json.dump({"network": NETWORK, "amount_sompi": tkas_to_sompi(args.amount_tkas),
               "hash": H.hex(), "secret": secret.hex(), "timeout": timeout,
               "maker_priv": maker.private_key, "taker_priv": taker.private_key,
               "maker_x": maker.xonly_public_key, "taker_x": taker.xonly_public_key,
               "address": addr}, open(CFG_PATH, "w"), indent=2)
    print("\nSaved. Fund the address, then: info / claim <addr> / refund <addr>")
    await aw(c.disconnect())

async def cmd_info(args):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    addr, _, _ = p2sh_for(cfg_redeem(cfg)); entries = await utxos_for(c, addr); D = await current_daa(c)
    bal = sum(get_amount(u) or 0 for u in entries)
    print("HTLC address :", addr)
    print("balance      :", bal/SOMPI, "TKAS across", len(entries), "UTXO(s)")
    print("hash H       :", cfg["hash"])
    print(f"timeout      : DAA {cfg['timeout']} ; now {D} ->",
          "REFUND open" if D >= cfg["timeout"] else f"claim window ({cfg['timeout']-D} DAA to refund)")
    await aw(c.disconnect())

async def _spend(args, path):
    cfg = json.load(open(CFG_PATH)); c = await with_client()
    redeem = cfg_redeem(cfg); addr, _, _ = p2sh_for(redeem); cfg_addr_cache[0] = addr
    entries = await utxos_for(c, addr)
    if not entries: raise SystemExit(f"no HTLC UTXO at {addr}")
    u = entries[0]; in_amt = get_amount(u)
    entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)
    out = PaymentOutput(args.payout, in_amt - FEE_SOMPI)
    tx = create_transaction([entry], [out], 0)
    if path == "claim":
        sig = create_input_signature(tx, 0, PrivateKey(cfg["taker_priv"]), SighashType.All)
        tx.inputs[0].signature_script = claim_sig_script(redeem.hex(), sig, bytes.fromhex(cfg["secret"]))
        print(f"CLAIM {(in_amt-FEE_SOMPI)/SOMPI} TKAS -> {args.payout} (revealing secret {cfg['secret'][:16]}...)")
        await _submit_and_wait(c, tx, "CLAIM")
    else:
        D = await current_daa(c); L = D - LOCKTIME_MARGIN
        if L < cfg["timeout"]:
            raise SystemExit(f"refund not open yet: need DAA >= {cfg['timeout']}, lock_time would be {L}")
        try: tx.lock_time = L
        except Exception as e: print("(lock_time set failed:", repr(e), ")")
        try: tx.inputs[0].sequence = 1
        except Exception as e: print("(sequence set failed:", repr(e), ")")
        sig = create_input_signature(tx, 0, PrivateKey(cfg["maker_priv"]), SighashType.All)
        tx.inputs[0].signature_script = refund_sig_script(redeem.hex(), sig)
        print(f"REFUND {(in_amt-FEE_SOMPI)/SOMPI} TKAS -> {args.payout} (lock_time {L} >= timeout {cfg['timeout']})")
        await _submit_and_wait(c, tx, "REFUND")
    await aw(c.disconnect())

def main():
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    l = sub.add_parser("lock"); l.add_argument("--amount-tkas", type=float, default=5.0)
    l.add_argument("--timeout-daa", type=int, default=600); l.add_argument("--secret", default=None)
    l.set_defaults(fn=cmd_lock)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    cl = sub.add_parser("claim"); cl.add_argument("payout"); cl.set_defaults(fn=lambda a: _spend(a, "claim"))
    rf = sub.add_parser("refund"); rf.add_argument("payout"); rf.set_defaults(fn=lambda a: _spend(a, "refund"))
    args = p.parse_args()
    asyncio.run(args.fn(args))

if __name__ == "__main__":
    main()
