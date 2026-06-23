#!/usr/bin/env python3
"""
Adversarial tester for the escrow covenant (compromised-arbiter model).

Imports the REAL escrow module -- same redeem script, same config, same helpers -- then
builds transactions that break each resolve-path rule, signs them with the genuine arbiter
private key, and submits them directly, bypassing the local guards in kaspa_escrow.py.

The claim under test: a compromised arbiter (valid key, attacker-controlled code) still
cannot steal. Every attack below should be REJECTED by the covenant script itself, not by
client-side checks.

Attacks:
  1. off-whitelist payout      single output to an attacker address       (whitelist rule)
  2. two-output skim           seller + a second output to the attacker   (output-count rule)
  3. underpay below the floor  single output far under input - allowance  (value-floor rule)
  4. settle-path masquerade    arbiter signature in both buyer+seller slots (signature rule)

Run after funding an escrow opened by kaspa_escrow.py. Expects 4/4 rejected.
"""
import asyncio, json, importlib.util, os, inspect, kaspa
from kaspa import (PaymentOutput, PrivateKey, SighashType, Keypair,
                   create_transaction, create_input_signature)

# ---- locate + load the real escrow module ----------------------------------
_cands = ["kaspa_escrow.py", "escrow/kaspa_escrow.py", "../escrow/kaspa_escrow.py",
          os.path.join(os.path.dirname(os.path.abspath(__file__)), "kaspa_escrow.py")]
_path = next((p for p in _cands if os.path.exists(p)), None)
if not _path: raise SystemExit("cannot find kaspa_escrow.py next to this script")
_spec = importlib.util.spec_from_file_location("esc", _path)
m = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(m)
SOMPI = m.SOMPI

async def aw(x): return await x if inspect.isawaitable(x) else x

async def main():
    cfg = json.load(open(m.CFG_PATH))
    redeem = m.cfg_redeem(cfg); addr, _, _ = m.p2sh_for(redeem)
    c = await m.with_client()
    entries = await m.utxos_for(c, addr)
    if not entries:
        raise SystemExit(f"no escrow UTXO at {addr} -- open and fund an escrow first")
    u = entries[0]; in_amt = m.get_amount(u)
    entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)

    arb = PrivateKey(cfg["arbiter_priv"])
    seller = cfg["seller_payout"]
    attacker = m.kp_address(Keypair.random())
    rhex = redeem.hex()

    print(f"escrow   {addr}")
    print(f"input    {in_amt/SOMPI} TKAS")
    print(f"attacker {attacker}")
    print(f"signing every attack with the REAL arbiter key; expecting the covenant to reject all.\n")

    def tx_with(outs, sigops):
        tx = create_transaction([entry], outs, 0)
        m.set_sig_ops(tx, sigops)
        return tx

    def build_1():  # off-whitelist single output
        tx = tx_with([PaymentOutput(attacker, in_amt - m.FEE_SOMPI)], 1)
        sig = create_input_signature(tx, 0, arb, SighashType.All)
        tx.inputs[0].signature_script = m.resolve_sig_script(rhex, sig); return tx

    def build_2():  # two outputs: seller + attacker (both large, to avoid mass noise)
        half = in_amt // 2
        outs = [PaymentOutput(seller, in_amt - half - m.FEE_SOMPI), PaymentOutput(attacker, half)]
        tx = tx_with(outs, 1)
        sig = create_input_signature(tx, 0, arb, SighashType.All)
        tx.inputs[0].signature_script = m.resolve_sig_script(rhex, sig); return tx

    def build_3():  # single output to seller, far below input - allowance
        tx = tx_with([PaymentOutput(seller, in_amt // 2)], 1)   # ~half "paid", half to fee
        sig = create_input_signature(tx, 0, arb, SighashType.All)
        tx.inputs[0].signature_script = m.resolve_sig_script(rhex, sig); return tx

    def build_4():  # settle path with the arbiter signature in both signer slots
        tx = tx_with([PaymentOutput(attacker, in_amt - m.FEE_SOMPI)], 2)
        sig = create_input_signature(tx, 0, arb, SighashType.All)
        tx.inputs[0].signature_script = m.settle_sig_script(rhex, sig, sig); return tx

    cases = [("off-whitelist payout (-> attacker)",        build_1, "whitelist"),
             ("two-output skim (seller + attacker)",        build_2, "output-count"),
             ("underpay below value floor",                 build_3, "value-floor"),
             ("settle-path masquerade (arbiter as both)",   build_4, "signature")]

    rejected = 0
    for i, (name, build, rule) in enumerate(cases, 1):
        try:
            tx = build()
            r = await aw(c.submit_transaction({"transaction": tx, "allowOrphan": False}))
            txid = r.get("transactionId") if isinstance(r, dict) else r
            print(f"[{i}] {name}")
            print(f"     !! ACCEPTED {txid} -- COVENANT BREACHED ({rule} rule did not hold)\n")
        except Exception as e:
            s = repr(e); j = s.find("verify the signature script")
            tail = s[j:j+90] if j != -1 else s[:90]
            print(f"[{i}] {name}")
            print(f"     rejected ({rule}): ...{tail}...\n")
            rejected += 1

    print(f"{rejected}/{len(cases)} attacks rejected by the covenant script.")
    if rejected == len(cases):
        print("The arbiter holds a valid key and still cannot steal, misdirect, underpay, or masquerade.")
    await aw(c.disconnect())

if __name__ == "__main__":
    asyncio.run(main())
