#!/usr/bin/env python3
"""
Adversarial probe for the Step 3b hardened agent-budget covenant.

Models a COMPROMISED AGENT: every attack is signed with the real agent key (so the
agent-auth check passes) but deliberately breaks one consensus rule, then is submitted
directly to the node -- bypassing all of the CLI's local guards. A correct covenant
must reject each one in the SCRIPT itself, not in client code.

Battery (each violates exactly one rule; earlier rules kept valid so the failure is
attributable to the target):
  1. over-cap        out0 > CAP
  2. off-whitelist   out0 to a non-whitelisted address
  3. wrong dev fee   out1 amount != DEV_FEE
  4. fee-drain       out0+out1+out2 + ALLOWANCE < input  (inflated fee)
  5. wrong signature agent path signed with the OWNER key
  6. forged child    out2 bound to an arbitrary address, not the templated child

All should be rejected by the covenant. Any ACCEPTED result is a SECURITY FAILURE.
Reuses the live covenant's own code/config so the redeem matches the funded UTXO.
"""
import asyncio, json, importlib.util, os, kaspa

# load the covenant module to reuse its exact script/helpers/config (works flat or foldered)
_cands = ["kaspa_agent_covenant_step3b.py",
          os.path.join("covenant", "kaspa_agent_covenant_step3b.py"),
          os.path.join("..", "covenant", "kaspa_agent_covenant_step3b.py")]
_path = next((p for p in _cands if os.path.exists(p)), _cands[0])
spec = importlib.util.spec_from_file_location("m", _path)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
S = m.SOMPI

def classify(msg):
    t = msg.lower()
    if ("script ran, but verification failed" in t or
        ("signature script" in t and "verif" in t) or
        "verification failed" in t):
        return "SCRIPT RULE  (covenant rejected) "
    if "not final" in t or "finaliz" in t or "sequence" in t:
        return "TIMELOCK (NOT the target rule)"
    if "already spent" in t or "already in mempool" in t:
        return "UTXO/mempool state"
    return "OTHER: " + msg[:90]

async def main():
    cfg = json.load(open(m.CFG_PATH))
    c = await m.with_client()
    addr = m.addr_for(cfg)
    entries = await m.utxos_for(c, addr)
    if not entries:
        print("no covenant UTXO at", addr); return
    u = entries[0]; in_amt = m.get_amount(u); D = await m.current_daa(c)
    L = D - m.LOCKTIME_MARGIN
    full, period = cfg["full_sompi"], cfg["period_daa"]
    budget, anchor = cfg["budget_sompi"], cfg["anchor"]
    reset = L >= anchor + period
    cap = cfg["cap_sompi"]; dev_fee = cfg["dev_fee_sompi"]; dev_addr = cfg["dev_addr"]
    wl = cfg["whitelist_addrs"][0]
    redeem = m.redeem_for(budget, anchor, cfg)
    FEE = m.FEE_SOMPI

    print(f"target covenant : {addr}")
    print(f"  in {in_amt/S} TKAS | budget {budget/S} | cap {cap/S} | dev {dev_fee/S}->{dev_addr[:20]} | reset={reset}\n")

    def child_for(out0):
        nb = (full if reset else budget) - out0
        na = L if reset else anchor
        return m.p2sh_for(m.redeem_for(nb, na, cfg))[0]

    def make(outs, key, selector):
        entry = u if not isinstance(u, dict) else kaspa.UtxoEntryReference.from_dict(u)
        tx = m.create_transaction([entry], [m.PaymentOutput(a, int(v)) for a, v in outs], 0)
        try: tx.lock_time = L
        except Exception: pass
        try: tx.inputs[0].sequence = 1
        except Exception: pass
        sig = m.create_input_signature(tx, 0, m.PrivateKey(key), m.SighashType.All)
        tx.inputs[0].signature_script = m.p2sh_sig_script(redeem.hex(), sig, selector)
        return tx

    A, O = cfg["agent_priv"], cfg["owner_priv"]
    n8 = 8 * S
    attacks = [
        ("over-cap (out0 > CAP)",
         [(wl, 11 * S), (dev_addr, dev_fee), (child_for(11 * S), in_amt - 11 * S - dev_fee - FEE)], A, True),
        ("off-whitelist (out0 to unlisted addr)",
         [(dev_addr, n8), (dev_addr, dev_fee), (child_for(n8), in_amt - n8 - dev_fee - FEE)], A, True),
        ("wrong dev fee (out1 != DEV_FEE)",
         [(wl, n8), (dev_addr, 1 * S), (child_for(n8), in_amt - n8 - 1 * S - FEE)], A, True),
        ("fee-drain (fee > ALLOWANCE)",
         [(wl, n8), (dev_addr, dev_fee), (child_for(n8), in_amt - n8 - dev_fee - 50_000_000)], A, True),
        ("wrong signature (owner key on agent path)",
         [(wl, n8), (dev_addr, dev_fee), (child_for(n8), in_amt - n8 - dev_fee - FEE)], O, True),
        ("forged child (out2 -> arbitrary addr)",
         [(wl, n8), (dev_addr, dev_fee), (wl, in_amt - n8 - dev_fee - FEE)], A, True),
    ]

    blocked = 0
    for name, outs, key, sel in attacks:
        try:
            tx = make(outs, key, sel)
            r = await m.aw(c.submit_transaction({"transaction": tx, "allowOrphan": False}))
            print(f"[!!] {name:<42} ACCEPTED -> SECURITY FAILURE  {r}")
        except Exception as e:
            cls = classify(repr(e))
            if cls.startswith("SCRIPT RULE"): blocked += 1
            print(f"[ok] {name:<42} {cls}")
    print(f"\n{blocked}/{len(attacks)} blocked by the covenant script itself.")
    if blocked == len(attacks):
        print("=> every limit is enforced at consensus, not in client code. Security claim sealed.")
    await m.aw(c.disconnect())

if __name__ == "__main__":
    asyncio.run(main())
