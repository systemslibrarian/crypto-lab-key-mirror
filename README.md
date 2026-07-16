# Key Mirror

**Key Transparency · append-only authenticated map · IETF KEYTRANS**

A key directory that can lie to one user and tell the truth to another, and the append-only Merkle structure plus gossip that makes the lie detectable.

## What It Is

Every end-to-end-encrypted system has a server that hands out public keys. The encryption (here: X25519 ECDH → HKDF-SHA-256 → AES-256-GCM) answers *"can anyone else read this?"* — it cannot answer *"whose key did I encrypt to?"* If the server **equivocates** — shows Alice a substituted key for Bob while showing Carol the real one — the encryption is perfect and the security is zero.

This demo runs that attack first, against real crypto, then rebuilds the defense one layer at a time:

- **RFC 6962 Merkle tree** (hand-rolled, inspectable): leaf/node hashing, audit paths, consistency proofs, and the independent RFC 9162 verifiers — pinned to the canonical Certificate Transparency reference-tree vectors.
- **ed25519 signed tree heads and signed bindings** (@noble/curves).
- **ECVRF-EDWARDS25519-SHA512-TAI** (RFC 9381, hand-rolled over @noble/curves point arithmetic) for label privacy — pinned to all three Appendix B.3 vectors.
- **X25519 + HKDF + AES-GCM** sealed box (RFC 7748 KAT) as the E2EE layer the attack rides on.

Security model: the **directory server is the adversary**. Clients verify everything a client can verify alone (signatures, inclusion, consistency); detection of equivocation additionally requires comparing notes across users (gossip) and self-monitoring. Transparency is **detection, not prevention** — the demo says so in-page, because the attacker really does read the messages sent before detection.

**Not production crypto — a teaching demo.** Key material is generated per page load and lives only in memory; nothing leaves the browser.

## Exhibits

1. **The lie** — flip the directory to malicious and step through Alice's lookup, her AES-GCM-sealed message landing on Mallory's key, the re-encrypted forward Bob never questions, and Carol getting the truth. Cryptographic results and the security verdict are rendered separately: every tag verifies *and* the verdict is alarm.
2. **The defense, layer by layer** — run the same attack at layers 0–4: bare trust, signed responses, inclusion proofs, consistency proofs, gossip. Layers 0–3 pass every genuine check while the lie stands; layer 4 produces two validly signed heads for the same epoch with different roots — transferable proof of equivocation.
3. **Consistency proofs, byte by byte** — step the real RFC 9162 verifier through an honest append (proof verifies) and a forked history (reconstruction mismatches, shown per-byte).
4. **Label privacy** — real ECVRF maps username → tree slot: verifiable to the user holding the proof, opaque to observers; flip one bit of the proof and the verifier rejects.
5. **Monitoring** — Bob audits his own published history and finds the planted key, inclusion proof attached: the attacker had to leave a receipt.

## When to Use It

- Teaching why E2EE messengers (WhatsApp key transparency, iMessage Contact Key Verification, Signal's planned KT) need a transparency layer at all.
- Explaining the difference between *authentication* (layer 1), *membership* (layer 2), *append-only history* (layer 3), and *global consistency* (layer 4) — and why each one alone is insufficient.
- Showing what CONIKS/Parakeet/KEYTRANS-lineage systems actually detect, and what they don't.
- **Do NOT use it** as a key-transparency implementation, as a KEYTRANS wire-format reference, or as evidence that any specific deployed system is secure. The Merkle log here is a flat binding log, not KEYTRANS's VRF-addressed prefix tree.

## Live Demo

<https://systemslibrarian.github.io/crypto-lab-key-mirror/> — flip the malicious toggle, run the interception, climb the defense ladder, step the failing fork proof, derive and tamper with a VRF label, and audit Bob's history.

## What Can Go Wrong

- **Equivocation below the gossip layer is undetectable by design** — that is the lab's thesis, demonstrated with passing proofs, not asserted.
- **Gossip only detects lies between compared views**: if Alice never compares heads with anyone, her fork lives on. Coverage, not cleverness, is the guarantee.
- **Detection is retroactive.** Messages sent to the substituted key before detection are compromised, permanently.
- **Monitoring requires participation**: a key planted under Bob's name is only found if Bob (or his devices, or a delegated monitor) actually audits.
- **Trust on first use remains**: a client's first accepted tree head anchors everything after it.

## Real-World Usage

- **WhatsApp** ships key transparency built on its auditable key directory (Parakeet lineage).
- **Apple iMessage** Contact Key Verification has devices automatically cross-check the key directory.
- **IETF KEYTRANS WG** is standardizing the authenticated-map construction this demo teaches the trust story of.
- **Certificate Transparency** (RFC 6962/9162) is the same machinery pointed at X.509 certificates — CT logs certificates for domain names, KT logs public keys for user identities.

## How to Run Locally

```bash
npm install
npm run dev        # local dev server
npm test           # 50 unit tests incl. spec KATs
npm run build      # typecheck + production build
npm run test:a11y  # axe WCAG 2.1 A/AA gate, both themes (needs: npx playwright install chromium)
```

## Related Demos

- [vrf-gate](https://systemslibrarian.github.io/crypto-lab-vrf-gate/) — the full ECVRF construction this lab links to for depth
- [merkle-proofs](https://systemslibrarian.github.io/crypto-lab-merkle-proofs/) / [merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) / [pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/) — Merkle trees and Certificate Transparency
- [x3dh-wire](https://systemslibrarian.github.io/crypto-lab-x3dh-wire/) / [ratchet-wire](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/) / [mls-group](https://systemslibrarian.github.io/crypto-lab-mls-group/) — the messaging protocols whose key directories KT audits

## Build & Verify

- **50 Vitest tests, all passing**, including:
  - RFC 6962 Merkle KATs — the CT reference tree: empty-tree hash, all 8 incremental roots, 5 audit-path vectors, 4 consistency-proof vectors (`src/merkle/kat.test.ts`);
  - RFC 9381 Appendix B.3 ECVRF KATs — Examples 16–18 in full (pi, beta, H, and the try-and-increment counter), prove and verify (`src/vrf/ecvrf.test.ts`);
  - RFC 7748 §6.1 X25519 KAT and FIPS 180-4 SHA-256 KATs;
  - fail-closed rejection tests for every verifier, an attack test proving layers 0–3 pass while views diverge, gossip detection, and monitor findings;
  - the UI stepper's traced verifier pinned to the real verifier (`src/merkle/trace.test.ts`).
- **Accessibility gate**: `@axe-core/playwright` scans the production build in **both** themes with every exhibit driven to its richest (alarm) state; zero WCAG 2.1 A/AA violations required, enforced in CI before deploy.

## Performance

All proofs are over toy-sized logs (≤ 33 leaves); every interaction completes in milliseconds. ECVRF proving is a few curve multiplications (~1 ms); nothing here is performance-sensitive.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
