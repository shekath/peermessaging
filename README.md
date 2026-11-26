# Cipher — serverless, encrypted P2P messenger (Android core)

Security foundation for the app on the whiteboard: no phone numbers, no accounts, no message servers.
Contacts join only through **signed, single-use invite links or QR codes**.

> **No software is "unhackable."** This code removes whole classes of attack by design and uses only
> audited cryptography — but it must be compiled, tested and **independently audited** before release.
> It was written without an Android SDK available, so expect small API fixes when you first build
> (especially libsignal store signatures, which change between releases).

## Security layers

| # | Layer | File | What it stops |
|---|-------|------|---------------|
| 1 | Hardware vault (StrongBox/TEE, AES-256-GCM, locked-device-bound) | `security/KeystoreVault.kt` | Stolen app files, backups, forensic copies |
| 2 | Encrypted database (SQLCipher, secure-delete, memory security) | `storage/SecureDatabase.kt` | Reading messages/keys from disk |
| 3 | Identity = device key, address = hash of key | `identity/IdentityManager.kt` | Account takeover, SIM swap, impersonation |
| 4 | Signed, single-use, 24 h invites (link + QR) | `invite/InviteManager.kt` | Fake contacts, leaked-link reuse, phone-number scraping |
| 5 | Pinned trust store — **no trust-on-first-use** | `crypto/PinnedProtocolStore.kt` | MITM key substitution, strangers messaging you |
| 6 | Signal protocol: PQXDH (Kyber-1024) + Double Ratchet, length padding | `crypto/SessionManager.kt` | Eavesdropping, past/future key compromise, quantum harvest, size analysis |
| 7 | Sealed envelopes, strict parsing, replay window | `transport/Transport.kt` | Malicious relays/radios, replay floods |
| 8 | FLAG_SECURE, debugger + signature checks, R8, no logs | `security/IntegrityGuard.kt`, `proguard-rules.pro` | Screenshots, casual tampering, log leaks |

Platform hardening: `allowBackup=false`, backup/transfer exclusions, no cleartext, system CAs only,
no contacts/phone/SMS permissions, invite payload in the URL **fragment** (never sent to any server).

## Invite flow

```
Inviter                                   Invitee
create(): sign{idKey, reach, secret, exp} ── link / QR ──▶ parseAndVerify(): check sig, expiry
                                                         pin inviter idKey
          ◀── RedeemRequest{idKey, bundle, nonce, HMAC(secret, transcript)} ──
verifyRedeem(): constant-time HMAC, burn secret atomically
pin invitee idKey, startSession(bundle)
          ── inviter bundle (inside libsignal PreKey msg) ──▶ startSession()
            ═══════ Double Ratchet session, both identities pinned ═══════
```

## Threat model — what is and isn't covered

Covered: network attackers, malicious relays/radios/satellite gateways, stolen-but-locked phones,
leaked invite links, server subpoenas (there is no server), metadata from message size.

Not covered (be honest with users): a phone that's **unlocked and in an attacker's hands**, OS-level
spyware (Pegasus-class), a user who screenshots chats, timing analysis by a global network observer
(use the Tor transport to reduce this), and bugs not yet found — hence the audit.

## Get the APK

**Option A — no Android Studio (GitHub builds it for you, free):**
1. Create a new **private** repo on github.com and upload this folder's contents (keep `.github/`).
2. Open the repo's **Actions** tab → "Build APK" runs automatically (~6–8 min).
3. Open the finished run → download **Cipher-debug-apk** → unzip → copy `app-debug.apk` to your phone.
4. On the phone: tap the APK → allow "Install unknown apps" for your file manager → Install.
If the build fails, open the failed step's log — first builds often need a small libsignal API fix.

**Option B — Android Studio (Ladybug or newer, JDK 17):**
Open the folder → let Gradle sync → Build ▸ Build APK(s) → or Run ▶ with your phone on USB debugging.

**Before a public release:** set `EXPECTED_CERT_SHA256` in `IntegrityGuard.kt`, create a release keystore,
and build `assembleRelease` (R8-obfuscated, signed). Debug APKs are for testing only.

## What works in this build

Real: hardware-vault identity, encrypted DB, signed single-use invite links + QR codes, signature/expiry
verification, key pinning, safety numbers, share sheet, `cipher://` deep links, panic wipe, screenshot
blocking, integrity checks. Simulated (UI only): message delivery over internet/Wi-Fi/LoRa — the
transports are the next build step, so chats don't leave the phone yet.

**Licence note:** libsignal is AGPL-3.0, so the app must be released as open source under a
compatible licence. That's also good for trust — Signal, Briar and Session are all open source.

## Next steps

1. Compile and fix API drift; add instrumented tests (vault, DB, invite round-trip, session round-trip).
2. Internet transport: libp2p (Noise + DHT) or Tor onion services; Wi-Fi Direct + NSD for LAN.
3. Compose UI from the whiteboard prototype; app-lock PIN (Argon2id) + panic wipe.
4. Reproducible builds, dependency pinning (`gradle/verification-metadata.xml`), fuzz the parsers.
5. Independent security audit before any public release.
