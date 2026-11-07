# Aperture

Authentication primitives that are easy to get wrong: password hashing, session tokens,
TOTP two-factor codes, recovery codes, and login lockout.

Zero dependencies — `node:crypto` does the cryptography; the work is using it correctly.

## Run it

```bash
node --test
```

```ts
import { hashPassword, verifyPassword, SessionStore, totp, generateTotpSecret } from "./src/auth.ts";

const stored = hashPassword("a long passphrase");
verifyPassword("a long passphrase", stored); // true

const sessions = new SessionStore(24 * 60 * 60 * 1000);
const { token } = sessions.issue("user-1");
sessions.resolve(token)?.userId; // "user-1"
```

## What each piece does, and why it is shaped that way

**Passwords: scrypt with stored parameters.** The hash string is
`scrypt$N$r$p$salt$digest`, so raising the cost later does not invalidate existing users — old
hashes keep their own parameters. Comparing with `timingSafeEqual` avoids leaking the digest
through response timing.

**Sessions: only the hash is stored.** The token is 32 random bytes; the store keeps
`SHA-256(token)`. A stolen session table therefore yields nothing usable, because you cannot
reverse a 256-bit random value. Lookup hashes the presented token and indexes by that.

**TOTP: implemented, not approximated.** `totp()` reproduces the RFC 6238 reference vectors
(`94287082` at t=59, `07081804` at t=1111111109, `89005924` at t=1234567890) — those are the
official test values, and they are asserted in the suite. A hand-rolled TOTP that is merely
"close" produces codes that no authenticator app will accept.

**Drift window is ±1 step by default.** Every additional step is another code an attacker can
replay, so the default is deliberately narrow and configurable rather than generously wide.

**Recovery codes are hashed and removed on use.** One code, one login. Formatting is forgiven
(lowercase, spaces instead of dashes) because that is what a user typing from paper will do.

**Lockout counts per key and clears on success.** A global counter would let one attacker lock
out every account; a per-key counter with exponential lockout is the version that does not
become a denial-of-service tool.

## Design decisions

**Errors are typed, not strings.** `AuthError` carries a `code` (`weak_password`,
`invalid_secret`), so callers map to responses without parsing messages, and a message can be
changed without breaking control flow.

**Parameter parsing is defensive.** `verifyPassword` validates `N`, `r` and `p` against sane
bounds before calling scrypt, so a corrupted or hostile stored hash cannot turn into a
memory-exhaustion attempt.

**The enrolment URI is generated, not described.** `otpauthUri` produces the exact
`otpauth://totp/...` form an authenticator app expects, including digits and period.

## Tests

Hash format, salt uniqueness, correct/incorrect/tampered verification, weak-password refusal,
RFC 4226 and RFC 6238 reference vectors, drift-window boundaries, base32 round-trip, session
resolution and expiry, proof that only hashes are stored, revocation, recovery-code
normalisation and single use, and lockout thresholds, expiry and per-key isolation.
