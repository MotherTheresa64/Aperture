import test from "node:test";
import assert from "node:assert/strict";
import {
  AuthError,
  LockoutPolicy,
  RecoveryCodes,
  SessionStore,
  base32Decode,
  generateRecoveryCodes,
  generateTotpSecret,
  hashPassword,
  hotp,
  otpauthUri,
  totp,
  verifyPassword,
  verifyTotp,
} from "../src/auth.ts";

const T0 = 1_700_000_000_000;

test("password hashes carry their parameters and a unique salt", () => {
  const a = hashPassword("correct horse battery");
  const b = hashPassword("correct horse battery");
  assert.match(a, /^scrypt\$16384\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
  assert.notEqual(a, b, "the same password must not produce the same digest");
  assert.equal(verifyPassword("correct horse battery", a), true);
  assert.equal(verifyPassword("correct horse battery", b), true);
});

test("a wrong password fails, and so does a tampered hash", () => {
  const stored = hashPassword("s3cretly-long");
  assert.equal(verifyPassword("s3cretly-lonf", stored), false);
  assert.equal(verifyPassword("", stored), false);
  assert.equal(verifyPassword("s3cretly-long", stored.replace("scrypt$", "bcrypt$")), false);
  assert.equal(verifyPassword("s3cretly-long", "garbage"), false);
  assert.equal(verifyPassword("s3cretly-long", ""), false);
});

test("rehashing with a known salt is deterministic", () => {
  const salt = Buffer.alloc(16, 7);
  assert.equal(hashPassword("reproducible-pass", salt), hashPassword("reproducible-pass", salt));
});

test("weak passwords are refused", () => {
  assert.throws(() => hashPassword("short"), AuthError);
  assert.throws(() => hashPassword(""), AuthError);
  assert.throws(() => hashPassword("x".repeat(1025)), AuthError);
});

test("HOTP matches the RFC 4226 reference vectors", () => {
  const key = Buffer.from("12345678901234567890", "ascii");
  assert.equal(hotp(key, 0), "755224");
  assert.equal(hotp(key, 1), "287082");
  assert.equal(hotp(key, 2), "359152");
});

test("TOTP matches the RFC 6238 reference vectors", () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // ASCII "12345678901234567890"
  assert.deepEqual(base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), Buffer.from("12345678901234567890", "ascii"));
  assert.equal(totp(secret, 59_000, 30, 8), "94287082");
  assert.equal(totp(secret, 1_111_111_109_000, 30, 8), "07081804");
  assert.equal(totp(secret, 1_234_567_890_000, 30, 8), "89005924");
});

test("verification accepts drift inside the window and nothing outside it", () => {
  const secret = generateTotpSecret();
  const now = T0;
  const code = totp(secret, now);

  assert.equal(verifyTotp(secret, code, now), true);
  assert.equal(verifyTotp(secret, code, now + 29_000), true, "same 30-second step");
  assert.equal(verifyTotp(secret, code, now + 30_000), true, "one step of drift is tolerated");
  assert.equal(verifyTotp(secret, code, now + 60_000), false, "two steps away exceeds the default ±1 window");
  assert.equal(verifyTotp(secret, code, now + 120_000), false, "three steps away is a replay risk");
  assert.equal(verifyTotp(secret, code, now + 60_000, { window: 2 }), true, "a widened window accepts it");
  assert.equal(verifyTotp(secret, code, now, { window: 0 }), true, "an exact window still accepts now");
  assert.equal(verifyTotp(secret, "000000" === code ? "111111" : "000000", now), false);
  assert.equal(verifyTotp(secret, "abcdef", now), false, "non-numeric input is not a code");
  assert.equal(verifyTotp(secret, "12345", now), false, "wrong length");
});

test("generated secrets are base32 and usable", () => {
  const secret = generateTotpSecret();
  assert.match(secret, /^[A-Z2-7]+$/);
  assert.equal(base32Decode(secret).length, 20);
  assert.equal(typeof totp(secret, T0), "string");
  assert.equal(totp(secret, T0).length, 6);
});

test("the enrolment URI is scannable", () => {
  const uri = otpauthUri("Noah's App", "noah@example.com", "GEZDGNBVGY3TQOJQ");
  assert.ok(uri.startsWith("otpauth://totp/"));
  assert.ok(uri.includes("secret=GEZDGNBVGY3TQOJQ"));
  assert.ok(uri.includes("digits=6"));
  assert.ok(uri.includes("period=30"));
});

test("a session token resolves to its user until it expires", () => {
  const store = new SessionStore(60_000);
  const { token, expiresAt } = store.issue("user-1", T0);
  assert.equal(expiresAt, T0 + 60_000);

  const session = store.resolve(token, T0 + 1);
  assert.ok(session);
  assert.equal(session.userId, "user-1");

  assert.equal(store.resolve(token, T0 + 60_000), null, "expiry is inclusive at the boundary");
  assert.equal(store.size, 0, "an expired session is dropped, not retained");
});

test("only a hash of the token is stored", () => {
  const store = new SessionStore();
  const { token } = store.issue("user-1", T0);
  const session = store.resolve(token, T0)!;
  assert.notEqual(session.tokenHash, token);
  assert.match(session.tokenHash, /^[0-9a-f]{64}$/);
  assert.equal(store.resolve(session.tokenHash, T0), null, "the stored hash is not a credential");
});

test("unknown and malformed tokens resolve to nothing", () => {
  const store = new SessionStore();
  store.issue("user-1", T0);
  assert.equal(store.resolve("not-a-token", T0), null);
  assert.equal(store.resolve("", T0), null);
  assert.equal(store.resolve(undefined as never, T0), null);
});

test("sessions can be revoked individually or wholesale", () => {
  const store = new SessionStore();
  const first = store.issue("user-1", T0);
  const second = store.issue("user-1", T0);
  store.issue("user-2", T0);

  assert.equal(store.revoke(first.token), true);
  assert.equal(store.resolve(first.token, T0), null);
  assert.equal(store.revoke(first.token), false, "revoking twice reports no change");

  assert.equal(store.revokeAll("user-1"), 1);
  assert.equal(store.resolve(second.token, T0), null);
  assert.equal(store.size, 1, "the other user's session survives");
});

test("recovery codes are unique, normalised and single use", () => {
  const codes = generateRecoveryCodes(5);
  assert.equal(codes.length, 5);
  assert.equal(new Set(codes).size, 5);
  for (const code of codes) assert.match(code, /^[0-9A-F]{5}-[0-9A-F]{5}$/);

  const store = new RecoveryCodes();
  store.load(codes);
  assert.equal(store.remaining(), 5);

  assert.equal(store.redeem(codes[0].toLowerCase().replace("-", " ")), true, "formatting is forgiven");
  assert.equal(store.redeem(codes[0]), false, "a code works exactly once");
  assert.equal(store.remaining(), 4);
  assert.equal(store.redeem("AAAAA-BBBBB"), false, "an invented code is useless");
});

test("lockout triggers at the threshold and clears on success", () => {
  const policy = new LockoutPolicy({ threshold: 3, lockoutMs: 60_000 });
  assert.equal(policy.recordFailure("u1", T0).locked, false);
  assert.equal(policy.recordFailure("u1", T0).remaining, 1);
  assert.equal(policy.recordFailure("u1", T0).locked, true);

  assert.equal(policy.isLocked("u1", T0), true);
  assert.equal(policy.retryAfterMs("u1", T0), 60_000);
  assert.equal(policy.isLocked("u1", T0 + 60_000), false, "the lock expires");
  assert.equal(policy.retryAfterMs("u1", T0 + 60_000), 0);

  policy.recordFailure("u2", T0);
  policy.recordFailure("u2", T0);
  policy.recordSuccess("u2");
  assert.equal(policy.recordFailure("u2", T0).remaining, 2, "success resets the counter to zero");
});

test("lockout is per key", () => {
  const policy = new LockoutPolicy({ threshold: 2, lockoutMs: 1_000 });
  policy.recordFailure("a", T0);
  policy.recordFailure("a", T0);
  assert.equal(policy.isLocked("a", T0), true);
  assert.equal(policy.isLocked("b", T0), false);
});
