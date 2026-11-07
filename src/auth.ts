import {
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

export class AuthError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "AuthError";
    this.code = code;
  }
}

/* ------------------------------------------------------------------ passwords */

const SCRYPT_PARAMS = { N: 16_384, r: 8, p: 1, keylen: 32 };

function safeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Hashes with scrypt and stores the parameters alongside the digest, so the cost can be
 * raised later without invalidating every existing password.
 */
export function hashPassword(password: string, salt?: Buffer): string {
  if (typeof password !== "string" || password.length < 8) {
    throw new AuthError("weak_password", "password must be at least 8 characters");
  }
  if (password.length > 1024) {
    throw new AuthError("invalid_password", "password is too long");
  }
  const { N, r, p, keylen } = SCRYPT_PARAMS;
  const saltBytes = salt ?? randomBytes(16);
  const derived = scryptSync(password, saltBytes, keylen, { N, r, p });
  return [
    "scrypt",
    N,
    r,
    p,
    saltBytes.toString("base64"),
    derived.toString("base64"),
  ].join("$");
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = String(stored).split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (!Number.isInteger(N) || N < 2 || N > 1_048_576) return false;
  if (!Number.isInteger(r) || r < 1 || r > 64) return false;
  if (!Number.isInteger(p) || p < 1 || p > 16) return false;

  let salt: Buffer;
  let expected: Buffer;
  try {
    salt = Buffer.from(parts[4], "base64");
    expected = Buffer.from(parts[5], "base64");
  } catch {
    return false;
  }
  if (salt.length === 0 || expected.length === 0) return false;

  let actual: Buffer;
  try {
    actual = scryptSync(password, salt, expected.length, { N, r, p });
  } catch {
    return false;
  }
  return safeEqual(actual, expected);
}

/* ---------------------------------------------------------------------- TOTP */

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[\s=]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new AuthError("invalid_secret", `not base32: ${char}`);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** HOTP (RFC 4226): truncate an HMAC-SHA1 over the counter. */
export function hotp(key: Buffer, counter: number, digits = 6): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", key).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, "0");
}

export function totp(secret: string | Buffer, time: number, step = 30, digits = 6): string {
  const key = typeof secret === "string" ? base32Decode(secret) : secret;
  if (key.length === 0) throw new AuthError("invalid_secret", "secret must not be empty");
  return hotp(key, Math.floor(time / 1000 / step), digits);
}

/**
 * Accepts the current step plus `window` steps either side, to absorb clock drift.
 * A wider window is a real security trade-off: every extra step is another code an
 * attacker can replay.
 */
export function verifyTotp(
  secret: string,
  code: string,
  time: number,
  opts: { step?: number; digits?: number; window?: number } = {},
): boolean {
  const step = opts.step ?? 30;
  const digits = opts.digits ?? 6;
  const window = opts.window ?? 1;
  if (!new RegExp(`^\\d{${digits}}$`).test(String(code))) return false;

  const key = base32Decode(secret);
  const counter = Math.floor(time / 1000 / step);
  const candidate = Buffer.from(code);
  let matched = false;
  for (let offset = -window; offset <= window; offset++) {
    const attempt = Buffer.from(hotp(key, counter + offset, digits));
    if (safeEqual(attempt, candidate)) matched = true;
  }
  return matched;
}

export function generateTotpSecret(bytes = 20): string {
  const raw = randomBytes(bytes);
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of raw) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function otpauthUri(issuer: string, account: string, secret: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({ secret, issuer, algorithm: "SHA1", digits: "6", period: "30" });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/* ------------------------------------------------------------------ sessions */

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export interface Session {
  userId: string;
  tokenHash: string;
  expiresAt: number;
  createdAt: number;
}

/**
 * Stores only a SHA-256 of each token. A leaked session table then contains no usable
 * credentials — the attacker cannot reverse a 256-bit random token.
 */
export class SessionStore {
  private sessions = new Map<string, Session>();
  private ttlMs: number;

  constructor(ttlMs = 24 * 60 * 60 * 1000) {
    this.ttlMs = ttlMs;
  }

  issue(userId: string, now = Date.now()): { token: string; expiresAt: number } {
    const token = randomBytes(32).toString("base64url");
    const session: Session = {
      userId,
      tokenHash: sha256(token),
      createdAt: now,
      expiresAt: now + this.ttlMs,
    };
    this.sessions.set(session.tokenHash, session);
    return { token, expiresAt: session.expiresAt };
  }

  resolve(token: string, now = Date.now()): Session | null {
    if (typeof token !== "string" || token === "") return null;
    const session = this.sessions.get(sha256(token));
    if (!session) return null;
    if (session.expiresAt <= now) {
      this.sessions.delete(session.tokenHash);
      return null;
    }
    return { ...session };
  }

  revoke(token: string): boolean {
    return this.sessions.delete(sha256(token));
  }

  revokeAll(userId: string): number {
    let removed = 0;
    for (const [hash, session] of this.sessions) {
      if (session.userId === userId) {
        this.sessions.delete(hash);
        removed++;
      }
    }
    return removed;
  }

  get size(): number {
    return this.sessions.size;
  }
}

/* ------------------------------------------------------------------ recovery */

export function generateRecoveryCodes(count = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = randomBytes(5).toString("hex").toUpperCase();
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5, 10)}`);
  }
  return codes;
}

/** Codes are stored hashed and removed on use, so each one works exactly once. */
export class RecoveryCodes {
  private codes = new Set<string>();

  load(codes: string[]): void {
    for (const code of codes) this.codes.add(sha256(this.normalise(code)));
  }

  remaining(): number {
    return this.codes.size;
  }

  redeem(code: string): boolean {
    return this.codes.delete(sha256(this.normalise(code)));
  }

  private normalise(code: string): string {
    return String(code).toUpperCase().replace(/[^A-Z0-9]/g, "");
  }
}

/* ------------------------------------------------------------------- lockout */

export class LockoutPolicy {
  private failures = new Map<string, { count: number; lockedUntil: number }>();
  private threshold: number;
  private lockoutMs: number;

  constructor(opts: { threshold?: number; lockoutMs?: number } = {}) {
    this.threshold = opts.threshold ?? 5;
    this.lockoutMs = opts.lockoutMs ?? 15 * 60 * 1000;
  }

  isLocked(key: string, now = Date.now()): boolean {
    const state = this.failures.get(key);
    return state !== undefined && state.lockedUntil > now;
  }

  recordFailure(key: string, now = Date.now()): { locked: boolean; remaining: number } {
    const state = this.failures.get(key) ?? { count: 0, lockedUntil: 0 };
    const count = state.count + 1;
    const locked = count >= this.threshold;
    this.failures.set(key, {
      count: locked ? 0 : count,
      lockedUntil: locked ? now + this.lockoutMs : 0,
    });
    return { locked, remaining: locked ? 0 : this.threshold - count };
  }

  recordSuccess(key: string): void {
    this.failures.delete(key);
  }

  retryAfterMs(key: string, now = Date.now()): number {
    const state = this.failures.get(key);
    if (!state) return 0;
    return Math.max(0, state.lockedUntil - now);
  }
}
