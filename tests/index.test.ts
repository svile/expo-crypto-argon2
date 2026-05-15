import { beforeEach, describe, expect, it, vi } from 'vitest';

// vi.hoisted ensures mockArgon2id exists before the vi.mock factory runs
const { mockArgon2id } = vi.hoisted(() => ({ mockArgon2id: vi.fn() }));

vi.mock('expo-modules-core', () => ({
  requireNativeModule: () => ({ argon2id: mockArgon2id }),
}));

import { argon2id } from '../src';

// Known hash bytes used across all tests
const HASH_BYTES = new Uint8Array([
  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
]);
const HASH_HEX = '0123456789abcdef';

const BASE_PARAMS = {
  password: 'password',
  salt: 'salt',
  iterations: 3,
  memorySize: 65536,
  parallelism: 1,
  hashLength: 8,
} as const;

beforeEach(() => {
  mockArgon2id.mockResolvedValue(HASH_BYTES);
});

describe('native call params', () => {
  it('converts string password and salt to UTF-8 hex', async () => {
    await argon2id({ ...BASE_PARAMS, outputType: 'hex' });
    expect(mockArgon2id).toHaveBeenCalledWith({
      password: '70617373776f7264', // "password" in UTF-8
      salt: '73616c74', // "salt" in UTF-8
      iterations: 3,
      memory: 65536,
      parallelism: 1,
      hashLength: 8,
    });
  });

  it('passes Uint8Array password and salt as hex without UTF-8 re-encoding', async () => {
    const password = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const salt = new Uint8Array([0xca, 0xfe]);
    await argon2id({ ...BASE_PARAMS, password, salt });
    expect(mockArgon2id).toHaveBeenCalledWith(
      expect.objectContaining({ password: 'deadbeef', salt: 'cafe' }),
    );
  });

  it('passes memorySize as memory to native', async () => {
    await argon2id({ ...BASE_PARAMS });
    expect(mockArgon2id).toHaveBeenCalledWith(
      expect.objectContaining({ memory: 65536 }),
    );
  });

  it('does not pass outputType to native', async () => {
    await argon2id({ ...BASE_PARAMS, outputType: 'hex' });
    const call = mockArgon2id.mock.calls[0][0];
    expect(call).not.toHaveProperty('outputType');
  });
});

describe('hex output', () => {
  it('converts native Uint8Array to lowercase hex string', async () => {
    const result = await argon2id({ ...BASE_PARAMS, outputType: 'hex' });
    expect(result).toBe(HASH_HEX);
  });

  it('defaults to hex when outputType is omitted', async () => {
    const result = await argon2id(BASE_PARAMS);
    expect(result).toBe(HASH_HEX);
  });
});

describe('binary output', () => {
  it('returns native Uint8Array as-is', async () => {
    const result = await argon2id({ ...BASE_PARAMS, outputType: 'binary' });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result).toBe(HASH_BYTES); // same reference, no copy
  });
});

describe('encoded output', () => {
  it('returns a PHC-format string', async () => {
    const result = await argon2id({ ...BASE_PARAMS, outputType: 'encoded' });
    expect(result).toMatch(
      /^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/\-_]+\$[A-Za-z0-9+/\-_]+$/,
    );
  });

  it('encodes the correct params in the PHC header', async () => {
    const result = await argon2id({ ...BASE_PARAMS, outputType: 'encoded' });
    expect(result).toContain('$argon2id$v=19$m=65536,t=3,p=1$');
  });

  it('base64url-encodes the salt without padding', async () => {
    const result = await argon2id({ ...BASE_PARAMS, outputType: 'encoded' });
    // "salt" UTF-8 → btoa → "c2FsdA==" → base64url → "c2FsdA"
    const parts = result.split('$');
    expect(parts[4]).toBe('c2FsdA');
    expect(parts[4]).not.toContain('=');
  });

  it('base64url-encodes the hash without padding', async () => {
    const result = await argon2id({ ...BASE_PARAMS, outputType: 'encoded' });
    const parts = result.split('$');
    expect(parts[5]).not.toContain('=');
  });

  it('uses base64url-safe characters (- and _ instead of + and /)', async () => {
    // Use bytes that produce + or / in standard base64 to verify substitution
    mockArgon2id.mockResolvedValue(new Uint8Array([0xfb, 0xff, 0xfe]));
    const result = await argon2id({ ...BASE_PARAMS, outputType: 'encoded' });
    expect(result).not.toContain('+');
    expect(result).not.toContain('/');
  });
});

describe('error handling', () => {
  it('throws when secret is provided', async () => {
    await expect(
      argon2id({ ...BASE_PARAMS, secret: 'secret' }),
    ).rejects.toThrow('expo-crypto-argon2: secret is not yet supported');
  });

  it('propagates native errors', async () => {
    mockArgon2id.mockRejectedValue(new Error('argon2: wrong hash length'));
    await expect(argon2id(BASE_PARAMS)).rejects.toThrow(
      'argon2: wrong hash length',
    );
  });
});
