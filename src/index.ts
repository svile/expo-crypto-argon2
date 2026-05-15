import { requireNativeModule } from 'expo-modules-core';

/** Mirrors hash-wasm's IDataType. Strings are UTF-8 encoded before hashing. */
export type IDataType = string | Uint8Array;

export interface Argon2Params {
  password: IDataType;
  salt: IDataType;
  /** Optional secret key for keyed hashing. */
  secret?: IDataType;
  iterations: number;
  parallelism: number;
  /** Memory in KiB — e.g. 65536 = 64 MiB. */
  memorySize: number;
  hashLength: number;
  /** Output format. Defaults to 'hex'. */
  outputType?: 'hex' | 'binary' | 'encoded';
}

/** Mirrors hash-wasm's conditional return type. */
type Argon2ReturnType<T extends Argon2Params> = T extends {
  outputType: 'binary';
}
  ? Uint8Array
  : string;

const ExpoCryptoArgon2 = requireNativeModule('ExpoCryptoArgon2');

export async function argon2id<T extends Argon2Params>(
  params: T,
): Promise<Argon2ReturnType<T>> {
  if (params.secret !== undefined) {
    // Requires argon2_ctx (lower-level API) — not yet implemented
    throw new Error('expo-crypto-argon2: secret is not yet supported');
  }

  const outputType = params.outputType ?? 'hex';

  // Native always returns raw bytes (Uint8Array). Output conversion happens here.
  const hashBytes: Uint8Array = await ExpoCryptoArgon2.argon2id({
    password: toHex(params.password),
    salt: toHex(params.salt),
    iterations: params.iterations,
    memory: params.memorySize,
    parallelism: params.parallelism,
    hashLength: params.hashLength,
  });

  if (outputType === 'binary') {
    return hashBytes as Argon2ReturnType<T>;
  }
  if (outputType === 'encoded') {
    const saltBytes = toBytes(params.salt);
    const encoded = `$argon2id$v=19$m=${params.memorySize},t=${params.iterations},p=${params.parallelism}$${toBase64url(saltBytes)}$${toBase64url(hashBytes)}`;
    return encoded as Argon2ReturnType<T>;
  }
  return uint8ArrayToHex(hashBytes) as Argon2ReturnType<T>;
}

function toBytes(data: IDataType): Uint8Array {
  if (typeof data === 'string') {
    return new TextEncoder().encode(data);
  }
  return data;
}

function toHex(data: IDataType): string {
  return uint8ArrayToHex(toBytes(data));
}

function uint8ArrayToHex(arr: Uint8Array): string {
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

function toBase64url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
