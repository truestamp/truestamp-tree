// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { encode, decode } from '@stablelib/hex'
import { equal as stableEqual } from '@stablelib/constant-time'
import { concat as stableConcat } from '@stablelib/bytes'
import { hash as stableSHA224 } from '@stablelib/sha224'
import { hash as stableSHA256 } from '@stablelib/sha256'
import { hash as stableSHA384 } from '@stablelib/sha384'
import { hash as stableSHA512 } from '@stablelib/sha512'
import { hash as stableSHA512_256 } from '@stablelib/sha512_256'
import {
  hash224 as stableSHA3224,
  hash256 as stableSHA3256,
  hash384 as stableSHA3384,
  hash512 as stableSHA3512,
} from '@stablelib/sha3'

/**
 * Constant time comparison of two Uint8Arrays.
 * Returns true if a and b are of equal non-zero length, and their contents are equal, or false otherwise.
 * Note that zero-length inputs are considered not equal, so this function will return false.
 * @param a First Uint8Array string to compare.
 * @param b Second Uint8Array string to compare.
 * @returns Boolean indicating if both args are identical.
 */
export function compare(a: Uint8Array, b: Uint8Array): boolean {
  return stableEqual(a, b)
}

/**
 * Concatenates byte arrays.
 * @param arrays Uint8Arrays to concatenate.
 * @returns Concatenated Uint8Array.
 */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  return stableConcat(...arrays)
}

/**
 * Decodes a Hex encoded string to a Uint8Array.
 * @param s Hex encoded Uint8Array string to decode.
 * @returns Decoded Uint8Array.
 */
export function decodeHex(s: string): Uint8Array {
  return decode(s)
}

/**
 * Encodes a Uint8Array to Hex encoded string.
 * @param u Uint8Array to encode.
 * @returns HEX encoded Uint8Array string.
 */
export function encodeHex(u: Uint8Array): string {
  // lowercase hex string
  return encode(u, true)
}

/**
 * Test whether a number is a power of two (1,2,4,8,16,32,...).
 * This is useful for determining if the data preparing to be added to the tree is a power of two in length, and thus a balanced tree.
 * @param x Number to test.
 * @returns Boolean indicating if the number is a power of two.
 */
export function powerOfTwo(x: number): boolean {
  return Math.log2(x) % 1 === 0
}

/**
 * Pure JavaScript SHA224 hash function that accepts and returns Uint8Array values.
 * @param data The data to hash.
 * @returns The hash digest.
 */
export function sha224(data: Uint8Array): Uint8Array {
  return stableSHA224(data)
}

/**
 * Pure JavaScript SHA256 hash function that accepts and returns Uint8Array values.
 * @param data The data to hash.
 * @returns The hash digest.
 */
export function sha256(data: Uint8Array): Uint8Array {
  return stableSHA256(data)
}

/**
 * Pure JavaScript SHA384 hash function that accepts and returns Uint8Array values.
 * @param data The data to hash.
 * @returns The hash digest.
 */
export function sha384(data: Uint8Array): Uint8Array {
  return stableSHA384(data)
}

/**
 * Pure JavaScript SHA512 hash function that accepts and returns Uint8Array values.
 * @param data The data to hash.
 * @returns The hash digest.
 */
export function sha512(data: Uint8Array): Uint8Array {
  return stableSHA512(data)
}

/**
 * Pure JavaScript SHA512/256 hash function that accepts and returns Uint8Array values.
 * @param data The data to hash.
 * @returns The hash digest.
 */
export function sha512_256(data: Uint8Array): Uint8Array {
  return stableSHA512_256(data)
}

/**
 * Pure JavaScript SHA3-224 hash function that accepts and returns Uint8Array values.
 * @param data The data to hash.
 * @returns The hash digest.
 */
export function sha3_224(data: Uint8Array): Uint8Array {
  return stableSHA3224(data)
}

/**
 * Pure JavaScript SHA3-256 hash function that accepts and returns Uint8Array values.
 * @param data The data to hash.
 * @returns The hash digest.
 */
export function sha3_256(data: Uint8Array): Uint8Array {
  return stableSHA3256(data)
}

/**
 * Pure JavaScript SHA3-384 hash function that accepts and returns Uint8Array values.
 * @param data The data to hash.
 * @returns The hash digest.
 */
export function sha3_384(data: Uint8Array): Uint8Array {
  return stableSHA3384(data)
}

/**
 * Pure JavaScript SHA3-512 hash function that accepts and returns Uint8Array values.
 * @param data The data to hash.
 * @returns The hash digest.
 */
export function sha3_512(data: Uint8Array): Uint8Array {
  return stableSHA3512(data)
}
