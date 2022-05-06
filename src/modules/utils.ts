// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { createHash } from 'sha256-uint8array'
import { TreeHashFunction } from './types'
import { encode, decode } from '@stablelib/hex'

/**
 * Compare two Uint8Array.
 * @param a First Uint8Array string to compare.
 * @param b Second Uint8Array string to compare.
 * @returns Boolean indicating if both args are identical.
 */
export function compare(a: Uint8Array, b: Uint8Array): boolean {
  if (a === b) return true
  if (a.byteLength !== b.byteLength) return false

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }

  return true
}

/**
 * Concatenate two Uint8Array.
 * @param a First Uint8Array string to concat.
 * @param b Second Uint8Array string to concat.
 * @returns Concatenated Uint8Array.
 */
export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const tmp: Uint8Array = new Uint8Array(a.byteLength + b.byteLength)
  tmp.set(new Uint8Array(a), 0)
  tmp.set(new Uint8Array(b), a.byteLength)
  return tmp
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
 * @param x Number to test.
 * @returns Boolean indicating if the number is a power of two.
 */
export function powerOfTwo(x: number): boolean {
  return Math.log2(x) % 1 === 0
}

/**
 * Test that a hash function accepts and returns a Uint8Array, returning the hash length.
 * @param f The hash function to test.
 * @returns The length of the hash function output.
 */
export function validateHashFunction(f: TreeHashFunction): number {
  if (typeof f !== 'function') {
    throw new Error('hashFunction must be a function')
  }

  const testOutput: Uint8Array = f(new Uint8Array([0]))
  const hashLength: number = testOutput.byteLength
  if (hashLength < 20 || hashLength > 64) {
    throw new Error(
      'hash function must return a non-empty Uint8Array between 20 and 64 bytes long',
    )
  }
  return hashLength
}

// Pure JavaScript implementation of the SHA-256 hash function that
// accepts and returns Uint8Array.
// const createHash = require("sha256-uint8array").createHash;

/**
 * Pure JavaScript SHA256 hash function that accepts and returns Uint8Array values.
 * Faster native code implementations may be available for some platforms, but this
 * implementation is pure JavaScript and should work anywhere and is provided as a
 * convenience. See {@link https://github.com/kawanet/sha256-uint8array}
 * @param data The data to hash with SHA256.
 * @returns The hash digest.
 */
export function sha256(data: Uint8Array): Uint8Array {
  return createHash().update(data).digest()
}
