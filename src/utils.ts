// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { TreeData, TreeHashFunction } from './types'

// Pre-computed conversion array
// See : https://stackoverflow.com/questions/40031688/javascript-arraybuffer-to-hex
const byteToHex: string[] = []
for (let n = 0; n <= 0xff; n++) {
  const hexOctet = n.toString(16).padStart(2, '0')
  byteToHex.push(hexOctet)
}

//** 0x00 byte prefix applied to leaf nodes */
export const LEAF_NODE_PREFIX: Uint8Array = new Uint8Array([0])
//** 0x01 byte prefix applied to inner nodes */
export const INNER_NODE_PREFIX: Uint8Array = new Uint8Array([1])

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
  // return new Uint8Array(hexString.split(separator).map(b => parseInt(b, 16)))
  const length = s.length
  const arrayBuffer = new Uint8Array(length / 2)
  for (let i = 0; i < length; i += 2) {
    arrayBuffer[i / 2] = parseInt(s.substr(i, 2), 16)
  }
  return arrayBuffer
}

/**
 * Encodes a Uint8Array to Hex encoded string.
 * @param u Uint8Array to encode.
 * @returns HEX encoded Uint8Array string.
 */
export function encodeHex(u: Uint8Array): string {
  const buff = new Uint8Array(u)
  const hexOctets: string[] = []

  for (let i = 0; i < buff.length; i++) {
    hexOctets.push(byteToHex[buff[i]])
  }

  return hexOctets.join('')
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
 * Validate that each entry in a TreeData has a length that matches the hash function output length.
 * @hidden
 * @param data The TreeData array.
 * @param length The tested length of the hash function output.
 */
export function treeDataHasExpectedLength(
  data: TreeData,
  length: number,
): void {
  for (const d of data) {
    if (d.length !== length) {
      throw new Error(
        "argument 'data' array contains items that don't match the hash function output length",
      )
    }
  }
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
