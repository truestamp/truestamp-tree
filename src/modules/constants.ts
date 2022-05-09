// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

/**
 * 0x00 byte prefix applied to leaf nodes
 * @ignore
 * */
export const LEAF_NODE_PREFIX: Uint8Array = new Uint8Array([0])

/**
 *  0x01 byte prefix applied to inner nodes
 * @ignore
 * */
export const INNER_NODE_PREFIX: Uint8Array = new Uint8Array([1])

/**
 *  The names of the built-in hash functions supported by the library.
 * @ignore
 * */
export const HASH_FUNCTION_NAMES: string[] = [
  'sha224',
  'sha256',
  'sha384',
  'sha512',
  'sha512_256',
  'sha3_224',
  'sha3_256',
  'sha3_384',
  'sha3_512',
]
