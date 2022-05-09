// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import {
  array,
  boolean,
  define,
  enums,
  instance,
  nonempty,
  object,
  optional,
  pattern,
  size,
  string,
  tuple,
  union,
  number,
  Infer,
} from 'superstruct'

import isUint8Array from '@stdlib/assert/is-uint8array'
import isFunction from '@stdlib/assert/is-function'

import { HASH_FUNCTION_NAMES } from './constants'
/**
 * A regular expression the defines the shape of a valid Hex string that represents 20-64 bytes.
 * SHA-1 -> 20 bytes
 * SHA-256 -> 32 bytes
 * SHA-384 -> 48 bytes
 * SHA-512 -> 64 bytes
 * */
const REGEX_HASH_HEX_20_64 = /^(([a-f0-9]{2}){20,64})$/i

/**
 * A regular expression the defines the shape of a valid Hex string.
 * */
const REGEX_HASH_HEX = /^(([a-f0-9]{2})+)$/i

const MerkleRoot = define<Uint8Array>('MerkleRoot', (value): boolean => {
  if (!isUint8Array(value)) {
    return false
  }

  if ((value as Uint8Array).length < 20 || (value as Uint8Array).length > 64) {
    return false
  }

  return true
})

const ProofBinary = define<Uint8Array>('ProofBinary', (value): boolean => {
  if (!isUint8Array(value)) {
    return false
  }

  // Too large
  if ((value as Uint8Array).length > 1024 * 1024) {
    return false
  }

  return true
})

/**
 * The type that defines the expected shape of user provided Tree hash function.
 * */
export const HashFunctionStruct = define<(input: Uint8Array) => Uint8Array>(
  'HashFunction',
  (value): boolean => {
    if (isFunction(value)) {
      const data = new Uint8Array([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
      ])

      try {
        const func = value as (input: Uint8Array) => Uint8Array
        const hash: unknown = func(data)

        if (
          isUint8Array(hash) &&
          (hash as Uint8Array).length >= 20 &&
          (hash as Uint8Array).length <= 64
        ) {
          return true
        }

        return false
      } catch (error) {
        return false
      }
    }

    return false
  },
)

/**
 * The inferred type that defines the shape of user provided hash function.
 * */
export type HashFunction = Infer<typeof HashFunctionStruct>

/**
 * The type that defines the expected shape of user provided hash function names.
 * */
export const HashFunctionNameStruct = define<string>(
  'HashFunction',
  (value): boolean => {
    if (typeof value !== 'string') {
      return false
    }

    return HASH_FUNCTION_NAMES.includes(value)
  },
)

/**
 * The inferred type that defines the shape of known hash function names.
 * */
export type HashFunctionName = Infer<typeof HashFunctionNameStruct>

/**
 * The struct that defines the shape and expected output of a user provided hash function.
 * */
export const TreeHashNameOrFunctionStruct = union([
  HashFunctionStruct,
  HashFunctionNameStruct,
])

/**
 * The inferred type that defines the shape and expected output of a user provided hash function.
 * */
export type TreeHashNameOrFunction = Infer<typeof TreeHashNameOrFunctionStruct>

/**
 * The struct that defines the shape of user provided tree data.
 * */
export const TreeDataStruct = nonempty(array(instance(Uint8Array)))

/**
 * The inferred type that defines the shape of user provided of tree data.
 * */
export type TreeData = Infer<typeof TreeDataStruct>

/**
 * The struct that defines the shape of user provided tree configuration.
 * */
export const TreeOptionsStruct = object({
  requireBalanced: optional(boolean()),
  debug: optional(boolean()),
})

/**
 * The inferred type that defines the shape of user provided tree configuration.
 * */
export type TreeOptions = Infer<typeof TreeOptionsStruct>

/**
 * The struct that defines the shape of a Uint8Array Merkle root hash.
 * */
export const MerkleRootStruct = MerkleRoot

/**
 * The inferred type that defines the shape of a Uint8Array Merkle root hash.
 * */
export type MerkleRoot = Infer<typeof MerkleRootStruct>

/**
 * The struct that defines the shape of a Uint8Array inclusion proof.
 * */
export const ProofBinaryStruct = ProofBinary

/**
 * The inferred type that defines the shape of a Uint8Array inclusion proof.
 * */
export type ProofBinary = Infer<typeof ProofBinaryStruct>

/**
 * The struct that defines the shape of a Hex encoded inclusion proof.
 * */
export const ProofHexStruct = pattern(string(), REGEX_HASH_HEX)

/**
 * The inferred type that defines the shape of a Hex encoded inclusion proof.
 * */
export type ProofHex = Infer<typeof ProofHexStruct>

/**
 * The struct that defines the shape of one layer of an Object encoded inclusion proof.
 * */
export const ProofObjectLayerStruct = tuple([
  size(number(), 0, 1), // 0 : left, 1 : right
  pattern(string(), REGEX_HASH_HEX_20_64),
])

/**
 * The inferred type that defines the shape of one layer of an Object encoded inclusion proof.
 * */
export type ProofObjectLayer = Infer<typeof ProofObjectLayerStruct>

/**
 * The struct that defines the shape of an Object encoded inclusion proof.
 * v : version number
 * h : hash function
 * p : proof
 * */
export const ProofObjectStruct = object({
  v: enums([1]),
  h: enums(HASH_FUNCTION_NAMES),
  p: array(ProofObjectLayerStruct),
})

/**
 * The inferred type that defines the shape of an Object encoded inclusion proof.
 * */
export type ProofObject = Infer<typeof ProofObjectStruct>

/**
 * The struct that defines the internal structure of a tree.
 * @ignore
 * */
export const TreeTreeStruct = array(array(instance(Uint8Array)))

/**
 * The inferred type that defines the internal structure of a tree.
 * @ignore
 * */
export type TreeTree = Infer<typeof TreeTreeStruct>
