// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { z } from 'zod'

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

/**
 * Defines the shape of a Uint8Array Merkle root hash.
 * */
export const MerkleRoot = z
  .instanceof(Uint8Array)
  .refine(val => val.length >= 20 && val.length <= 64, {
    message:
      'Merkle root must be a Uint8Array with length between 20 and 64 bytes',
  })

export type MerkleRoot = z.infer<typeof MerkleRoot>

/**
 * Defines the shape of a Uint8Array inclusion proof.
 * */
export const ProofBinary = z
  .instanceof(Uint8Array)
  .refine(val => val.length <= 1024 * 1024, {
    message:
      'Binary inclusion proof must be a Uint8Array with length <= 1,048,576 bytes',
  })

export type ProofBinary = z.infer<typeof ProofBinary>

/**
 * The type that defines the expected shape of user provided Tree hash function.
 * */
export const HashFunction = z
  .function()
  .args(z.instanceof(Uint8Array))
  .returns(z.instanceof(Uint8Array))

export type HashFunction = z.infer<typeof HashFunction>

/**
 * The type that defines the expected shape of user provided hash function names.
 * */
export const TreeHashFunctionName = z
  .string()
  .refine(val => HASH_FUNCTION_NAMES.includes(val), {
    message: `Tree hash function name must be one of the following: ${HASH_FUNCTION_NAMES.join(
      ',',
    )}`,
  })

export type TreeHashFunctionName = z.infer<typeof TreeHashFunctionName>

/**
 * Defines the shape of user provided tree data.
 * */
export const TreeData = z.array(z.instanceof(Uint8Array)).min(1)

export type TreeData = z.infer<typeof TreeData>

/**
 * Defines the shape of user provided tree configuration.
 * */
export const TreeOptions = z.object({
  requireBalanced: z.optional(z.boolean()),
  debug: z.optional(z.boolean()),
})

export type TreeOptions = z.infer<typeof TreeOptions>

/**
 * Defines the shape of a Hex encoded inclusion proof.
 * */
export const ProofHex = z.string().regex(REGEX_HASH_HEX)

export type ProofHex = z.infer<typeof ProofHex>

/**
 * Defines the shape of one layer of an Object encoded inclusion proof.
 * */
export const ProofObjectLayer = z.tuple([
  z.number().int().min(0).max(1),
  z.string().regex(REGEX_HASH_HEX_20_64),
])

export type ProofObjectLayer = z.infer<typeof ProofObjectLayer>

export const ProofHashTypeEnum = z.enum([
  'sha224',
  'sha256',
  'sha384',
  'sha512',
  'sha512_256',
  'sha3_224',
  'sha3_256',
  'sha3_384',
  'sha3_512',
])

export type ProofHashTypeEnum = z.infer<typeof ProofHashTypeEnum>

/**
 * Defines the shape of an Object encoded inclusion proof.
 * v : version number
 * h : hash function
 * p : proof
 * */
export const ProofObject = z.object({
  v: z.number().int().min(1).max(1),
  h: ProofHashTypeEnum,
  p: z.array(ProofObjectLayer),
})

export type ProofObject = z.infer<typeof ProofObject>

/**
 * Defines the internal structure of a tree.
 * */
export const TreeTree = z.array(z.array(z.instanceof(Uint8Array)))

export type TreeTree = z.infer<typeof TreeTree>

export const ResolvedHashName = z.object({
  name: z.string(),
  length: z.number().int().min(20).max(64),
  fn: HashFunction,
})

export type ResolvedHashName = z.infer<typeof ResolvedHashName>
