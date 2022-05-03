// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import {
  array,
  boolean,
  enums,
  instance,
  nonempty,
  object,
  pattern,
  size,
  string,
  tuple,
  number,
  Infer,
} from 'superstruct'

// SHA-1 -> 20 bytes
// SHA-256 -> 32 bytes
// SHA-384 -> 48 bytes
// SHA-512 -> 64 bytes
const REGEX_HASH_HEX_20_64 = /^(([a-f0-9]{2}){20,64})$/i

const REGEX_HASH_HEX = /^(([a-f0-9]{2})+)$/i

// FIXME : possible to define a function that takes a certain arg using SuperStruct?
export type TreeHashFunction = (input: Uint8Array) => Uint8Array

//** @ignore */
export const TreeDataStruct = nonempty(array(instance(Uint8Array)))
export type TreeData = Infer<typeof TreeDataStruct>

//** @ignore */
export const TreeTreeStruct = array(array(instance(Uint8Array)))
export type TreeTree = Infer<typeof TreeTreeStruct>

//** @ignore */
export const TreeOptionsStruct = object({
  requireBalanced: boolean(),
})

export type TreeOptions = Infer<typeof TreeOptionsStruct>

//** @ignore */
export const ProofHexStruct = pattern(string(), REGEX_HASH_HEX)

export type ProofHex = Infer<typeof ProofHexStruct>

//** @ignore */
export const ProofLayerStruct = tuple([
  size(number(), 0, 1), // 0 : left, 1 : right
  pattern(string(), REGEX_HASH_HEX_20_64),
])

export type ProofLayer = Infer<typeof ProofLayerStruct>

//** @ignore */
export const ProofObjectStruct = object({
  v: enums([1]), // version : only version 1 is supported now
  p: array(ProofLayerStruct),
})

export type ProofObject = Infer<typeof ProofObjectStruct>
