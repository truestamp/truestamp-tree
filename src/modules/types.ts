// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import {
  array,
  boolean,
  enums,
  instance,
  nonempty,
  object,
  optional,
  pattern,
  size,
  string,
  tuple,
  number,
  Infer,
} from 'superstruct'

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
 * The type that defines the expected shape of user provided Tree hash function.
 * */
export type TreeHashFunction = (input: Uint8Array) => Uint8Array

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
export const ProofLayerStruct = tuple([
  size(number(), 0, 1), // 0 : left, 1 : right
  pattern(string(), REGEX_HASH_HEX_20_64),
])

/**
 * The inferred type that defines the shape of one layer of an Object encoded inclusion proof.
 * */
export type ProofLayer = Infer<typeof ProofLayerStruct>

/**
 * The struct that defines the shape of an Object encoded inclusion proof.
 * */
export const ProofObjectStruct = object({
  v: enums([1]), // version : only version 1 is supported now
  p: array(ProofLayerStruct),
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
