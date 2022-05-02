// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { TreeHashFunction } from './types'
import {
  compare,
  concat,
  validateHashFunction,
  LEAF_NODE_PREFIX,
  INNER_NODE_PREFIX,
} from '../src/utils'

/**
 * @ignore
 * See instead {@link Tree.validate} which wraps this function.
 */
export function validate(
  root: Uint8Array,
  proof: Uint8Array,
  data: Uint8Array,
  hashFunction: TreeHashFunction,
): boolean {
  const hashFuncOutLen = validateHashFunction(hashFunction)

  // Single item trees return a root that is the same
  // as the data provided and an empty proof.
  if (compare(root, data) && proof.length === 0) {
    return true
  }

  // The data input length must be the same as the hash function output length
  if (data.length !== hashFuncOutLen) {
    return false
  }

  // The length of the data plus a '0' or '1' byte to indicate the direction
  const intermediateStepLen = data.length + 1

  // The proof length must be divisible by the proofStepLen
  if (proof.length % intermediateStepLen !== 0) {
    return false
  }

  // For each intermediate step of the proof, the first byte must be 0 or 1
  // indicating the direction of the proof concatenation, and the remaining bytes
  // must be a valid hash of the data. This direction is used to determine
  // if the hash is concatenated on the left or right of the original data.
  // All intermediate hashes will be concatenated with the 'data' input
  // which serves as the foundation of the proof.
  for (let i = 0; i < proof.length; i += intermediateStepLen) {
    const intermediateHash: Uint8Array = proof.subarray(
      i + 1,
      i + intermediateStepLen,
    )

    // Each intermediateHash must be the same length as the hash function output
    if (intermediateHash.length !== hashFuncOutLen) {
      return false
    }
    // Choose the prefix to prepend to the data when hashing
    // to prevent second pre-image attacks. The first, or leaf,
    // gets a `0x00` prefix, and the remaining, or inner, nodes
    // get a `0x01` prefix.
    const prefix: Uint8Array = i === 0 ? LEAF_NODE_PREFIX : INNER_NODE_PREFIX

    // left or right concatenate the data and the intermediateHash
    // and hash the result, always building on the previous value
    // of data.
    data = hashFunction(
      proof[i]
        ? concat(prefix, concat(intermediateHash, data))
        : concat(prefix, concat(data, intermediateHash)),
    )
  }

  // The final hash must be equal to the root
  return compare(root, data)
}
