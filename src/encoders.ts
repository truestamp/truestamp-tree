// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { assert } from 'superstruct'
import { encodeHex, decodeHex } from '../src/utils'
import {
  ProofHexStruct,
  ProofHex,
  ProofObjectStruct,
  ProofObject,
  ProofLayer,
} from './types'

/**
 * Encode a Uint8Array proof to a Hex string.
 * @ignore
 * @param proof The proof to encode.
 * @return The encoded proof value.
 */
export function proofToHex(proof: Uint8Array): ProofHex {
  const proofHex = encodeHex(proof)
  assert(proofHex, ProofHexStruct)
  return proofHex
}

/**
 * Decode a Hex proof to a Uint8Array.
 * @ignore
 * @param proofHex The proof to encode.
 * @return The encoded proof value.
 */
export function hexToProof(proofHex: ProofHex): Uint8Array {
  assert(proofHex, ProofHexStruct)
  return decodeHex(proofHex)
}

/**
 * Encode a Uint8Array proof to an Object.
 * @ignore
 * @param proof The proof to encode.
 * @return The encoded proof value.
 */
export function proofToObject(
  proof: Uint8Array,
  layerHashLen: number,
): ProofObject {
  const layerHashLengthPlusOne: number = layerHashLen + 1
  const proofLength: number = proof.byteLength
  const proofLayers: ProofLayer[] = []

  for (let i = 0; i < proofLength; i += layerHashLengthPlusOne) {
    const order: Uint8Array = proof.subarray(i, i + 1)
    const hash: Uint8Array = proof.subarray(i + 1, i + layerHashLengthPlusOne)
    proofLayers.push([parseInt(encodeHex(order), 16), encodeHex(hash)])
  }

  const proofObj: ProofObject = { v: 1, p: proofLayers }
  assert(proofObj, ProofObjectStruct)
  return proofObj
}

/**
 * Decode an Object proof to a Uint8Array.
 * @ignore
 * @param proofObj The proof to encode.
 * @return The encoded proof value.
 */
export function objectToProof(proofObj: ProofObject): Uint8Array {
  assert(proofObj, ProofObjectStruct)

  const firstProofLayerHashByteLen = proofObj.p[0][1].length / 2

  // FIXME : can this check be done in superstruct which we assert above?
  // Confirm that all proof layers have the same length hash
  for (const layer of proofObj.p) {
    if (layer[1].length / 2 !== firstProofLayerHashByteLen) {
      throw new Error('all object proof hashes must be the same length')
    }
  }

  const proofLayers = proofObj.p

  // Allocate a buffer to hold the full length proof
  const proof = new Uint8Array(
    proofLayers.length * (1 + firstProofLayerHashByteLen),
  )

  for (let i = 0; i < proofLayers.length; i++) {
    const [order, hash] = proofLayers[i]
    proof[i * (1 + firstProofLayerHashByteLen)] = order
    proof.set(decodeHex(hash), i * (1 + firstProofLayerHashByteLen) + 1)
  }

  return proof
}
