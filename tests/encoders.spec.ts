// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { randomBytes } from 'crypto'
import { proofToHex, hexToProof, proofToObject, objectToProof } from '../src/encoders'
import { Tree } from '../src/tree'
import { sha1, sha256 } from './helpers'
import { verify } from '../src/verifier'
import { ProofObject, ProofObjectStruct, TreeHashFunction } from '../src/types'
import { encodeHex } from '../src/utils'

describe('proofToHex and hexToProof roundtrip', () => {
  test('should encode/decode verifiable sha1 hex proofs', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 16; i++) {
      data.push(randomBytes(20))
    }

    const tree = new Tree(data, sha1)

    // get the proof for the data at the chosen index
    for (let i = 0; i < data.length; i++) {
      const proof = tree.proof(data[i])
      const hexProof = proofToHex(proof)
      expect(typeof hexProof).toEqual('string')
      expect(hexProof).toMatch(/^[0-9a-f]+$/)
      expect(verify(tree.root(), hexToProof(hexProof), data[i], sha1)).toBeTruthy()
    }
  })

  test('should encode/decode verifiable sha256 hex proofs', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 16; i++) {
      data.push(randomBytes(32))
    }

    const tree = new Tree(data, sha256)

    // get the proof for the data at the chosen index
    for (let i = 0; i < data.length; i++) {
      const proof = tree.proof(data[i])
      const hexProof = proofToHex(proof)
      expect(typeof hexProof).toEqual('string')
      expect(hexProof).toMatch(/^[0-9a-f]+$/)
      expect(verify(tree.root(), hexToProof(hexProof), data[i], sha256)).toBeTruthy()
    }
  })
})

describe('proofToObject and objectToProof roundtrip', () => {
  test('should throw if the any proof hashes are of different length', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 10; ++i) {
      data.push(randomBytes(32))
    }

    const tree = new Tree(data, sha256)
    const proof = tree.proofObject(data[4])

    // manipulate the proof
    proof.p[2] = [0, encodeHex(randomBytes(20))] // change the hash length

    const t = () => {
      verify(tree.root(), objectToProof(proof), data[4], sha256)
    }

    expect(t).toThrow(Error)
    expect(t).toThrow('all object proof hashes must be the same length')
  })

  test('should encode/decode verifiable sha1 object proofs', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 16; i++) {
      data.push(randomBytes(20))
    }

    const tree = new Tree(data, sha1)

    // get the proof for the data at the chosen index
    for (let i = 0; i < data.length; i++) {
      const proof = tree.proof(data[i])
      const objProof: ProofObject = proofToObject(proof, 20)
      expect(typeof objProof).toEqual('object')
      expect(verify(tree.root(), objectToProof(objProof), data[i], sha1)).toBeTruthy()
    }
  })

  test('should encode/decode verifiable sha256 object proofs', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 16; i++) {
      data.push(randomBytes(32))
    }

    const tree = new Tree(data, sha256)

    // get the proof for the data at the chosen index
    for (let i = 0; i < data.length; i++) {
      const proof = tree.proof(data[i])
      const objProof: ProofObject = proofToObject(proof, 32)
      expect(typeof objProof).toEqual('object')
      expect(verify(tree.root(), objectToProof(objProof), data[i], sha256)).toBeTruthy()
    }
  })
})
