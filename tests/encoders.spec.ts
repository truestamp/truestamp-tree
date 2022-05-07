// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { randomBytes } from 'crypto'
import { Tree } from '../src/modules/tree'
import { ProofHexStruct, ProofObject, ProofObjectStruct } from '../src/modules/types'
import { encodeHex, sha256, sha512 } from '../src/modules/utils'
import { assert } from 'superstruct'

describe('proofToHex and hexToProof roundtrip', () => {
  test('should encode/decode verifiable sha256 hex proofs', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 16; i++) {
      data.push(randomBytes(32))
    }

    const tree = new Tree(data, sha256)

    // get the proof for the data at the chosen index
    for (let i = 0; i < data.length; i++) {
      const hexProof = tree.proofHex(data[i])
      expect(typeof hexProof).toEqual('string')
      expect(hexProof).toMatch(/^[0-9a-f]+$/)
      expect(Tree.verify(tree.root(), hexProof, data[i], sha256)).toBeTruthy()
      expect(assert(hexProof, ProofHexStruct)).toBeUndefined()
    }
  })

  test('should encode/decode verifiable sha512 hex proofs', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 16; i++) {
      data.push(randomBytes(64))
    }

    const tree = new Tree(data, sha512)

    // get the proof for the data at the chosen index
    for (let i = 0; i < data.length; i++) {
      const hexProof = tree.proofHex(data[i])
      expect(typeof hexProof).toEqual('string')
      expect(hexProof).toMatch(/^[0-9a-f]+$/)
      expect(Tree.verify(tree.root(), hexProof, data[i], sha512)).toBeTruthy()
      expect(assert(hexProof, ProofHexStruct)).toBeUndefined()
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
    const objProof = tree.proofObject(data[4])

    // manipulate the proof
    objProof.p[2] = [0, encodeHex(randomBytes(20))] // change the hash length

    const t = () => {
      Tree.verify(tree.root(), objProof, data[4], sha256)
    }

    expect(t).toThrow(Error)
    expect(t).toThrow('all object proof hashes must be the same length')
  })

  test('should encode/decode verifiable sha256 object proofs', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 16; i++) {
      data.push(randomBytes(32))
    }

    const tree = new Tree(data, sha256)

    // get the proof for the data at the chosen index
    for (let i = 0; i < data.length; i++) {
      const objProof: ProofObject = tree.proofObject(data[i])
      expect(typeof objProof).toEqual('object')
      expect(Tree.verify(tree.root(), objProof, data[i], sha256)).toBeTruthy()
      expect(assert(objProof, ProofObjectStruct)).toBeUndefined()
    }
  })

  test('should encode/decode verifiable sha512 object proofs', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 16; i++) {
      data.push(randomBytes(64))
    }

    const tree = new Tree(data, sha512)

    // get the proof for the data at the chosen index
    for (let i = 0; i < data.length; i++) {
      const objProof: ProofObject = tree.proofObject(data[i])
      expect(typeof objProof).toEqual('object')
      expect(Tree.verify(tree.root(), objProof, data[i], sha512)).toBeTruthy()
      expect(assert(objProof, ProofObjectStruct)).toBeUndefined()
    }
  })
})
