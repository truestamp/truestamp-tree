// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { Tree } from '../src/modules/tree'
import { ProofObject } from '../src/modules/types'
import { encodeHex } from '../src/modules/utils'
import { getRandomBytes, getRandomData } from './helpers'

describe('proofToHex and hexToProof roundtrip', () => {
  test('should encode/decode verifiable hex proofs', () => {
    const data = getRandomData(8, 32)

    const tree = new Tree(data)

    // get the proof for the data at the chosen index
    for (let i = 0; i < data.length; i++) {
      const hexProof = tree.proofHex(data[i])
      expect(typeof hexProof).toEqual('string')
      expect(hexProof).toMatch(/^[0-9a-f]+$/)
      expect(Tree.verify(tree.root(), hexProof, data[i], 'sha256')).toBeTruthy()
    }
  })
})

describe('proofToObject and objectToProof roundtrip', () => {
  test('should throw if the any proof hashes are of different length', () => {
    const data = getRandomData(8, 32)

    const tree = new Tree(data, 'sha256')
    const objProof: ProofObject = tree.proofObject(data[4])

    // manipulate the proof
    objProof.p[2] = [0, encodeHex(getRandomBytes(20))] // change the hash length

    const t = () => {
      Tree.verify(tree.root(), objProof, data[4], 'sha256')
    }

    expect(t).toThrow(Error)
    expect(t).toThrow('all object proof hashes must be the same length')
  })

  test('should encode/decode verifiable object proofs', () => {
    const data = getRandomData(8, 32)

    const tree = new Tree(data, 'sha256')

    // get the proof for the data at the chosen index
    for (let i = 0; i < data.length; i++) {
      const objProof: ProofObject = tree.proofObject(data[i])
      expect(typeof objProof).toEqual('object')
      expect(Tree.verify(tree.root(), objProof, data[i], 'sha256')).toBeTruthy()
    }
  })
})
