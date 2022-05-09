// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { Tree } from '../src/modules/tree'
import { sha256 } from '../src/modules/utils'
import { getRandomBytes, sliceElement, sha1_node } from './helpers'
import { ProofHexStruct, ProofObjectStruct } from '../src/modules/types'
import { assert } from 'superstruct'

describe('should pass ported tape test', () => {
  test('binary 1', () => {
    const d = getRandomBytes(20)
    const tree = new Tree([d], sha1_node)
    expect(tree.root()).toEqual(d)
    expect(tree.proof(d).length).toEqual(0)
    expect(Tree.verify(d, new Uint8Array(0), d, sha1_node)).toBeTruthy()
    expect(Tree.verify(d, new Uint8Array(1), d, sha1_node)).toBeFalsy()
  })

  test('binary 2', () => {
    const d1 = Buffer.from('73b824aa6091c14ce5d72d17b4e84317afba4cee', 'hex')
    const d2 = Buffer.from('93158d5aa8dda6d8fe8db6b3c80448312c4ed52c', 'hex')
    const root = Buffer.from('098e44f5b2e46f815d9c53cb6acce5638bf23fa1', 'hex')
    const proof1 = Buffer.from(
      '0093158d5aa8dda6d8fe8db6b3c80448312c4ed52c',
      'hex',
    )
    const proof2 = Buffer.from(
      '0173b824aa6091c14ce5d72d17b4e84317afba4cee',
      'hex',
    )
    const tree = new Tree([d1, d2], sha1_node)

    expect(tree.root().join(',')).toEqual(root.join(','))
    expect(tree.proof(d1).join(',')).toEqual(proof1.join(','))
    expect(tree.proof(d2).join(',')).toEqual(proof2.join(','))

    expect(Tree.verify(root, proof1, d1, sha1_node)).toBeTruthy()
    expect(Tree.verify(root, proof2, d2, sha1_node)).toBeTruthy()

    expect(Tree.verify(root, proof2, d1, sha1_node)).toBeFalsy()
    expect(Tree.verify(root, proof1, d2, sha1_node)).toBeFalsy()
  })

  test('binary 3', () => {
    const d1 = new Uint8Array(Buffer.from('8f86ba7f7481fa30716b0bc5b37650bdf4999204', 'hex'))
    const d2 = new Uint8Array(Buffer.from('025e1d661e91e1c55ce9091c89512d97251c7b61', 'hex'))
    const d3 = new Uint8Array(Buffer.from('bbed8ca2b401f13ab821d4f24f58a39bdabcd683', 'hex'))
    const root = new Uint8Array(Buffer.from('3516118752e9aa5490fbbbb0e104bd7ebd12845e', 'hex'))
    const proof1 = new Uint8Array(Buffer.from(
      '00025e1d661e91e1c55ce9091c89512d97251c7b610027bbaac2c45f74217aa3d5bb78bc891347cb954c',
      'hex',
    ))
    const proof2 = new Uint8Array(Buffer.from(
      '018f86ba7f7481fa30716b0bc5b37650bdf49992040027bbaac2c45f74217aa3d5bb78bc891347cb954c',
      'hex',
    ))
    const proof3 = new Uint8Array(Buffer.from(
      '00bbed8ca2b401f13ab821d4f24f58a39bdabcd68301ddd5541102a1379a24bed37b5e1aa9b91dcebd04',
      'hex',
    ))
    const tree = new Tree([d1, d2, d3], sha1_node)

    expect(tree.root()).toEqual(root)
    expect(tree.proof(d1).join(',')).toEqual(proof1.join(','))
    expect(tree.proof(d2).join(',')).toEqual(proof2.join(','))
    expect(tree.proof(d3).join(',')).toEqual(proof3.join(','))

    expect(Tree.verify(root, proof1, d1, sha1_node)).toBeTruthy()
    expect(Tree.verify(root, proof2, d2, sha1_node)).toBeTruthy()
    expect(Tree.verify(root, proof3, d3, sha1_node)).toBeTruthy()

    expect(Tree.verify(root, proof3, d1, sha1_node)).toBeFalsy()
    expect(Tree.verify(root, proof2, d3, sha1_node)).toBeFalsy()
    expect(Tree.verify(root, proof1, d2, sha1_node)).toBeFalsy()
  })

  test('binary 4', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 16; ++i) {
      data.push(getRandomBytes(20))
    }

    const tree = new Tree(data, sha1_node, { requireBalanced: false })

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, sha1_node),
      ).toBeTruthy()
    }
  })
})

describe('Tree', () => {
  test('should be usable with sha256 hash function', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 16; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256)

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, sha256),
      ).toBeTruthy()
    }
  })

  test('should throw if initialized with empty data array', () => {
    const t = () => {
      const tree = new Tree([], sha256)
    }

    expect(t).toThrow(Error)
    expect(t).toThrow("Expected a nonempty array but received an empty one")
  })

  test('should accept a data array with length 1', () => {
    const data = [getRandomBytes(32)]
    const tree = new Tree(data, sha256)

    // the root of a single node tree is the data itself
    expect(tree.root()).toEqual(data[0])
    // the proof of a single node tree is an empty array
    expect(tree.proof(data[0])).toEqual(new Uint8Array(0))
    expect(
      Tree.verify(tree.root(), tree.proof(data[0]), data[0], sha256),
    ).toBeTruthy()

  })

  describe('with {requiresBalancedTree: false}', () => {

    test('should accept a data array with length 2', () => {
      const data = [getRandomBytes(32), getRandomBytes(32)]
      const tree = new Tree(data, sha256, { requireBalanced: false, debug: false })

      for (const d of data) {
        expect(
          Tree.verify(tree.root(), tree.proof(d), d, sha256),
        ).toBeTruthy()
      }
    })
  })

  describe('with {requiresBalancedTree: true}', () => {
    test('should accept a data array with length 2', () => {
      const data = [getRandomBytes(32), getRandomBytes(32)]
      const tree = new Tree(data, sha256, { requireBalanced: true })

      for (const d of data) {
        expect(
          Tree.verify(tree.root(), tree.proof(d), d, sha256),
        ).toBeTruthy()
      }
    })

    test('should throw with a data array of length 3', () => {
      const data = [getRandomBytes(32), getRandomBytes(32), getRandomBytes(32)]
      const t = () => {
        const tree = new Tree(data, sha256, { requireBalanced: true })
      }

      expect(t).toThrow(Error)
      expect(t).toThrow("argument 'data' array length must be a power of two (or set 'requireBalanced' to false)")
    })
  })
})

describe('with {debug: true}', () => {
  test('should console.debug() output with a data array with length 2', () => {
    const data = [
      getRandomBytes(32), getRandomBytes(32),
    ]
    const tree = new Tree(data, sha256, { debug: true })

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, sha256),
      ).toBeTruthy()
    }
  })
})

describe('Tree.height', () => {
  test('should return the expected height with data length == 1', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 1; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256)

    const height = tree.height()
    expect(height).toBe(Math.ceil(Math.log2(data.length)))
  })

  test('should return the expected height with balanced data length == 16', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 16; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256)

    const height = tree.height()
    expect(height).toBe(Math.ceil(Math.log2(data.length)))
  })

  test('should return the expected height with balanced data length == 1024', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 1024; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256)

    const height = tree.height()
    expect(height).toBe(Math.ceil(Math.log2(data.length)))
  })

  test('should return the expected height with unbalanced data length', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 21; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256)

    const height = tree.height()
    expect(height).toBe(Math.ceil(Math.log2(data.length)))
  })

})

describe('Tree.proof', () => {
  test('should throw if the target cannot be found', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 10; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256)

    const t = () => {
      // unknown data node
      tree.proof(getRandomBytes(32))
    }

    expect(t).toThrow(Error)
    expect(t).toThrow('proof dataItem not found')
  })

  test('should return a verifiable proof with data length == 2', () => {
    const data = [getRandomBytes(32), getRandomBytes(32)]
    const tree = new Tree(data, sha256)
    const proof = tree.proof(data[1])
    expect(proof).toBeInstanceOf(Uint8Array)
    expect(proof.length).toEqual(33)
    expect(
      Tree.verify(tree.root(), proof, data[1], sha256),
    ).toBeTruthy()
  })

  test('should return a verifiable proof with data length == 16', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 16; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256)

    const proof = tree.proof(data[1])
    expect(proof).toBeInstanceOf(Uint8Array)
    expect(
      Tree.verify(tree.root(), proof, data[1], sha256),
    ).toBeTruthy()
  })
})

describe('Tree.proofHex', () => {
  test('should throw if the target cannot be found', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 16; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256)

    const t = () => {
      // unknown data node
      tree.proofHex(getRandomBytes(32))
    }

    expect(t).toThrow(Error)
    expect(t).toThrow('proof dataItem not found')
  })

  test('should return a verifiable proof with data length == 2', () => {
    const data = [getRandomBytes(32), getRandomBytes(32)]
    const tree = new Tree(data, sha256)
    const proof = tree.proofHex(data[1])
    expect(typeof proof).toBe('string')
    expect(
      Tree.verify(tree.root(), proof, data[1], sha256),
    ).toBeTruthy()
  })

  test('should return a verifiable proof with data length == 16', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 16; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256)

    const proof = tree.proofHex(data[1])
    expect(typeof proof).toBe('string')
    expect(assert(proof, ProofHexStruct)).toBeUndefined()
    expect(
      Tree.verify(tree.root(), proof, data[1], sha256),
    ).toBeTruthy()
  })
})

describe('Tree.proofObject', () => {
  test('should throw if the target cannot be found', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 10; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256)

    const t = () => {
      // unknown data node
      tree.proofObject(getRandomBytes(32))
    }

    expect(t).toThrow(Error)
    expect(t).toThrow('proof dataItem not found')
  })

  test('should return a verifiable proof with data length == 2', () => {
    const data = [getRandomBytes(32), getRandomBytes(32)]
    const tree = new Tree(data, 'sha256')
    const proof = tree.proofObject(data[1])
    expect(typeof proof).toBe('object')
    expect(assert(proof, ProofObjectStruct)).toBeUndefined()
    expect(
      Tree.verify(tree.root(), proof, data[1], sha256),
    ).toBeTruthy()
  })

  test('should return a verifiable proof with data length == 16', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 16; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, 'sha256')

    const proof = tree.proofObject(data[1])
    expect(assert(proof, ProofObjectStruct)).toBeUndefined()
    expect(
      Tree.verify(tree.root(), proof, data[1], sha256),
    ).toBeTruthy()
  })
})

describe('Tree.verify', () => {

  test('verification should throw if the Merkle root is not a Uint8Array', () => {
    const data = [getRandomBytes(32), getRandomBytes(32)]

    const tree = new Tree(data, sha256)
    const proof = tree.proof(data[1])

    // The same, but with a good root should work.
    expect(Tree.verify(tree.root(), proof, data[1], sha256)).toBeTruthy()

    // Construct a bad root.
    const badRoot = new Uint8Array([])

    const t = () => {
      Tree.verify(badRoot, proof, data[1], sha256)
    }

    expect(t).toThrow(Error)
    expect(t).toThrow('Expected a value of type `MerkleRoot`, but received: ``')
  })


  describe('Uint8Array proof', () => {
    test('verification should throw if proof is way too large', () => {
      const badProof = new Uint8Array(getRandomBytes(1024 * 1024 + 1))
      const t = () => {
        Tree.verify(new Uint8Array(getRandomBytes(32)), badProof, new Uint8Array([0]), undefined)
      }

      expect(t).toThrow(Error)
      expect(t).toThrow('invalid or corrupted proof provided')
    })

    test('verification should throw if no hashFunction is provided', () => {
      const t = () => {
        Tree.verify(new Uint8Array(getRandomBytes(32)), new Uint8Array([0]), new Uint8Array([0]), undefined)
      }

      expect(t).toThrow(Error)
      expect(t).toThrow('Expected a value of type `HashFunction`, but received: `undefined`')
    })

    test('should not verify if any proof hashes are of the wrong length', () => {
      const data: Uint8Array[] = []
      for (let i = 0; i < 16; ++i) {
        data.push(getRandomBytes(32))
      }

      const tree = new Tree(data, sha256)
      const proof = tree.proof(data[1])
      // manipulate the proof
      const slicedProof = sliceElement(proof, 40)

      expect(
        Tree.verify(tree.root(), slicedProof, data[1], sha256),
      ).toBeFalsy()
    })

    test('should not verify if data length is not equal to hash function output length', () => {
      const data: Uint8Array[] = []
      for (let i = 0; i < 4; ++i) {
        data.push(getRandomBytes(32))
      }

      const tree = new Tree(data, sha256)
      const proof = tree.proof(data[1])
      expect(proof).toBeInstanceOf(Uint8Array)

      // manipulate the data
      const slicedData = sliceElement(data[1], 2)

      expect(
        Tree.verify(tree.root(), proof, slicedData, sha256),
      ).toBeFalsy()
    })

    test('should verify', () => {
      const data: Uint8Array[] = []
      for (let i = 0; i < 4; ++i) {
        data.push(getRandomBytes(32))
      }

      const tree = new Tree(data, sha256)

      const proof = tree.proof(data[1])
      expect(proof).toBeInstanceOf(Uint8Array)
      expect(
        Tree.verify(tree.root(), proof, data[1], sha256),
      ).toBeTruthy()
    })

  })

  describe('Hex proof', () => {

    test('verification should throw if no hashFunction is provided', () => {
      const t = () => {
        Tree.verify(new Uint8Array(getRandomBytes(32)), 'deadbeefdeadbeefdeadbeefdeadbeef', new Uint8Array([0]), undefined)
      }

      expect(t).toThrow(Error)
      expect(t).toThrow('Expected a value of type `HashFunction`, but received: `undefined`')
    })

    test('should not verify if any proof hashes are of the wrong length', () => {
      const data: Uint8Array[] = []
      for (let i = 0; i < 4; ++i) {
        data.push(getRandomBytes(32))
      }

      const tree = new Tree(data, sha256)
      const proof = tree.proofHex(data[1])

      // manipulate the proof
      const slicedProofFirstHalf = proof.substring(0, proof.length / 2)
      const slicedProofSecondHalf = proof.substring(proof.length / 2)
      const slicedProof = slicedProofFirstHalf.substring(0, slicedProofFirstHalf.length - 2) + slicedProofSecondHalf

      expect(
        Tree.verify(tree.root(), slicedProof, data[1], sha256),
      ).toBeFalsy()
    })

    test('should verify', () => {
      const data: Uint8Array[] = []
      for (let i = 0; i < 4; ++i) {
        data.push(getRandomBytes(32))
      }

      const tree = new Tree(data, sha256)

      const proofHex = tree.proofHex(data[1])
      expect(typeof proofHex).toBe('string')
      expect(assert(proofHex, ProofHexStruct)).toBeUndefined()
      expect(
        Tree.verify(tree.root(), proofHex, data[1], sha256),
      ).toBeTruthy()
    })

  })

  describe('Object proof', () => {
    test('verification should throw if unknown hashFunction is provided in object and undefined is provided as hashFunction arg', () => {
      const t = () => {
        Tree.verify(new Uint8Array(getRandomBytes(32)), { v: 1, h: 'foo', p: [[0, 'deadbeefdeadbeefdeadbeefdeadbeef']] }, new Uint8Array([0]), undefined)
      }

      expect(t).toThrow(Error)
      expect(t).toThrow('invalid or corrupted proof provided')
    })

    test('verification should throw if any proof object layer hashes are of the wrong length', () => {
      const data: Uint8Array[] = []
      for (let i = 0; i < 4; ++i) {
        data.push(getRandomBytes(32))
      }

      const tree = new Tree(data, sha256)
      const proof = tree.proofObject(data[1])

      // manipulate the proof
      proof.p[1] = [0, 'deadbeef']

      const t = () => {
        Tree.verify(tree.root(), proof, data[1], sha256)
      }

      expect(t).toThrow(Error)
      expect(t).toThrow('invalid or corrupted proof provided')
    })
  })

  test('should verify with hash function provided', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 4; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, 'sha256')

    const objProof = tree.proofObject(data[1])
    expect(assert(objProof, ProofObjectStruct)).toBeUndefined()
    expect(
      Tree.verify(tree.root(), objProof, data[1], sha256),
    ).toBeTruthy()
  })

  test('should verify without hash function provided, using named function in proof', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 4; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, 'sha256')

    const objProof = tree.proofObject(data[1])
    expect(assert(objProof, ProofObjectStruct)).toBeUndefined()
    expect(
      Tree.verify(tree.root(), objProof, data[1]),
    ).toBeTruthy()
  })

})
