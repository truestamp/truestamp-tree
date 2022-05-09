// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { Tree, treeDataHasExpectedLength } from '../src/modules/tree'
import { getRandomBytes, getRandomData, sliceElement } from './helpers'
import { ProofHexStruct, ProofObjectStruct } from '../src/modules/types'
import { powerOfTwo } from '../src/modules/utils'
import { assert } from 'superstruct'

describe('Tree', () => {
  test('should be usable with default sha256 hash function', () => {
    const data = getRandomData(8, 32)

    const tree = new Tree(data)

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, 'sha256'),
      ).toBeTruthy()
    }
  })

  test('should throw if initialized with empty data array', () => {
    const t = () => {
      const tree = new Tree([])
    }

    expect(t).toThrow(Error)
    expect(t).toThrow("Expected a nonempty array but received an empty one")
  })

  test('should accept a data array with length 1', () => {
    const data = getRandomData(1, 32)
    const tree = new Tree(data)

    // the root of a single node tree is the data itself
    expect(tree.root()).toEqual(data[0])
    // the proof of a single node tree is an empty array
    expect(tree.proof(data[0])).toEqual(new Uint8Array(0))
    expect(
      Tree.verify(tree.root(), tree.proof(data[0]), data[0], 'sha256'),
    ).toBeTruthy()

  })

  describe('with {requiresBalancedTree: false}', () => {

    test('should accept a data array with length 2', () => {
      const data = getRandomData(2, 32)
      const tree = new Tree(data, 'sha256', { requireBalanced: false, debug: false })

      for (const d of data) {
        expect(
          Tree.verify(tree.root(), tree.proof(d), d, 'sha256'),
        ).toBeTruthy()
      }
    })
  })

  describe('with {requiresBalancedTree: true}', () => {
    test('should accept a data array with length 2', () => {
      const data = getRandomData(2, 32)
      expect(powerOfTwo(data.length)).toBeTruthy()

      const tree = new Tree(data, 'sha256', { requireBalanced: true })

      for (const d of data) {
        expect(
          Tree.verify(tree.root(), tree.proof(d), d, 'sha256'),
        ).toBeTruthy()
      }
    })

    test('should throw with a data array of length 3', () => {
      const data = getRandomData(3, 32)
      expect(powerOfTwo(data.length)).toBeFalsy()

      const t = () => {
        const tree = new Tree(data, 'sha256', { requireBalanced: true })
      }

      expect(t).toThrow(Error)
      expect(t).toThrow("argument 'data' array length must be a power of two (or set 'requireBalanced' to false)")
    })
  })
})

describe('with {debug: true}', () => {
  test('should console.debug() output with a data array with length 2', () => {
    const data = getRandomData(2, 32)

    const tree = new Tree(data, 'sha256', { debug: true })

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, 'sha256'),
      ).toBeTruthy()
    }
  })
})

describe('Tree.height', () => {
  test('should return the expected height with data length == 1', () => {
    const data = getRandomData(1, 32)

    const tree = new Tree(data)

    const height = tree.height()
    expect(height).toBe(Math.ceil(Math.log2(data.length)))
  })

  test('should return the expected height with balanced data length == 8', () => {
    const data = getRandomData(8, 32)

    const tree = new Tree(data)

    const height = tree.height()
    expect(height).toBe(Math.ceil(Math.log2(data.length)))
  })

  test('should return the expected height with balanced data length == 1024', () => {
    const data = getRandomData(1024, 32)

    const tree = new Tree(data)

    const height = tree.height()
    expect(height).toBe(Math.ceil(Math.log2(data.length)))
  })

  test('should return the expected height with unbalanced data length', () => {
    const data = getRandomData(21, 32)
    expect(powerOfTwo(data.length)).toBeFalsy()

    const tree = new Tree(data)

    const height = tree.height()
    expect(height).toBe(Math.ceil(Math.log2(data.length)))
  })

})

describe('Tree.proof', () => {
  test('should throw if the target cannot be found', () => {
    const data = getRandomData(8, 32)

    const tree = new Tree(data)

    const t = () => {
      // unknown data node
      tree.proof(getRandomBytes(32))
    }

    expect(t).toThrow(Error)
    expect(t).toThrow('proof dataItem not found')
  })

  test('should return a verifiable proof with data length == 2', () => {
    const data = getRandomData(2, 32)
    const tree = new Tree(data)
    const proof = tree.proof(data[1])
    expect(proof).toBeInstanceOf(Uint8Array)
    expect(proof.length).toEqual(33)
    expect(
      Tree.verify(tree.root(), proof, data[1], 'sha256'),
    ).toBeTruthy()
  })

  test('should return a verifiable proof with data length == 8', () => {
    const data = getRandomData(8, 32)

    const tree = new Tree(data)

    const proof = tree.proof(data[1])
    expect(proof).toBeInstanceOf(Uint8Array)
    expect(
      Tree.verify(tree.root(), proof, data[1], 'sha256'),
    ).toBeTruthy()
  })
})

describe('Tree.proofHex', () => {
  test('should throw if the target cannot be found', () => {
    const data = getRandomData(8, 32)

    const tree = new Tree(data)

    const t = () => {
      // unknown data node
      tree.proofHex(getRandomBytes(32))
    }

    expect(t).toThrow(Error)
    expect(t).toThrow('proof dataItem not found')
  })

  test('should return a verifiable proof with data length == 2', () => {
    const data = getRandomData(2, 32)
    const tree = new Tree(data)
    const proof = tree.proofHex(data[1])
    expect(typeof proof).toBe('string')
    expect(
      Tree.verify(tree.root(), proof, data[1], 'sha256'),
    ).toBeTruthy()
  })

  test('should return a verifiable proof with data length == 8', () => {
    const data = getRandomData(8, 32)

    const tree = new Tree(data)

    const proof = tree.proofHex(data[1])
    expect(typeof proof).toBe('string')
    expect(assert(proof, ProofHexStruct)).toBeUndefined()
    expect(
      Tree.verify(tree.root(), proof, data[1], 'sha256'),
    ).toBeTruthy()
  })
})

describe('Tree.proofObject', () => {
  test('should throw if the target cannot be found', () => {
    const data = getRandomData(8, 32)

    const tree = new Tree(data)

    const t = () => {
      // unknown data node
      tree.proofObject(getRandomBytes(32))
    }

    expect(t).toThrow(Error)
    expect(t).toThrow('proof dataItem not found')
  })

  test('should return a verifiable proof with data length == 2', () => {
    const data = getRandomData(2, 32)
    const tree = new Tree(data)
    const proof = tree.proofObject(data[1])
    expect(typeof proof).toBe('object')
    expect(assert(proof, ProofObjectStruct)).toBeUndefined()
    expect(
      Tree.verify(tree.root(), proof, data[1], 'sha256'),
    ).toBeTruthy()
  })

  test('should return a verifiable proof with data length == 8', () => {
    const data = getRandomData(8, 32)

    const tree = new Tree(data)

    const proof = tree.proofObject(data[1])
    expect(assert(proof, ProofObjectStruct)).toBeUndefined()
    expect(
      Tree.verify(tree.root(), proof, data[1], 'sha256'),
    ).toBeTruthy()
  })
})

describe('Tree.verify', () => {

  test('verification should throw if the Merkle root is not a Uint8Array', () => {
    const data = getRandomData(2, 32)

    const tree = new Tree(data)
    const proof = tree.proof(data[1])

    // The same, but with a good root should work.
    expect(Tree.verify(tree.root(), proof, data[1], 'sha256')).toBeTruthy()

    // Construct a bad root.
    const badRoot = new Uint8Array([])

    const t = () => {
      Tree.verify(badRoot, proof, data[1], 'sha256')
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
      expect(t).toThrow('Expected a value of type `TreeHashFunctionName`, but received: `undefined`')
    })

    test('should not verify if any proof hashes are of the wrong length', () => {
      const data = getRandomData(8, 32)

      const tree = new Tree(data)
      const proof = tree.proof(data[1])
      // manipulate the proof
      const slicedProof = sliceElement(proof, 40)

      expect(
        Tree.verify(tree.root(), slicedProof, data[1], 'sha256'),
      ).toBeFalsy()
    })

    test('should not verify if data length is not equal to hash function output length', () => {
      const data = getRandomData(4, 32)

      const tree = new Tree(data)
      const proof = tree.proof(data[1])
      expect(proof).toBeInstanceOf(Uint8Array)

      // manipulate the data
      const slicedData = sliceElement(data[1], 2)

      expect(
        Tree.verify(tree.root(), proof, slicedData, 'sha256'),
      ).toBeFalsy()
    })

    test('should verify', () => {
      const data = getRandomData(4, 32)

      const tree = new Tree(data)

      const proof = tree.proof(data[1])
      expect(proof).toBeInstanceOf(Uint8Array)
      expect(
        Tree.verify(tree.root(), proof, data[1], 'sha256'),
      ).toBeTruthy()
    })

  })

  describe('Hex proof', () => {

    test('verification should throw if no hashFunction is provided', () => {
      const t = () => {
        Tree.verify(new Uint8Array(getRandomBytes(32)), 'deadbeefdeadbeefdeadbeefdeadbeef', new Uint8Array([0]), undefined)
      }

      expect(t).toThrow(Error)
      expect(t).toThrow('Expected a value of type `TreeHashFunctionName`, but received: `undefined`')
    })

    test('should not verify if any proof hashes are of the wrong length', () => {
      const data = getRandomData(4, 32)

      const tree = new Tree(data)
      const proof = tree.proofHex(data[1])

      // manipulate the proof
      const slicedProofFirstHalf = proof.substring(0, proof.length / 2)
      const slicedProofSecondHalf = proof.substring(proof.length / 2)
      const slicedProof = slicedProofFirstHalf.substring(0, slicedProofFirstHalf.length - 2) + slicedProofSecondHalf

      expect(
        Tree.verify(tree.root(), slicedProof, data[1], 'sha256'),
      ).toBeFalsy()
    })

    test('should verify', () => {
      const data = getRandomData(4, 32)

      const tree = new Tree(data)

      const proofHex = tree.proofHex(data[1])
      expect(typeof proofHex).toBe('string')
      expect(assert(proofHex, ProofHexStruct)).toBeUndefined()
      expect(
        Tree.verify(tree.root(), proofHex, data[1], 'sha256'),
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
      const data = getRandomData(4, 32)

      const tree = new Tree(data)
      const proof = tree.proofObject(data[1])

      // manipulate the proof
      proof.p[1] = [0, 'deadbeef']

      const t = () => {
        Tree.verify(tree.root(), proof, data[1], 'sha256')
      }

      expect(t).toThrow(Error)
      expect(t).toThrow('invalid or corrupted proof provided')
    })
  })

  test('should verify with hash function provided', () => {
    const data = getRandomData(4, 32)

    const tree = new Tree(data)

    const objProof = tree.proofObject(data[1])
    expect(assert(objProof, ProofObjectStruct)).toBeUndefined()
    expect(
      Tree.verify(tree.root(), objProof, data[1], 'sha256'),
    ).toBeTruthy()
  })

  test('should verify without hash function provided, using named function in proof', () => {
    const data = getRandomData(4, 32)

    const tree = new Tree(data, 'sha256')

    const objProof = tree.proofObject(data[1])
    expect(assert(objProof, ProofObjectStruct)).toBeUndefined()
    expect(
      Tree.verify(tree.root(), objProof, data[1]),
    ).toBeTruthy()
  })

})

describe('treeDataHasExpectedLength', () => {
  test('should return nothing if run cleanly', () => {
    const data = getRandomData(4, 32)
    expect(treeDataHasExpectedLength(data, 32)).toBeUndefined();
  });

  test('should throw if any tree data has the wrong length', () => {
    // one element is too short
    const data = [new Uint8Array(getRandomBytes(20)), new Uint8Array(getRandomBytes(32)), new Uint8Array(getRandomBytes(32)), new Uint8Array(getRandomBytes(32))]

    const t = () => {
      treeDataHasExpectedLength(data, 32);
    }

    expect(t).toThrow(Error)
    expect(t).toThrow("argument 'data' array contains items that don't match the hash function output length")

  });
});
