// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { Tree } from '../src/modules/tree'
import { sha256 } from '../src/modules/utils'
import { sliceElement, getRandomBytes } from './helpers'

describe('verify', () => {
  test('should return true for every proof in an unbalanced sha1 tree', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 3; ++i) { // unbalanced
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256)

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, sha256),
      ).toBeTruthy()
    }
  })

  test('should return true for every proof in a balanced sha1 tree', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 16; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256, { requireBalanced: true })

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, sha256),
      ).toBeTruthy()
    }
  })

  test('should return true for every proof in an unbalanced sha256 tree', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 3; ++i) { // unbalanced
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256)

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, sha256),
      ).toBeTruthy()
    }
  })

  test('should return true for every proof in a balanced sha256 tree', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 16; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256, { requireBalanced: true })

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, sha256),
      ).toBeTruthy()
    }
  })

  test('should return false if the intermediate hash in a proof is not the correct length', () => {
    const data: Uint8Array[] = []
    for (let i = 0; i < 16; ++i) {
      data.push(getRandomBytes(32))
    }

    const tree = new Tree(data, sha256, { requireBalanced: true })

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), sliceElement(tree.proof(d), 64), d, sha256),
      ).toBeFalsy()
    }
  })
})
