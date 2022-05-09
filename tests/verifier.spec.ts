// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { Tree } from '../src/modules/tree'
import { powerOfTwo } from '../src/modules/utils'
import { sliceElement, getRandomData } from './helpers'

describe('verify', () => {
  test('should return true for every proof in an unbalanced tree', () => {
    const data = getRandomData(3, 32)
    expect(powerOfTwo(data.length)).toBeFalsy()

    const tree = new Tree(data)

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, 'sha256'),
      ).toBeTruthy()
    }
  })

  test('should return true for every proof in a balanced tree', () => {
    const data = getRandomData(8, 32)
    expect(powerOfTwo(data.length)).toBeTruthy()

    const tree = new Tree(data, 'sha256', { requireBalanced: true })

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, 'sha256'),
      ).toBeTruthy()
    }
  })

  test('should return true for every proof in an unbalanced sha256 tree', () => {
    const data = getRandomData(3, 32)
    expect(powerOfTwo(data.length)).toBeFalsy()

    const tree = new Tree(data)

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, 'sha256'),
      ).toBeTruthy()
    }
  })

  test('should return true for every proof in a balanced sha256 tree', () => {
    const data = getRandomData(8, 32)
    expect(powerOfTwo(data.length)).toBeTruthy()

    const tree = new Tree(data, 'sha256', { requireBalanced: true })

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), tree.proof(d), d, 'sha256'),
      ).toBeTruthy()
    }
  })

  test('should return false if the intermediate hash in a proof is not the correct length', () => {
    const data = getRandomData(8, 32)

    const tree = new Tree(data, 'sha256', { requireBalanced: true })

    for (const d of data) {
      expect(
        Tree.verify(tree.root(), sliceElement(tree.proof(d), 64), d, 'sha256'),
      ).toBeFalsy()
    }
  })
})
