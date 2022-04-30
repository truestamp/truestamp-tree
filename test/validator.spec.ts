// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { randomBytes } from 'crypto'
import { Tree } from '../src/tree'
import { sha1, sha256 } from './helpers'
import { validate } from '../src/validator'

describe('validate', () => {
  test('should return true for every proof in an unbalanced sha1 tree', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 3; ++i) {
      data.push(randomBytes(20))
    }

    const tree = new Tree(data, sha1)

    for (const d of data) {
      expect(
        validate(tree.root(), tree.proof(d), d, sha1),
      ).toBeTruthy()
    }
  })

  test('should return true for every proof in a balanced sha1 tree', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 16; ++i) {
      data.push(randomBytes(20))
    }

    const tree = new Tree(data, sha1, { requireBalanced: true })

    for (const d of data) {
      expect(
        validate(tree.root(), tree.proof(d), d, sha1),
      ).toBeTruthy()
    }
  })

  test('should return true for every proof in an unbalanced sha256 tree', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 3; ++i) {
      data.push(randomBytes(32))
    }

    const tree = new Tree(data, sha256)

    for (const d of data) {
      expect(
        validate(tree.root(), tree.proof(d), d, sha256),
      ).toBeTruthy()
    }
  })

  test('should return true for every proof in a balanced sha256 tree', () => {
    const data: Buffer[] = []
    for (let i = 0; i < 16; ++i) {
      data.push(randomBytes(32))
    }

    const tree = new Tree(data, sha256, { requireBalanced: true })

    for (const d of data) {
      expect(
        validate(tree.root(), tree.proof(d), d, sha256),
      ).toBeTruthy()
    }
  })
})
