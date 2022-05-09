// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { encodeHex, decodeHex, powerOfTwo, concat, compare, sha224, sha256, sha384, sha512, sha512_256, sha3_224, sha3_256, sha3_384, sha3_512 } from '../src/modules/utils';
import { Tree, treeDataHasExpectedLength, resolveHashNameOrFunction } from '../src/modules/tree';
import { getRandomBytes, sha224_node, sha256_node, sha384_node, sha512_node } from './helpers';

describe('encodeHex', () => {
  test('should return the expected hex string', () => {
    const expected = '000102030405060708090a0b0c0d0e0f'
    const buf = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    expect(encodeHex(buf)).toBe(expected);
  });
})

describe('decodeHex', () => {
  test('should return the expected Uint8Array', () => {
    const expected = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    const decoded = decodeHex('000102030405060708090a0b0c0d0e0f')
    expect(compare(expected, decoded)).toBeTruthy();
  });
})

describe('powerOfTwo', () => {
  test('should return expected values', () => {
    expect(powerOfTwo(0)).toBeFalsy();
    expect(powerOfTwo(3)).toBeFalsy();
    expect(powerOfTwo(5)).toBeFalsy();
    expect(powerOfTwo(6)).toBeFalsy();
    expect(powerOfTwo(7)).toBeFalsy();
    expect(powerOfTwo(9)).toBeFalsy();

    expect(powerOfTwo(1)).toBeTruthy();
    expect(powerOfTwo(2)).toBeTruthy();
    expect(powerOfTwo(4)).toBeTruthy();
    expect(powerOfTwo(8)).toBeTruthy();
  });
})

describe('concat', () => {
  test('should return expected values', () => {
    const u1 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    const u2 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    expect(encodeHex(concat(u1, u2))).toBe('000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f');
  });
});

describe('compare', () => {
  test('should return true if matching', () => {
    const u1 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    const u2 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    expect(compare(u1, u2)).toBeTruthy();
  });

  test('should return false if not matching', () => {
    const u1 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    const u2 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    expect(compare(u1, u2)).toBeFalsy();
  });
});

describe('treeDataHasExpectedLength', () => {
  test('should return nothing if run cleanly', () => {
    const data = [new Uint8Array(getRandomBytes(32)), new Uint8Array(getRandomBytes(32)), new Uint8Array(getRandomBytes(32)), new Uint8Array(getRandomBytes(32))]
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

describe('hash functions', () => {
  test('sha256 should return same value as Node.js crypto', () => {
    const ARRAY_LENGTH = 1_000
    const randomValues = Array.from(Array(ARRAY_LENGTH)).map(() => getRandomBytes(32))

    for (const value of randomValues) {
      expect(sha256(value)).toEqual(new Uint8Array(sha256_node(value).buffer));
    }
  });

  test('Node.js hash functions should function roundtrip', () => {
    const hashFunctions = [
      sha224_node,
      sha256_node,
      sha384_node,
      sha512_node,
    ]

    for (const hashFunction of hashFunctions) {
      const hash = hashFunction(new Uint8Array(getRandomBytes(32)))
      const data = [hash, hash]
      const tree = new Tree(data, hashFunction);
      expect(Tree.verify(tree.root(), tree.proofObject(data[0]), data[0], hashFunction)).toBeTruthy();
    }
  });

  test('defined hash functions should function roundtrip', () => {
    const hashFunctions = [
      sha224,
      sha256,
      sha384,
      sha512,
      sha512_256,
      sha3_224,
      sha3_256,
      sha3_384,
      sha3_512
    ]

    for (const hashFunction of hashFunctions) {
      const hash = hashFunction(new Uint8Array(getRandomBytes(32)))
      const data = [hash, hash]
      const tree = new Tree(data, hashFunction);
      expect(Tree.verify(tree.root(), tree.proofObject(data[0]), data[0], hashFunction)).toBeTruthy();
    }
  });

  test('defined hash function string names should function roundtrip', () => {
    const hashFunctionNames = [
      'sha224',
      'sha256',
      'sha384',
      'sha512',
      'sha512_256',
      'sha3_224',
      'sha3_256',
      'sha3_384',
      'sha3_512'
    ]

    for (const hashFunctionName of hashFunctionNames) {
      const resolvedHash = resolveHashNameOrFunction(hashFunctionName)

      const hash = resolvedHash.fn(new Uint8Array(getRandomBytes(32).buffer))
      const data = [hash, hash]
      const tree = new Tree(data, resolvedHash.name);
      expect(Tree.verify(tree.root(), tree.proofObject(data[0]), data[0])).toBeTruthy();
    }
  });
});
