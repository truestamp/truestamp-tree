// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { encodeHex, decodeHex, powerOfTwo, concat, compare } from '../src/modules/utils';
import { Tree, resolveHashName } from '../src/modules/tree';
import { getRandomData } from './helpers';

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

describe('resolveHashName', () => {
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
      const resolvedHash = resolveHashName(hashFunctionName)

      const data = getRandomData(8, resolvedHash.length)

      const tree = new Tree(data, resolvedHash.name);
      expect(Tree.verify(tree.root(), tree.proofObject(data[0]), data[0])).toBeTruthy();
    }
  });

  test('should throw if provided w/ undefined arg', () => {
    const t = () => {
      // @ts-ignore-next-line
      resolveHashName(undefined)
    }

    expect(t).toThrow(Error)
    expect(t).toThrow("invalid hash function name: 'undefined'")
  })

  test('should throw if provided w/ invalid arg', () => {
    const t = () => {
      // @ts-ignore-next-line
      resolveHashName('foohash-256')
    }

    expect(t).toThrow(Error)
    expect(t).toThrow("invalid hash function name: 'foohash-256'")
  })

});
