// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { randomBytes } from 'crypto';
import { encodeHex, decodeHex, powerOfTwo, concat, compare, treeDataHasExpectedLength, validateHashFunction } from '../src/utils';
import { sha1, sha256 } from './helpers';

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

describe('validateHashFunction', () => {
  test('should return a number if valid', () => {
    const u1 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

    expect(validateHashFunction(sha1)).toBe(20);
    expect(validateHashFunction(sha256)).toBe(32);
  });

  test('should throw if function is not a function', () => {
    const t = () => {
      // @ts-ignore
      validateHashFunction('foo');
    }

    expect(t).toThrow(Error)
    expect(t).toThrow("hashFunction must be a function")

  });

  test('should throw if function return is < 20 bytes', () => {
    const shortFunc = (d: Uint8Array): Uint8Array => {
      return new Uint8Array(randomBytes(19))
    }

    const t = () => {
      validateHashFunction(shortFunc);
    }

    expect(t).toThrow(Error)
    expect(t).toThrow("hash function must return a non-empty Uint8Array between 20 and 64 bytes long")

  });

  test('should throw if function return is > 64 bytes', () => {
    const longFunc = (d: Uint8Array): Uint8Array => {
      return new Uint8Array(randomBytes(65))
    }

    const t = () => {
      validateHashFunction(longFunc);
    }

    expect(t).toThrow(Error)
    expect(t).toThrow("hash function must return a non-empty Uint8Array between 20 and 64 bytes long")

  });

});

describe('treeDataHasExpectedLength', () => {
  test('should return nothing if run cleanly', () => {
    const data = [new Uint8Array(randomBytes(32)), new Uint8Array(randomBytes(32)), new Uint8Array(randomBytes(32)), new Uint8Array(randomBytes(32))]
    expect(treeDataHasExpectedLength(data, 32)).toBeUndefined();
  });

  test('should throw if any tree data has the wrong length', () => {
    // one element is too short
    const data = [new Uint8Array(randomBytes(20)), new Uint8Array(randomBytes(32)), new Uint8Array(randomBytes(32)), new Uint8Array(randomBytes(32))]

    const t = () => {
      treeDataHasExpectedLength(data, 32);
    }

    expect(t).toThrow(Error)
    expect(t).toThrow("argument 'data' array contains items that don't match the hash function output length")

  });

});
