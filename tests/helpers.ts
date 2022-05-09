// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { randomBytes } from '@stablelib/random'

export function getRandomBytes(num: number): Uint8Array {
  return randomBytes(num)
}

export function getRandomData(num: number, bytes: number): Uint8Array[] {
  const data: Uint8Array[] = []
  for (let i = 0; i < num; ++i) {
    data.push(getRandomBytes(bytes))
  }
  return data
}

/**
 * Remove a single byte from a Uint8Array at a given index. Returns a new Uint8Array.
 */
export function sliceElement(a: Uint8Array, position: number): Uint8Array {
  const tmp: Uint8Array = new Uint8Array(a.byteLength - 1)

  for (let i = 0; i < a.length; i++) {
    if (i === position) {
      continue
    } else {
      tmp[i] = a[i]
    }
  }

  return tmp
}
