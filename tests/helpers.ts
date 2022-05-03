// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { createHash } from 'crypto'

export function sha1(data: Uint8Array): Uint8Array {
  return createHash('sha1').update(data).digest()
}

export function sha256(data: Uint8Array): Uint8Array {
  return createHash('sha256').update(data).digest()
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
