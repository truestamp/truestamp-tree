// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { createHash } from 'crypto'
import { randomBytes } from '@stablelib/random'

export function sha1_node(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha1').update(data).digest().buffer)
}

export function sha224_node(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha224').update(data).digest().buffer)
}

export function sha256_node(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest().buffer)
}

export function sha384_node(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha384').update(data).digest().buffer)
}

export function sha512_node(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha512').update(data).digest().buffer)
}

export function getRandomBytes(num: number): Uint8Array {
  return randomBytes(num)
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
