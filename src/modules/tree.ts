// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { assert, is } from 'superstruct'

import {
  ProofHex,
  ProofHexStruct,
  ProofLayer,
  ProofObject,
  ProofObjectStruct,
  TreeData,
  TreeDataStruct,
  TreeHashFunction,
  TreeOptionsStruct,
  TreeTree,
} from './types'

import {
  compare,
  concat,
  powerOfTwo,
  validateHashFunction,
  decodeHex,
  encodeHex,
} from './utils'

import { INNER_NODE_PREFIX, LEAF_NODE_PREFIX } from './constants'

/**
 * Encode a Uint8Array proof to a Hex string.
 * @ignore
 * @param proof The proof to encode.
 * @return The encoded proof value.
 */
export function proofToHex(proof: Uint8Array): ProofHex {
  const proofHex = encodeHex(proof)
  assert(proofHex, ProofHexStruct)
  return proofHex
}

/**
 * Decode a Hex proof to a Uint8Array.
 * @ignore
 * @param proofHex The proof to encode.
 * @return The encoded proof value.
 */
export function hexToProof(proofHex: ProofHex): Uint8Array {
  assert(proofHex, ProofHexStruct)
  return decodeHex(proofHex)
}

/**
 * Encode a Uint8Array proof to an Object.
 * @ignore
 * @param proof The proof to encode.
 * @return The encoded proof value.
 */
export function proofToObject(
  proof: Uint8Array,
  layerHashLen: number,
): ProofObject {
  const layerHashLengthPlusOne: number = layerHashLen + 1
  const proofLength: number = proof.byteLength
  const proofLayers: ProofLayer[] = []

  for (let i = 0; i < proofLength; i += layerHashLengthPlusOne) {
    const order: Uint8Array = proof.subarray(i, i + 1)
    const hash: Uint8Array = proof.subarray(i + 1, i + layerHashLengthPlusOne)
    proofLayers.push([parseInt(encodeHex(order), 16), encodeHex(hash)])
  }

  const proofObj: ProofObject = { v: 1, p: proofLayers }
  assert(proofObj, ProofObjectStruct)
  return proofObj
}

/**
 * Decode an Object proof to a Uint8Array.
 * @ignore
 * @param proofObj The proof to encode.
 * @return The encoded proof value.
 */
export function objectToProof(proofObj: ProofObject): Uint8Array {
  assert(proofObj, ProofObjectStruct)

  const firstProofLayerHashByteLen = proofObj.p[0][1].length / 2

  // FIXME : can this check be done in superstruct which we assert above?
  // Confirm that all proof layers have the same length hash
  for (const layer of proofObj.p) {
    if (layer[1].length / 2 !== firstProofLayerHashByteLen) {
      throw new Error('all object proof hashes must be the same length')
    }
  }

  const proofLayers = proofObj.p

  // Allocate a buffer to hold the full length proof
  const proof = new Uint8Array(
    proofLayers.length * (1 + firstProofLayerHashByteLen),
  )

  for (let i = 0; i < proofLayers.length; i++) {
    const [order, hash] = proofLayers[i]
    proof[i * (1 + firstProofLayerHashByteLen)] = order
    proof.set(decodeHex(hash), i * (1 + firstProofLayerHashByteLen) + 1)
  }

  return proof
}

/**
 * @ignore
 * See instead {@link Tree.verify} which wraps this function.
 */
export function verify(
  root: Uint8Array,
  proof: Uint8Array,
  data: Uint8Array,
  hashFunction: TreeHashFunction,
): boolean {
  const hashFuncOutLen = validateHashFunction(hashFunction)

  // Single item trees return a root that is the same
  // as the data provided and an empty proof.
  if (compare(root, data) && proof.length === 0) {
    return true
  }

  // The data input length must be the same as the hash function output length
  if (data.length !== hashFuncOutLen) {
    return false
  }

  // The length of the data plus a '0' or '1' byte to indicate the direction
  const intermediateStepLen = data.length + 1

  // The proof length must be divisible by the intermediateStepLen
  // Also ensures that each intermediateHash must be the same
  // length as the hash function output since the proof is
  // equally divisible.
  if (proof.length % intermediateStepLen !== 0) {
    return false
  }

  // For each intermediate step of the proof, the first byte must be 0 or 1
  // indicating the direction of the proof concatenation, and the remaining bytes
  // must be a valid hash of the data. This direction is used to determine
  // if the hash is concatenated on the left or right of the original data.
  // All intermediate hashes will be concatenated with the 'data' input
  // which serves as the foundation of the proof.
  for (let i = 0; i < proof.length; i += intermediateStepLen) {
    const intermediateHash: Uint8Array = proof.subarray(
      i + 1,
      i + intermediateStepLen,
    )

    // Choose the prefix to prepend to the data when hashing
    // to prevent second pre-image attacks. The first, or leaf,
    // gets a `0x00` prefix, and the remaining, or inner, nodes
    // get a `0x01` prefix.
    const prefix: Uint8Array = i === 0 ? LEAF_NODE_PREFIX : INNER_NODE_PREFIX

    // left or right concatenate the data and the intermediateHash
    // and hash the result, always building on the previous value
    // of data.
    data = hashFunction(
      proof[i]
        ? concat(prefix, concat(intermediateHash, data))
        : concat(prefix, concat(data, intermediateHash)),
    )
  }

  // The final hash must be equal to the root
  return compare(root, data)
}

/**
 * Validate that each entry in a TreeData has a length that matches the hash function output length.
 * @hidden
 * @param data The TreeData array.
 * @param length The tested length of the hash function output.
 */
export function treeDataHasExpectedLength(
  data: TreeData,
  length: number,
): void {
  for (const d of data) {
    if (d.length !== length) {
      throw new Error(
        "argument 'data' array contains items that don't match the hash function output length",
      )
    }
  }
}

/**
 * Developer debug logging function.
 * @param message The message to send to the console log.
 * @param enabled The enabled flag which determines if this function logs, or is a no-op.
 * @hidden
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function debugLog(message: any, enabled: boolean): void {
  if (enabled) {
    // eslint-disable-next-line no-console
    console.debug(message)
  }
}

/** Class representing a Merkle tree. */
export class Tree {
  /**
   * The data nodes of the Merkle tree.
   * @ignore
   * */
  private readonly data: TreeData

  /**
   * The Merkle tree structure, with each layer in a new array, and the final layer is the Merkle root.
   * @ignore
   * */
  private readonly tree: TreeTree = []

  /**
   * The length, in Bytes, of the output of the hash function used to construct the tree.
   *  @ignore
   * */
  private readonly hashFuncOutLen: number

  /**
   * Is debug logging enabled?
   *  @ignore
   * */
  private readonly debug: boolean

  /**
   * Is requireBalanced enabled?
   *  @ignore
   * */
  private readonly requireBalanced: boolean

  /**
   * Create a new Merkle tree.
   * @param data The array of Uint8Array data values that the tree will be constructed from.
   * @param hashFunction The hash function that will be used to create the tree. It must take a single Uint8Array argument and return a Uint8Array that is between 20 and 64 bytes in length.
   * @param options The options to use when creating the tree.
   */
  // FIXME : It should be possible to use TreeOptions type for options, but if we do that the tests get the type wrong??
  // eslint-disable-next-line prettier/prettier
  constructor (
    data: TreeData,
    hashFunction: TreeHashFunction,
    options: { requireBalanced?: boolean; debug?: boolean } = {
      requireBalanced: false,
      debug: false,
    },
  ) {
    assert(data, TreeDataStruct)
    this.hashFuncOutLen = validateHashFunction(hashFunction)
    assert(options, TreeOptionsStruct)

    this.requireBalanced = options.requireBalanced ?? false
    this.debug = options.debug ?? false

    if (this.requireBalanced && !powerOfTwo(data.length)) {
      throw new Error(
        "argument 'data' array length must be a power of two (or set 'requireBalanced' to false)",
      )
    }

    treeDataHasExpectedLength(data, this.hashFuncOutLen)
    this.data = data
    this.build(this.data, hashFunction)

    debugLog(`constructor options: ${JSON.stringify(options)}`, this.debug)
    debugLog(
      `constructor hashFuncOutLen: ${JSON.stringify(this.hashFuncOutLen)}`,
      this.debug,
    )
    debugLog(`constructor data: ${JSON.stringify(this.data)}`, this.debug)
  }

  /**
   * Get the Merkle root of the tree.
   * @return The Merkle root value.
   */
  public root(): Uint8Array {
    // Return the zero'th element of the last level
    // which is the root of the tree.
    return this.tree[this.tree.length - 1][0]
  }

  /**
   * Get the Merkle tree height, which is the number of hashing layers that resulted after building the tree not including the Merkle root. Should be `Math.ceil(Math.log2(data.length))`.
   * @return The tree height value.
   */
  public height(): number {
    return this.tree.length - 1
  }

  /**
   * Get the Merkle inclusion proof for specific data in raw form.
   * @param dataItem The single data item, already added to the tree, to get the proof for.
   * @return The Merkle inclusion proof value.
   */
  public proof(dataItem: Uint8Array): Uint8Array {
    for (let i = 0; i < this.data.length; i++) {
      if (compare(this.data[i], dataItem)) {
        debugLog(
          `proof dataItem found: ${JSON.stringify(dataItem)}`,
          this.debug,
        )
        return this.proofForIndex(i)
      }
    }

    throw new Error('data node not found')
  }

  /**
   * Get the Merkle inclusion proof for specified data as a single Hex encoded string.
   * @param dataItem The single data item, already added to the tree, to get the proof for.
   * @return The Merkle inclusion proof value.
   */
  public proofHex(dataItem: Uint8Array): ProofHex {
    const proof: Uint8Array = this.proof(dataItem)
    return proofToHex(proof)
  }

  /**
   * Get the Merkle inclusion proof for specified data as a JavaScript Object with Hex encoded hash values.
   * @param dataItem The single data item, already added to the tree, to get the proof for.
   * @return The Merkle inclusion proof value.
   */
  public proofObject(dataItem: Uint8Array): ProofObject {
    const proof: Uint8Array = this.proof(dataItem)
    return proofToObject(proof, this.hashFuncOutLen)
  }

  /**
   * Verify a proof against the Merkle `root`, `data`, and `hashFunction` generated at Tree creation time.
   * @param root The Merkle `root` value of a tree.
   * @param proof The Merkle inclusion `proof` that allows traversal from the `data` to the `root`. The `proof` can be provided in any of the supported encodings.
   * @param data A single data item, exactly as added to the original tree, that the `proof` was generated for.
   * @param hashFunction The hash function, must be the same as that used to create the tree originally.
   * @return A boolean to indicate verification success or failure.
   */
  public static verify(
    root: Uint8Array,
    proof: Uint8Array | ProofHex | ProofObject,
    data: Uint8Array,
    hashFunction: TreeHashFunction,
  ): boolean {
    if (is(proof, ProofHexStruct)) {
      return verify(root, hexToProof(proof), data, hashFunction)
    } else if (is(proof, ProofObjectStruct)) {
      return verify(root, objectToProof(proof), data, hashFunction)
    } else {
      return verify(root, proof, data, hashFunction)
    }
  }

  /**
   * Constructs the internal Merkle tree structure recursively from the `data` provided at Tree creation time. Appends Tree layers and the Merkle root to the `tree` property.
   * @param data An array of data items.
   * @param hashFunction The hash function to use for Tree construction.
   * @param leaves Determine if building leaf nodes or inner nodes. '0x00' prefix for leaf nodes, '0x01' prefix for inner nodes.
   * @hidden
   */
  private build(
    data: Uint8Array[],
    hashFunction: TreeHashFunction,
    leaves = true, // process leaves first (default) which get a different prefix
  ): void {
    this.tree.push(data)

    // Either a single item tree (in which case the data element
    // and the Merkle root are the same), or recursive calls have
    // reduced the tree to a single hash (Merkle root).
    if (data.length === 1) return

    const newLevel: TreeData = []

    for (let i = 0; i < data.length; i += 2) {
      // Choose the prefix to prepend to the data when hashing
      // to prevent second pre-image attacks. The first, or leaf,
      // gets a `0x00` prefix, and the remaining, or inner, nodes
      // get a `0x01` prefix. This needs to be applied during the
      // verification process as well.
      const prefix: Uint8Array = leaves ? LEAF_NODE_PREFIX : INNER_NODE_PREFIX

      // Left
      const d1 = data[i]
      // Right, or duplicate left if an unbalanced tree
      const d2 = data[i + 1] || d1
      newLevel.push(hashFunction(concat(prefix, concat(d1, d2))))
    }

    this.build(newLevel, hashFunction, false)
  }

  /**
   * Constructs a proof that traverses from a single data node found at index `i` to the Merkle root.
   * @param i The array index of the data node to build a proof for.
   * @return A proof.
   * @hidden
   */
  private proofForIndex(i: number): Uint8Array {
    const height: number = this.height()

    let level = 0
    let isRightSideElement = Math.floor(i % 2) // '0' for left (i is even), '1' for right (i is odd)
    let index = i - isRightSideElement

    debugLog(
      `proofForIndex i: ${i}, isRightSideElement: ${isRightSideElement}, index: ${index}`,
      this.debug,
    )

    const proof: number[] = []

    // Last level is the Merkle root, and is excluded
    while (level < height) {
      const currentLevelHashes: Uint8Array[] = this.tree[level]

      debugLog(
        `proofForIndex entering while : level ${level} isRightSideElement: ${isRightSideElement} index: ${index}`,
        this.debug,
      )

      // If current element is a right side element (1) - take left element,
      // If current element is not a right side element, try to take right one.
      // If there is no right element (unbalanced tree) duplicate the left.
      const otherElement: Uint8Array = isRightSideElement
        ? currentLevelHashes[index]
        : currentLevelHashes[index + 1] ?? currentLevelHashes[index]

      // Push '0' or '1' depending on the position of the sibling
      // and the hash of the element it pairs with onto the proof.
      proof.push(isRightSideElement, ...otherElement.values())

      isRightSideElement = Math.floor((index / 2) % 2)
      index = Math.floor(index / 2) - isRightSideElement

      debugLog(
        `proofForIndex exiting while : level ${level} isRightSideElement: ${isRightSideElement} index: ${index}`,
        this.debug,
      )

      // Move up a level
      level++
    }

    debugLog(`proofForIndex proof data : ${JSON.stringify(proof)}`, this.debug)

    return new Uint8Array(proof)
  }
}
