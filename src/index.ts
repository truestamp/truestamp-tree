// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

export {
  Tree,
  proofToHex,
  hexToProof,
  proofToObject,
  objectToProof,
} from './modules/tree'

export {
  ProofHex,
  ProofHexStruct,
  ProofLayer,
  ProofLayerStruct,
  ProofObject,
  ProofObjectStruct,
  TreeData,
  TreeDataStruct,
  TreeHashFunction,
  TreeOptions,
  TreeOptionsStruct,
  TreeTree,
  TreeTreeStruct,
} from './modules/types'

export {
  concat,
  compare,
  encodeHex,
  decodeHex,
  powerOfTwo,
  sha224,
  sha384,
  sha256,
  sha512,
  sha512_256,
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
  validateHashFunction,
} from './modules/utils'

export { LEAF_NODE_PREFIX, INNER_NODE_PREFIX } from './modules/constants'
