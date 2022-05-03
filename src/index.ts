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
  validateHashFunction,
} from './modules/utils'

export { LEAF_NODE_PREFIX, INNER_NODE_PREFIX } from './modules/constants'
