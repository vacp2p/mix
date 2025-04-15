import options, os, results, strformat, strutils
import std/streams
import libp2p/[crypto/crypto, crypto/curve25519, crypto/secp, multiaddress, peerid]
import ./[config, curve25519, utils]

const MixNodeInfoSize* =
  addrSize + (2 * FieldElementSize) + (SkRawPublicKeySize + SkRawPrivateKeySize)
const MixPubInfoSize* = addrSize + FieldElementSize + SkRawPublicKeySize

type MixNodeInfo* = object
  multiAddr: string
  mixPubKey: FieldElement
  mixPrivKey: FieldElement
  libp2pPubKey: SkPublicKey
  libp2pPrivKey: SkPrivateKey

var mixNodes*: seq[MixNodeInfo] = @[]

proc initMixNodeInfo*(
    multiAddr: string,
    mixPubKey, mixPrivKey: FieldElement,
    libp2pPubKey: SkPublicKey,
    libp2pPrivKey: SkPrivateKey,
): MixNodeInfo =
  MixNodeInfo(
    multiAddr: multiAddr,
    mixPubKey: mixPubKey,
    mixPrivKey: mixPrivKey,
    libp2pPubKey: libp2pPubKey,
    libp2pPrivKey: libp2pPrivKey,
  )

proc getMixNodeInfo*(
    info: MixNodeInfo
): (string, FieldElement, FieldElement, SkPublicKey, SkPrivateKey) =
  (
    info.multiAddr, info.mixPubKey, info.mixPrivKey, info.libp2pPubKey,
    info.libp2pPrivKey,
  )

proc serializeMixNodeInfo*(nodeInfo: MixNodeInfo): Result[seq[byte], string] =
  let addrBytes = multiAddrToBytes(nodeInfo.multiAddr).valueOr:
    return err("Error in multiaddress conversion to bytes: " & error)

  let
    mixPubKeyBytes = fieldElementToBytes(nodeInfo.mixPubKey)
    mixPrivKeyBytes = fieldElementToBytes(nodeInfo.mixPrivKey)
    libp2pPubKeyBytes = nodeInfo.libp2pPubKey.getBytes()
    libp2pPrivKeyBytes = nodeInfo.libp2pPrivKey.getBytes()

  return ok(
    addrBytes & mixPubKeyBytes & mixPrivKeyBytes & libp2pPubKeyBytes & libp2pPrivKeyBytes
  )

proc deserializeMixNodeInfo*(data: openArray[byte]): Result[MixNodeInfo, string] =
  if len(data) != MixNodeInfoSize:
    return
      err("Serialized Mix node info must be exactly " & $MixNodeInfoSize & " bytes")

  let multiAddr = bytesToMultiAddr(data[0 .. addrSize - 1]).valueOr:
    return err("Error in multiaddress conversion to bytes: " & error)

  let mixPubKey = bytesToFieldElement(
    data[addrSize .. (addrSize + FieldElementSize - 1)]
  ).valueOr:
    return err("Mix public key deserialize error: " & error)

  let mixPrivKey = bytesToFieldElement(
    data[(addrSize + FieldElementSize) .. (addrSize + (2 * FieldElementSize) - 1)]
  ).valueOr:
    return err("Mix private key deserialize error: " & error)

  let libp2pPubKey = SkPublicKey.init(
    data[
      addrSize + (2 * FieldElementSize) ..
        addrSize + (2 * FieldElementSize) + SkRawPublicKeySize - 1
    ]
  ).valueOr:
    return err("Failed to initialize libp2p public key")

  let libp2pPrivKey = SkPrivateKey.init(
    data[addrSize + (2 * FieldElementSize) + SkRawPublicKeySize ..^ 1]
  ).valueOr:
    return err("Failed to initialize libp2p private key")

  ok(
    MixNodeInfo(
      multiAddr: multiAddr,
      mixPubKey: mixPubKey,
      mixPrivKey: mixPrivKey,
      libp2pPubKey: libp2pPubKey,
      libp2pPrivKey: libp2pPrivKey,
    )
  )

proc isNodeMultiaddress*(mixNodeInfo: MixNodeInfo, multiAddr: string): bool =
  return mixNodeInfo.multiAddr == multiAddr

proc writeMixNodeInfoToFile*(node: MixNodeInfo, index: int, nodeInfoFolderPath: string = "./nodeInfo"): Result[void, string] =
  if not dirExists(nodeInfoFolderPath):
    createDir(nodeInfoFolderPath)
  let filename = nodeInfoFolderPath / fmt"mixNode_{index}"
  var file = newFileStream(filename, fmWrite)
  if file == nil:
    return err("Failed to create file stream for " & filename)
  defer:
    file.close()

  let serializedData = serializeMixNodeInfo(node).valueOr:
    return err("Failed to serialize mix node info: " & error)

  file.writeData(addr serializedData[0], serializedData.len)
  return ok()

proc readMixNodeInfoFromFile*(index: int, nodeInfoFolderPath: string = "./nodeInfo"): Result[MixNodeInfo, string] =
  try:
    let filename = nodeInfoFolderPath / fmt"mixNode_{index}"
    if not fileExists(filename):
      return err("File does not exist")
    var file = newFileStream(filename, fmRead)
    if file == nil:
      return err(
        "Failed to open file: " & filename &
          ". Check permissions or if the path is correct."
      )
    defer:
      file.close()
    let data = file.readAll()
    if data.len != MixNodeInfoSize:
      return err(
        "Invalid data size for MixNodeInfo: expected " & $MixNodeInfoSize &
          " bytes, but got " & $(data.len) & " bytes."
      )
    let dMixNodeInfo = deserializeMixNodeInfo(cast[seq[byte]](data)).valueOr:
      return err("Mix node info deserialize error: " & error)
    return ok(dMixNodeInfo)
  except IOError as e:
    return err("File read error: " & $e.msg)
  except OSError as e:
    return err("OS error: " & $e.msg)

proc deleteNodeInfoFolder*(nodeInfoFolderPath: string = "./nodeInfo") =
  if dirExists(nodeInfoFolderPath):
    removeDir(nodeInfoFolderPath)

type MixPubInfo* = object
  multiAddr: string
  mixPubKey: FieldElement
  libp2pPubKey: SkPublicKey

proc initMixPubInfo*(
    multiAddr: string, mixPubKey: FieldElement, libp2pPubKey: SkPublicKey
): MixPubInfo =
  MixPubInfo(multiAddr: multiAddr, mixPubKey: mixPubKey, libp2pPubKey: libp2pPubKey)

proc getMixPubInfo*(info: MixPubInfo): (string, FieldElement, SkPublicKey) =
  (info.multiAddr, info.mixPubKey, info.libp2pPubKey)

proc serializeMixPubInfo*(nodeInfo: MixPubInfo): Result[seq[byte], string] =
  let addrBytes = multiAddrToBytes(nodeInfo.multiAddr).valueOr:
    return err("Error in multiaddress conversion to bytes: " & error)

  let
    mixPubKeyBytes = fieldElementToBytes(nodeInfo.mixPubKey)
    libp2pPubKeyBytes = nodeInfo.libp2pPubKey.getBytes()

  return ok(addrBytes & mixPubKeyBytes & libp2pPubKeyBytes)

proc deserializeMixPubInfo*(data: openArray[byte]): Result[MixPubInfo, string] =
  if len(data) != MixPubInfoSize:
    return
      err("Serialized mix public info must be exactly " & $MixPubInfoSize & " bytes")

  let multiAddr = bytesToMultiAddr(data[0 .. addrSize - 1]).valueOr:
    return err("Error in bytes to multiaddress conversion: " & error)

  let mixPubKey = bytesToFieldElement(
    data[addrSize .. (addrSize + FieldElementSize - 1)]
  ).valueOr:
    return err("Mix public key deserialize error: " & error)

  let libp2pPubKey = SkPublicKey.init(data[(addrSize + FieldElementSize) ..^ 1]).valueOr:
    return err("Failed to initialize libp2p public key: ")

  ok(MixPubInfo(multiAddr: multiAddr, mixPubKey: mixPubKey, libp2pPubKey: libp2pPubKey))

proc writePubInfoToFile*(node: MixPubInfo, index: int, pubInfoFolderPath: string = "./pubInfo"): Result[void, string] =
  if not dirExists(pubInfoFolderPath):
    createDir(pubInfoFolderPath)
  let filename = pubInfoFolderPath / fmt"mixNode_{index}"
  var file = newFileStream(filename, fmWrite)
  if file == nil:
    return err("Failed to create file stream for " & filename)
  defer:
    file.close()

  let serializedData = serializeMixPubInfo(node).valueOr:
    return err("Failed to serialize mix pub info: " & error)

  file.writeData(addr serializedData[0], serializedData.len)
  return ok()

proc readMixPubInfoFromFile*(index: int, pubInfoFolderPath: string = "./pubInfo"): Result[MixPubInfo, string] =
  try:
    let filename = pubInfoFolderPath / fmt"mixNode_{index}"
    if not fileExists(filename):
      return err("File does not exist")
    var file = newFileStream(filename, fmRead)
    if file == nil:
      return err(
        "Failed to open file: " & filename &
          ". Check permissions or if the path is correct."
      )
    defer:
      file.close()
    let data = file.readAll()
    if data.len != MixPubInfoSize:
      return err(
        "Invalid data size for MixNodeInfo: expected " & $MixNodeInfoSize &
          " bytes, but got " & $(data.len) & " bytes."
      )
    let dMixPubInfo = deserializeMixPubInfo(cast[seq[byte]](data)).valueOr:
      return err("Mix pub info deserialize error: " & error)
    return ok(dMixPubInfo)
  except IOError as e:
    return err("File read error: " & $e.msg)
  except OSError as e:
    return err("OS error: " & $e.msg)

proc deletePubInfoFolder*(pubInfoFolderPath: string = "./pubInfo") =
  if dirExists(pubInfoFolderPath):
    removeDir(pubInfoFolderPath)

proc getMixPubInfoByIndex*(index: int): Result[MixPubInfo, string] =
  if index < 0 or index >= mixNodes.len:
    return err("Index must be between 0 and " & $(mixNodes.len))
  ok(
    MixPubInfo(
      multiAddr: mixNodes[index].multiAddr,
      mixPubKey: mixNodes[index].mixPubKey,
      libp2pPubKey: mixNodes[index].libp2pPubKey,
    )
  )

proc generateMixNodes(
    count: int, basePort: int = 4242
): Result[seq[MixNodeInfo], string] =
  var nodes = newSeq[MixNodeInfo](count)
  for i in 0 ..< count:
    let keyPairResult = generateKeyPair()
    if keyPairResult.isErr:
      return err("Generate key pair error: " & $keyPairResult.error)
    let (mixPrivKey, mixPubKey) = keyPairResult.get()

    let
      rng = newRng()
      keyPair = SkKeyPair.random(rng[])
      libp2pPrivKey = keyPair.seckey
      libp2pPubKey = keyPair.pubkey
      pubKeyProto = PublicKey(scheme: Secp256k1, skkey: libp2pPubKey)
      peerId = PeerId.init(pubKeyProto).get()
      multiAddr = fmt"/ip4/127.0.0.1/tcp/{basePort + i}/p2p/{peerId}"

    nodes[i] = MixNodeInfo(
      multiAddr: multiAddr,
      mixPubKey: mixPubKey,
      mixPrivKey: mixPrivKey,
      libp2pPubKey: libp2pPubKey,
      libp2pPrivKey: libp2pPrivKey,
    )

  ok(nodes)

proc initializeMixNodes*(count: int, basePort: int = 4242): Result[void, string] =
  mixNodes = generateMixNodes(count, basePort).valueOr:
    return err("Mix node initialization error: " & error)

proc getPeerIdFromMultiAddr*(multiAddr: string): Result[PeerId, string] =
  let parts = multiAddr.split("/")
  if parts.len != 7:
    return err("Invalid multiaddress format")
  ok(PeerId.init(parts[6]).get())

proc findMixNodeByPeerId*(peerId: PeerId): Result[MixNodeInfo, string] =
  for node in mixNodes:
    let peerIdRes = getPeerIdFromMultiAddr(node.multiAddr).valueOr:
      return err("Failed to get peer id from multiAddress")
    if peerIdRes == peerId:
      return ok(node)
  return err("No node with peer id: " & $peerId)

proc getMixNodeByIndex*(index: int): Result[MixNodeInfo, string] =
  if index < 0 or index >= mixNodes.len:
    return err("Index must be between 0 and " & $(mixNodes.len))
  ok(mixNodes[index])
