import options, os, results, strformat, strutils, config, utils
import std/streams
import libp2p/[crypto/crypto, crypto/curve25519, crypto/secp, multiaddress, peerid]
import curve25519

const MixNodeInfoSize* =
  addrSize + (2 * FieldElementSize) + (SkRawPublicKeySize + SkRawPrivateKeySize)
const MixPubInfoSize* = addrSize + FieldElementSize + SkRawPublicKeySize
const nodeInfoFolderPath* = "nodeInfo"
const pubInfoFolderPath* = "pubInfo"

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
  let addrBytesRes = multiAddrToBytes(nodeInfo.multiAddr)
  if addrBytesRes.isErr:
    return err(addrBytesRes.error)
  let addrBytes = addrBytesRes.get()

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

  let multiAddrRes = bytesToMultiAddr(data[0 .. addrSize - 1])
  if multiAddrRes.isErr:
    return err(multiAddrRes.error)
  let multiAddr = multiAddrRes.get()

  let mixPubKeyRes =
    bytesToFieldElement(data[addrSize .. (addrSize + FieldElementSize - 1)])
  if mixPubKeyRes.isErr:
    return err("Mix public key deserialize error")
  let mixPubKey = mixPubKeyRes.get()

  let mixPrivKeyRes = bytesToFieldElement(
    data[(addrSize + FieldElementSize) .. (addrSize + (2 * FieldElementSize) - 1)]
  )
  if mixPrivKeyRes.isErr:
    return err("Mix private key deserialize error")
  let mixPrivKey = mixPrivKeyRes.get()

  let pubKeyRes = SkPublicKey.init(
    data[
      addrSize + (2 * FieldElementSize) ..
        addrSize + (2 * FieldElementSize) + SkRawPublicKeySize - 1
    ]
  )
  if pubKeyRes.isErr:
    return err("Failed to initialize libp2p public key")
  let libp2pPubKey = pubKeyRes.get()

  let privKeyRes = SkPrivateKey.init(
    data[addrSize + (2 * FieldElementSize) + SkRawPublicKeySize ..^ 1]
  )
  if privKeyRes.isErr:
    return err("Failed to initialize libp2p private key")
  let libp2pPrivKey = privKeyRes.get()

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

proc writeMixNodeInfoToFile*(node: MixNodeInfo, index: int): Result[void, string] =
  if not dirExists(nodeInfoFolderPath):
    createDir(nodeInfoFolderPath)
  let filename = nodeInfoFolderPath / fmt"mixNode_{index}"
  var file = newFileStream(filename, fmWrite)
  if file == nil:
    return err("Failed to create file stream for " & filename)
  defer:
    file.close()

  let serializedRes = serializeMixNodeInfo(node)
  if serializedRes.isErr:
    return err("Failed to serialize mix node info: " & serializedRes.error)
  let serializedData = serializedRes.get()

  file.writeData(addr serializedData[0], serializedData.len)
  return ok()

proc readMixNodeInfoFromFile*(index: int): Result[MixNodeInfo, string] =
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
    let dMixNodeInfo = deserializeMixNodeInfo(cast[seq[byte]](data))
    if dMixNodeInfo.isErr:
      return err("Mix node info deserialize error.")
    return ok(dMixNodeInfo.get())
  except IOError as e:
    return err("File read error: " & $e.msg)
  except OSError as e:
    return err("OS error: " & $e.msg)

proc deleteNodeInfoFolder*() =
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
  let addrBytesRes = multiAddrToBytes(nodeInfo.multiAddr)
  if addrBytesRes.isErr:
    return err(addrBytesRes.error)
  let addrBytes = addrBytesRes.get()

  let
    mixPubKeyBytes = fieldElementToBytes(nodeInfo.mixPubKey)
    libp2pPubKeyBytes = nodeInfo.libp2pPubKey.getBytes()

  return ok(addrBytes & mixPubKeyBytes & libp2pPubKeyBytes)

proc deserializeMixPubInfo*(data: openArray[byte]): Result[MixPubInfo, string] =
  if len(data) != MixPubInfoSize:
    return
      err("Serialized mix public info must be exactly " & $MixPubInfoSize & " bytes")

  let multiAddrRes = bytesToMultiAddr(data[0 .. addrSize - 1])
  if multiAddrRes.isErr:
    return err(multiAddrRes.error)
  let multiAddr = multiAddrRes.get()

  let mixPubKeyRes =
    bytesToFieldElement(data[addrSize .. (addrSize + FieldElementSize - 1)])
  if mixPubKeyRes.isErr:
    return err("Mix public key deserialize error")
  let mixPubKey = mixPubKeyRes.get()

  let pubKeyRes = SkPublicKey.init(data[(addrSize + FieldElementSize) ..^ 1])
  if pubKeyRes.isErr:
    return err("Failed to initialize libp2p public key")
  let libp2pPubKey = pubKeyRes.get()

  ok(MixPubInfo(multiAddr: multiAddr, mixPubKey: mixPubKey, libp2pPubKey: libp2pPubKey))

proc writePubInfoToFile*(node: MixPubInfo, index: int): Result[void, string] =
  if not dirExists(pubInfoFolderPath):
    createDir(pubInfoFolderPath)
  let filename = pubInfoFolderPath / fmt"mixNode_{index}"
  var file = newFileStream(filename, fmWrite)
  if file == nil:
    return err("Failed to create file stream for " & filename)
  defer:
    file.close()

  let serializedRes = serializeMixPubInfo(node)
  if serializedRes.isErr:
    return err("Failed to serialize mix pub info: " & serializedRes.error)
  let serializedData = serializedRes.get()

  file.writeData(addr serializedData[0], serializedData.len)
  return ok()

proc readMixPubInfoFromFile*(index: int): Result[MixPubInfo, string] =
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
    let dMixPubInfo = deserializeMixPubInfo(cast[seq[byte]](data))
    if dMixPubInfo.isErr:
      return err("Mix pub info deserialize error.")
    return ok(dMixPubInfo.get())
  except IOError as e:
    return err("File read error: " & $e.msg)
  except OSError as e:
    return err("OS error: " & $e.msg)

proc deletePubInfoFolder*() =
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
  let mixNodesRes = generateMixNodes(count, basePort)
  if mixNodesRes.isErr:
    return err("Mix node initialization error")
  mixNodes = mixNodesRes.get()

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
