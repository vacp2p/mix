import curve25519, config, utils
import libp2p/[crypto/crypto, crypto/curve25519, crypto/secp, multiaddress, peerid]
import options, os, std/streams, strformat, strutils

const MixNodeInfoSize* = addrSize + (2 * FieldElementSize) + (SkRawPublicKeySize + SkRawPrivateKeySize)

type
  MixNodeInfo* = object
    multiAddr*: string
    mixPubKey*: FieldElement
    mixPrivKey*: FieldElement
    libp2pPubKey*: SkPublicKey
    libp2pPrivKey*: SkPrivateKey

proc initMixNodeInfo*(multiAddr: string, mixPubKey, mixPrivKey: FieldElement, libp2pPubKey: SkPublicKey, libp2pPrivKey: SkPrivateKey): MixNodeInfo =
  result.multiAddr = multiAddr
  result.mixPubKey = mixPubKey
  result.mixPrivKey = mixPrivKey
  result.libp2pPubKey = libp2pPubKey
  result.libp2pPrivKey = libp2pPrivKey

proc getMixNodeInfo*(info: MixNodeInfo): (string, FieldElement, FieldElement, SkPublicKey, SkPrivateKey) =
  (info.multiAddr, info.mixPubKey, info.mixPrivKey, info.libp2pPubKey, info.libp2pPrivKey)

proc serializeMixNodeInfo*(nodeInfo: MixNodeInfo): seq[byte] =
    let addrBytes = multiAddrToBytes(nodeInfo.multiAddr)
    let mixPubKeyBytes = fieldElementToBytes(nodeInfo.mixPubKey)
    let mixPrivKeyBytes = fieldElementToBytes(nodeInfo.mixPrivKey)
    let libp2pPubKeyBytes = nodeInfo.libp2pPubKey.getBytes()
    let libp2pPrivKeyBytes = nodeInfo.libp2pPrivKey.getBytes()
    
    result = addrBytes & mixPubKeyBytes & mixPrivKeyBytes & libp2pPubKeyBytes & libp2pPrivKeyBytes

proc deserializeMixNodeInfo*(data: openArray[byte]): MixNodeInfo =
    assert len(data) == MixNodeInfoSize, "Serialized Mix node info must be exactly " & $MixNodeInfoSize & " bytes"
    result.multiAddr = bytesToMultiAddr(data[0..addrSize - 1])
    result.mixPubKey = bytesToFieldElement(data[addrSize..(addrSize + FieldElementSize - 1)])
    result.mixPrivKey = bytesToFieldElement(data[(addrSize + FieldElementSize)..(addrSize + (2 * FieldElementSize) - 1)])

    let pubKeyRes = SkPublicKey.init(data[addrSize + (2 * FieldElementSize)..addrSize + (2 * FieldElementSize) + SkRawPublicKeySize - 1])
    assert pubKeyRes.isOk, "Failed to initialize libp2p public key"
    result.libp2pPubKey = pubKeyRes.get()
    
    let privKeyRes = SkPrivateKey.init(data[addrSize + (2 * FieldElementSize) + SkRawPublicKeySize..^1])
    assert privKeyRes.isOk, "Failed to initialize libp2p private key"
    result.libp2pPrivKey = privKeyRes.get()

const folderPath* = "nodeInfo"

proc writeMixNodeInfoToFile*(node: MixNodeInfo, index: int): bool =
    if not dirExists(folderPath):
        createDir(folderPath)
    let filename = folderPath / fmt"mixNode_{index}"
    var file = newFileStream(filename, fmWrite)
    if file == nil:
        return false
    defer: file.close()
    let serializedData = serializeMixNodeInfo(node)
    file.writeData(addr serializedData[0], serializedData.len)
    return true

proc readMixNodeInfoFromFile*(index: int): Option[MixNodeInfo] =
    let filename = folderPath / fmt"mixNode_{index}"
    if not fileExists(filename):
        return none(MixNodeInfo)
    var file = newFileStream(filename, fmRead)
    if file == nil:
        return none(MixNodeInfo)
    defer: file.close()
    let data = file.readAll()
    if data.len != MixNodeInfoSize:
        return none(MixNodeInfo)
    return some(deserializeMixNodeInfo(cast[seq[byte]](data)))

proc deleteNodeInfoFolder*() =
    if dirExists(folderPath):
        removeDir(folderPath)

var mixNodes*: seq[MixNodeInfo] = @[]

proc generateMixNodes(count: int, basePort: int = 4242): seq[MixNodeInfo] =
    result = newSeq[MixNodeInfo](count)
    for i in 0..<count:
        let (mixPrivKey, mixPubKey) = generateKeyPair()
        let rng = newRng()
        let keyPair = SkKeyPair.random(rng[])
        let libp2pPrivKey = keyPair.seckey
        let libp2pPubKey = keyPair.pubkey
        
        let pubKeyProto = PublicKey(scheme: Secp256k1, skkey: libp2pPubKey)
        let peerId = PeerId.init(pubKeyProto).get()
        let multiAddr = fmt"/ip4/127.0.0.1/tcp/{basePort + i}/p2p/{peerId}"
        
        result[i] = MixNodeInfo(
        multiAddr: multiAddr,
        mixPubKey: mixPubKey,
        mixPrivKey: mixPrivKey,
        libp2pPubKey: libp2pPubKey,
        libp2pPrivKey: libp2pPrivKey
        )

proc initializeMixNodes*(count: int, basePort: int = 4242) =
    mixNodes = generateMixNodes(count, basePort)

proc getPublicMixNodeInfo*(): seq[tuple[multiaddr: string, mixPubKey: FieldElement, libp2pPubKey: SkPublicKey]] =
    result = newSeq[tuple[multiaddr: string, mixPubKey: FieldElement, libp2pPubKey: SkPublicKey]](mixNodes.len)
    for i, node in mixNodes:
        result[i] = (node.multiAddr, node.mixPubKey, node.libp2pPubKey)

proc getPeerIdFromMultiAddr*(multiAddr: string): PeerId =
    let parts = multiAddr.split("/")
    assert parts.len == 7, "Invalid multiaddress format"
    return PeerId.init(parts[6]).get()

proc findMixNodeByPeerId*(peerId: PeerId): Option[MixNodeInfo] =
    for node in mixNodes:
        if getPeerIdFromMultiAddr(node.multiAddr) == peerId:
            return some(node)
    return none(MixNodeInfo)

proc getMixNodeByIndex*(index: int): MixNodeInfo =
    assert index >= 0 and index < mixNodes.len, "Index must be between 0 and " & $(mixNodes.len) & " bytes"
    return mixNodes[index]