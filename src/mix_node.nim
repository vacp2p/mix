import curve25519, config, utils
import libp2p/[crypto/crypto, crypto/secp, multiaddress, peerid]
import options, os, std/streams, stew/base58, strformat, strutils

const MixNodeInfoSize* = addrSize + (2 * FieldElementSize) + (SkRawPublicKeySize + SkRawPrivateKeySize)

type
  MixNodeInfo* = object
    multiAddr*: string
    mixPubKey*: FieldElement
    mixPrivKey*: FieldElement
    libp2pPubKey*: SkPublicKey
    libp2pPrivKey*: SkPrivateKey

proc serializeMixNodeInfo*(nodeInfo: MixNodeInfo): seq[byte] =
    result = newSeq[byte](MixNodeInfoSize)
    result.add(multiAddrToBytes(nodeInfo.multiAddr))
    result.add(fieldElementToBytes(nodeInfo.mixPubKey))
    result.add(fieldElementToBytes(nodeInfo.mixPrivKey))
    result.add(nodeInfo.libp2pPubKey.getBytes())
    result.add(nodeInfo.libp2pPrivKey.getBytes())

proc deserializeMixNodeInfo*(data: openArray[byte]): MixNodeInfo =
    assert len(data) == MixNodeInfoSize, "Serialized Mix node info must be exactly " & $(MixNodeInfoSize + 128) & " bytes"
    result.multiAddr = bytesToMultiAddr(data[0..addrSize - 1])
    result.mixPubKey = bytesToFieldElement(data[addrSize..(addrSize + FieldElementSize - 1)])
    result.mixPrivKey = bytesToFieldElement(data[(addrSize + FieldElementSize)..(addrSize + (2 * FieldElementSize) - 1)])

    let pubKeyRes = SkPublicKey.init(data[addrSize + (2 * FieldElementSize)..addrSize + (2 * FieldElementSize) + SkRawPublicKeySize - 1])
    assert pubKeyRes.isOk, "Failed to initialize libp2p public key"
    result.libp2pPubKey = pubKeyRes.get()
    
    let privKeyRes = SkPrivateKey.init(data[addrSize + (2 * FieldElementSize) + SkRawPublicKeySize..^1])
    assert privKeyRes.isOk, "Failed to initialize libp2p private key"
    result.libp2pPrivKey = privKeyRes.get()

const folderPath = "nodeInfo"

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
        
        let pubKeyBytes = libp2pPubKey.getBytes()
        let peerId = PeerId.init(pubKeyBytes)
        let multiAddr = fmt"/ip4/127.0.0.1/tcp/{basePort + i}/mix/{peerId}"
        
        result[i] = MixNodeInfo(
        multiAddr: multiAddr,
        mixPubKey: mixPubKey,
        mixPrivKey: mixPrivKey,
        libp2pPubKey: libp2pPubKey,
        libp2pPrivKey: libp2pPrivKey
        )

proc initializeMixNodes*(count: int, basePort: int = 4242) =
    mixNodes = generateMixNodes(count, basePort)

proc getPublicMixNodeInfo*(): seq[tuple[multiaddr: string, publicKey: FieldElement]] =
    result = newSeq[tuple[multiaddr: string, publicKey: FieldElement]](mixNodes.len)
    for i, node in mixNodes:
        result[i] = (node.multiAddr, node.mixPubKey)

proc getPeerIdFromMultiAddr*(multiAddr: string): PeerId =
    let parts = multiAddr.split("/")
    assert parts.len == 7, "Invalid multiaddress format"
    let peerIdBase58 = parts[6]
    let peerIdBytes = Base58.decode(peerIdBase58)
    assert peerIdBytes.len == 32, "Peer ID must be exactly 32 bytes"
    return PeerId.init(peerIdBytes).get()

proc findMixNodeByPeerId*(peerId: PeerId): Option[MixNodeInfo] =
    for node in mixNodes:
        if getPeerIdFromMultiAddr(node.multiAddr) == peerId:
            return some(node)
    return none(MixNodeInfo)

proc getMixNodeByIndex*(index: int): MixNodeInfo =
    assert index >= 0 and index < mixNodes.len, "Index must be between 0 and " & $(mixNodes.len) & " bytes"
    return mixNodes[index]