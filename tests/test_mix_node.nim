import chronicles, options, os, strformat, results, strutils, unittest
import libp2p/[crypto/crypto, crypto/secp, multiaddress, peerid]
import ../src/[curve25519, mix_node]

suite "Mix Node Tests":
  setup:
    var count = 5
    discard initializeMixNodes(count)
    deleteNodeInfoFolder()
    deletePubInfoFolder()

  teardown:
    deleteNodeInfoFolder()
    deletePubInfoFolder()

  test "get_mix_node_by_index":
    if mixNodes.len != count:
      error "Number of mix nodes simulated is incorrect."
      fail()

    for i in 0 ..< count:
      let nodeRes = getMixNodeByIndex(i)
      if nodeRes.isErr:
        error "Get mix node by index error", err = nodeRes.error
        fail()
      let node = nodeRes.get()

      let
        (multiAddr, mixPubKey, mixPrivKey, libp2pPubKey, libp2pPrivKey) =
          getMixNodeInfo(node)
        pubKeyProto = PublicKey(scheme: Secp256k1, skkey: libp2pPubKey)
        peerId = PeerId.init(pubKeyProto).get()

      if multiAddr != fmt"/ip4/127.0.0.1/tcp/{4242 + i}/p2p/{peerId}":
        error "Multiaddress of retrieved node is invalid", multiaddr = multiAddr
        fail()

      if fieldElementToBytes(mixPubKey).len != FieldElementSize:
        error "Mix public key of retrieved node is invalid",
          expected_size = FieldElementSize
        fail()

      if fieldElementToBytes(mixPrivKey).len != FieldElementSize:
        error "Mix private key of retrieved node is invalid",
          expected_size = FieldElementSize
        fail()

      if libp2pPubKey.getBytes().len != SkRawPublicKeySize:
        error "Libp2p public key of retrieved node is invalid",
          expected_size = SkRawPublicKeySize
        fail()

      if libp2pPrivKey.getBytes().len != SkRawPrivateKeySize:
        error "Libp2p private key of retrieved node is invalid",
          expected_size = SkRawPrivateKeySize
        fail()

  test "get_peer_id_from_multiaddr":
    let multiAddr =
      "/ip4/127.0.0.1/tcp/4242/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"

    let peerIdRes = getPeerIdFromMultiAddr(multiAddr)
    if peerIdRes.isErr:
      error "Get peer id from multiaddress error", err = peerIdRes.error
      fail()
    let peerId = peerIdRes.get()

    if $peerId != "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N":
      error "Incorrect peer ID."
      fail()

  test "find_mix_node_by_peer_id":
    for i in 0 ..< count:
      let nodeRes = getMixNodeByIndex(i)
      if nodeRes.isErr:
        error "Get mix node by index error", err = nodeRes.error
        fail()
      let node = nodeRes.get()

      let (multiAddr, mixPubKey, mixPrivKey, libp2pPubKey, libp2pPrivKey) =
        getMixNodeInfo(node)

      let peerIdRes = getPeerIdFromMultiAddr(multiAddr)
      if peerIdRes.isErr:
        error "Get peer id from multiaddress error", err = peerIdRes.error
        fail()
      let peerId = peerIdRes.get()

      let foundNodeRes = findMixNodeByPeerId(peerId)
      if foundNodeRes.isErr:
        error "Find mix node error", err = foundNodeRes.error
        fail()
      let foundNode = foundNodeRes.get()

      let (fMultiAddr, fMixPubKey, fMixPrivKey, fLibp2pPubKey, fLibp2pPrivKey) =
        getMixNodeInfo(foundNode)

      if fMultiAddr != multiAddr:
        error "Multiaddress does not match original multiaddress",
          multiaddr = fMultiAddr, original = multiAddr
        fail()

      if not compareFieldElements(fMixPubKey, mixPubKey):
        error "Mix public key does not match original mix public key",
          pubkey = fMixPubKey, original = mixPubKey
        fail()

      if not compareFieldElements(fMixPrivKey, mixPrivKey):
        error "Mix private key does not match original mix private key",
          privkey = fMixPrivKey, original = mixPrivKey
        fail()

      if fLibp2pPubKey.getBytes() != libp2pPubKey.getBytes():
        error "Libp2p public key does not match original libp2p public key",
          pubkey = fLibp2pPubKey.getBytes(), original = libp2pPubKey.getBytes()
        fail()

      if fLibp2pPrivKey.getBytes() != libp2pPrivKey.getBytes():
        error "Libp2p private key does not match original libp2p private key",
          privkey = fLibp2pPrivKey.getBytes(), original = libp2pPrivKey.getBytes()
        fail()

  test "invalid_peer_id_lookup":
    let multiAddr =
      "/ip4/127.0.0.1/tcp/4242/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
      # Random peer ID

    let peerIdRes = getPeerIdFromMultiAddr(multiAddr)
    if peerIdRes.isErr:
      error "Get peer id from multiaddress error", err = peerIdRes.error
      fail()
    let peerId = peerIdRes.get()

    let foundNodeRes = findMixNodeByPeerId(peerId)
    if foundNodeRes.isOk:
      fail()

  test "write_and_read_mix_node_info":
    for i in 0 ..< count:
      let nodeRes = getMixNodeByIndex(i)
      if nodeRes.isErr:
        error "Get mix node by index error", err = nodeRes.error
        fail()
      let node = nodeRes.get()

      let (multiAddr, mixPubKey, mixPrivKey, libp2pPubKey, libp2pPrivKey) =
        getMixNodeInfo(node)

      let writeNodeRes = writeMixNodeInfoToFile(node, i)
      if writeNodeRes.isErr:
        error "File write error", index = i
        fail()

      let readNodeRes = readMixNodeInfoFromFile(i)
      if readNodeRes.isErr:
        error "File read error", index = i
        fail()
      let readNode = readNodeRes.get()

      let (rMultiAddr, rMixPubKey, rMixPrivKey, rLibp2pPubKey, rLibp2pPrivKey) =
        getMixNodeInfo(readNode)

      if rMultiAddr != multiAddr:
        error "Multiaddress does not match original multiaddress",
          multiaddr = rMultiAddr, original = multiAddr
        fail()

      if not compareFieldElements(rMixPubKey, mixPubKey):
        error "Mix public key does not match original mix public key",
          pubkey = rMixPubKey, original = mixPubKey
        fail()

      if not compareFieldElements(rMixPrivKey, mixPrivKey):
        error "Mix private key does not match original mix private key",
          privkey = rMixPrivKey, original = mixPrivKey
        fail()

      if rLibp2pPubKey.getBytes() != libp2pPubKey.getBytes():
        error "Libp2p public key does not match original libp2p public key",
          pubkey = rLibp2pPubKey.getBytes(), original = libp2pPubKey.getBytes()
        fail()

      if rLibp2pPrivKey.getBytes() != libp2pPrivKey.getBytes():
        error "Libp2p private key does not match original libp2p private key",
          privkey = rLibp2pPrivKey.getBytes(), original = libp2pPrivKey.getBytes()
        fail()

  test "write_and_read_mix_pub_info":
    for i in 0 ..< count:
      let nodeRes = getMixPubInfoByIndex(i)
      if nodeRes.isErr:
        error "Get mix node by index error", err = nodeRes.error
        fail()
      let node = nodeRes.get()

      let (multiAddr, mixPubKey, libp2pPubKey) = getMixPubInfo(node)

      let writeNodeRes = writeMixPubInfoToFile(node, i)
      if writeNodeRes.isErr:
        error "File write error", index = i
        fail()

      let readNodeRes = readMixPubInfoFromFile(i)
      if readNodeRes.isErr:
        error "File read error", index = i
        fail()
      let readNode = readNodeRes.get()

      let (rMultiAddr, rMixPubKey, rLibp2pPubKey) = getMixPubInfo(readNode)

      if rMultiAddr != multiAddr:
        error "Multiaddress does not match original multiaddress",
          multiaddr = rMultiAddr, original = multiAddr
        fail()

      if not compareFieldElements(rMixPubKey, mixPubKey):
        error "Mix public key does not match original mix public key",
          pubkey = rMixPubKey, original = mixPubKey
        fail()

      if rLibp2pPubKey.getBytes() != libp2pPubKey.getBytes():
        error "Libp2p public key does not match original libp2p public key",
          pubkey = rLibp2pPubKey.getBytes(), original = libp2pPubKey.getBytes()
        fail()

  test "read_nonexistent_mix_node_info":
    let readNodeRes = readMixNodeInfoFromFile(999) # Non-existent index
    if readNodeRes.isOk:
      error "Mix node 999 should not exist."
      fail()

  test "generate_mix_nodes_with_different_ports":
    count = 3
    let basePort = 5000
    discard initializeMixNodes(count, basePort)

    for i in 0 ..< count:
      let nodeRes = getMixNodeByIndex(i)
      if nodeRes.isErr:
        error "Get mix node by index error", err = nodeRes.error
        fail()
      let node = nodeRes.get()

      let (multiAddr, _, _, _, _) = getMixNodeInfo(node)

      if not multiAddr.contains($(basePort + i)):
        error "Multiaddress does not contain expected port no.",
          expected_port = $(basePort + i)
        fail()
