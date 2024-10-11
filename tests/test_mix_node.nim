import options, os, strformat, strutils, unittest
import libp2p/[crypto/crypto, crypto/secp, multiaddress, peerid]
import ../src/mix_node
import ../src/curve25519

suite "Mix Node Tests":

  setup:
    var count = 5
    initializeMixNodes(count)
    deleteNodeInfoFolder()

  teardown:
    deleteNodeInfoFolder()

  test "get_mix_node_by_index":
    assert mixNodes.len == count, "Number of mix nodes simulated is incorrect."

    for i in 0..<count:
      let node = getMixNodeByIndex(i)

      let pubKeyProto = PublicKey(scheme: Secp256k1, skkey: node.libp2pPubKey)
      let peerId = PeerId.init(pubKeyProto).get()
      assert node.multiAddr == fmt"/ip4/127.0.0.1/tcp/{4242 + i}/p2p/{peerId}", "Multiaddress of node " & $i & " is invalid."

      assert fieldElementToBytes(node.mixPubKey).len == FieldElementSize, "Mix public key of node " & $i & " is not " & $FieldElementSize & "bytes."
      assert fieldElementToBytes(node.mixPrivKey).len == FieldElementSize, "Mix privte key of node " & $i & " is not " & $FieldElementSize & "bytes."

      assert node.libp2pPubKey.getBytes().len == SkRawPublicKeySize, "Libp2p public key of node " & $i & " is not " & $SkRawPublicKeySize & "bytes."
      assert node.libp2pPrivKey.getBytes().len == SkRawPrivateKeySize, "Libp2p private key of node " & $i & " is not " & $SkRawPrivateKeySize & "bytes."

  test "get_peer_id_from_multiaddr":
    let multiAddr = "/ip4/127.0.0.1/tcp/4242/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
    let peerId = getPeerIdFromMultiAddr(multiAddr)

    assert $peerId == "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N", "Incorrect peer ID."

  test "find_mix_node_by_peer_id":
    for i in 0..<count:
        let node = getMixNodeByIndex(i)
        let (multiAddr, mixPubKey, mixPrivKey, libp2pPubKey, libp2pPrivKey) = getMixNodeInfo(node)
        let peerId = getPeerIdFromMultiAddr(multiAddr)
        let foundNodeOpt = findMixNodeByPeerId(peerId)
        
        assert foundNodeOpt.isSome, "Mix node not found."
        let foundNode = foundNodeOpt.get()
        let (fMultiAddr, fMixPubKey, fMixPrivKey, fLibp2pPubKey, fLibp2pPrivKey) = getMixNodeInfo(foundNode)
        
        assert fMultiAddr == multiAddr, "Multiaddress does not match original multiaddress."
        assert compareFieldElements(fMixPubKey, mixPubKey), "Mix public key does not match original mix public key."
        assert compareFieldElements(fMixPrivKey, mixPrivKey), "Mix private key does not match original mix private key."
        assert fLibp2pPubKey.getBytes() == libp2pPubKey.getBytes(), "Libp2p public key does not match original libp2p public key."
        assert fLibp2pPrivKey.getBytes() == libp2pPrivKey.getBytes(), "Libp2p private key does not match original libp2p private key."

  test "invalid_peer_id_lookup":
    let multiAddr = "/ip4/127.0.0.1/tcp/4242/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N" # Random peer ID
    let peerId = getPeerIdFromMultiAddr(multiAddr)

    let foundNodeOpt = findMixNodeByPeerId(peerId)
    assert foundNodeOpt.isNone, "Found mix node with invalid peer id."

  test "write_and_read_mix_node_info":
    for i in 0..<count:
        let node = getMixNodeByIndex(i)
        let (multiAddr, mixPubKey, mixPrivKey, libp2pPubKey, libp2pPrivKey) = getMixNodeInfo(node)
        
        assert writeMixNodeInfoToFile(node, i), "File mixNode_" & $i & ": write error."
        assert dirExists(folderPath), "Node info folder does not exist."
        let readNodeOpt = readMixNodeInfoFromFile(i)
        assert readNodeOpt.isSome, "File mixNode_" & $i & ": read error."

        let readNode = readNodeOpt.get()
        let (rMultiAddr, rMixPubKey, rMixPrivKey, rLibp2pPubKey, rLibp2pPrivKey) = getMixNodeInfo(readNode)

        assert rMultiAddr == multiAddr, "Multiaddress does not match original multiaddress."
        assert compareFieldElements(rMixPubKey, mixPubKey), "Mix public key does not match original mix public key."
        assert compareFieldElements(rMixPrivKey, mixPrivKey), "Mix private key does not match original mix private key."
        assert rLibp2pPubKey.getBytes() == libp2pPubKey.getBytes(), "Libp2p public key does not match original libp2p public key."
        assert rLibp2pPrivKey.getBytes() == libp2pPrivKey.getBytes(), "Libp2p private key does not match original libp2p private key."

  test "read_nonexistent_mix_node_info":
    let readNodeOpt = readMixNodeInfoFromFile(999)  # Non-existent index
    assert readNodeOpt.isNone, "Mix node 999 should not exist."

  test "generate_mix_nodes_with_different_ports":
    count = 3
    let basePort = 5000
    initializeMixNodes(count, basePort)

    for i in 0..<count:
      let node = getMixNodeByIndex(i)
      check node.multiAddr.contains($(basePort + i))