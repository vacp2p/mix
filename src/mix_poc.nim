import chronicles, chronos, results, strutils
import std/[enumerate, sysrand]
import libp2p
import libp2p/[crypto/secp, multiaddress, builders, protocols/ping, switch]
import ../src/[mix_message, mix_node, mix_protocol, protocol]

proc cryptoRandomInt(max: int): int =
  var bytes: array[8, byte]
  discard urandom(bytes)
  let value = cast[uint64](bytes)
  result = int(value mod uint64(max))

proc createSwitch(libp2pPrivKey: SkPrivateKey, multiAddr: MultiAddress): Switch =
  let
    inTimeout: Duration = 5.minutes
    outTimeout: Duration = 5.minutes
  result = SwitchBuilder
    .new()
    .withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: libp2pPrivKey))
    .withAddress(multiAddr)
    .withRng(crypto.newRng())
    .withMplex(inTimeout, outTimeout)
    .withTcpTransport()
    .withNoise()
    .build()

# Set up nodes
proc setUpNodes(numNodes: int): seq[Switch] =
  # This is not actually GC-safe
  {.gcsafe.}:
    # Initialize mix nodes
    discard initializeMixNodes(numNodes)

    var nodes: seq[Switch] = @[]

    for index, node in enumerate(mixNodes):
      # Write public info of all mix nodes
      let nodePubInfoRes = getMixPubInfoByIndex(index)
      if nodePubInfoRes.isErr:
        error "Get mix pub info by index error", err = nodePubInfoRes.error
        continue
      let nodePubInfo = nodePubInfoRes.get()

      let writePubRes = writePubInfoToFile(nodePubInfo, index)
      if writePubRes.isErr:
        error "Failed to write pub info to file", nodeIndex = index
        continue

      # Write info of all mix nodes
      let writeNodeRes = writeMixNodeInfoToFile(node, index)
      if writeNodeRes.isErr:
        error "Failed to write mix info to file", nodeIndex = index
        continue

      # Extract private key and multiaddress
      let (multiAddrStr, _, _, _, libp2pPrivKey) = getMixNodeInfo(node)
      let multiAddr = MultiAddress.init(multiAddrStr.split("/p2p/")[0]).value()

      # Create switch
      nodes.add(createSwitch(libp2pPrivKey, multiAddr))

    return nodes

proc mixnetSimulation() {.async.} =
  let
    numberOfNodes = 10
    nodes = setUpNodes(numberOfNodes)

  var mixProto: seq[MixProtocol] = @[]

  # Start nodes
  for index, node in enumerate(nodes):
    # Mount Mix
    let protoRes = MixProtocol.new(index, numberOfNodes, nodes[index])
    if protoRes.isErr:
      error "Mix protocol initialization failed", err = protoRes.error
      return
    mixProto.add(protoRes.get())
    nodes[index].mount(mixProto[index])
    await nodes[index].start()
  await sleepAsync(1.seconds)

  let senderIndex = cryptoRandomInt(numberOfNodes)
  var receiverIndex = 0
  if senderIndex < numberOfNodes - 1:
    receiverIndex = senderIndex + 1
  let mixMsg = initMixMessage(cast[seq[byte]]("Hello World!"), OtherProtocol)

  let serializedRes = serializeMixMessage(mixMsg)
  if serializedRes.isErr:
    error "Serialization failed", err = serializedRes.error
    return
  let serializedMsg = serializedRes.get()

  await mixProto[senderIndex].anonymizeLocalProtocolSend(
    serializedMsg,
    nodes[receiverIndex].peerInfo.addrs[0],
    nodes[receiverIndex].peerInfo.peerId,
  )

  deleteNodeInfoFolder()
  deletePubInfoFolder()

when isMainModule:
  waitFor(mixnetSimulation())
