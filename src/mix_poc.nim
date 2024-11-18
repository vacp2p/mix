import chronos, std/enumerate
import libp2p
import libp2p/[crypto/secp, multiaddress, builders, protocols/ping,  switch]
import ../src/[config, mix_message, mix_node, mix_protocol]

proc cryptoRandomInt(max: int): int =
  var bytes: array[8, byte]
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
    initializeMixNodes(numNodes)
    
    var nodes: seq[Switch] = @[]
  
    for index, node in enumerate(mixNodes):
      # Write public info of all mix nodes
      let nodeMixPubInfo = getMixPubInfoByIndex(index)
      let pubResult = writePubInfoToFile(nodeMixPubInfo, index)
      if pubResult == false:
        echo "Failed to write pub info to file for node ", $index
        
      # Write info of all mix nodes
      let mixResult = writeMixNodeInfoToFile(node, index)
      if mixResult == false:
        echo "Failed to write mix node info to file for node ", $index
        
      # Extract private key and multiaddress
      let (multiAddrStr, _, _, _, libp2pPrivKey) = getMixNodeInfo(node)
      let multiAddr = MultiAddress.init(multiAddrStr).value()

      # Create switch
      nodes.add(createSwitch(libp2pPrivKey, multiAddr))

    return nodes

proc mixnet_with_ping() {.async.} =

  let
    numberOfNodes = 10
    nodes = setUpNodes(numberOfNodes)

  var mixProto: seq[MixProtocol] = @[]

  # Start nodes
  for index, node in enumerate(nodes):
    # Mount Mix
    mixProto.add(MixProtocol.new(index, numberOfNodes, nodes[index]))
    nodes[index].mount(mixProto[index])

    #[ Mount Ping
    let
      rng = newRng()
      ping = Ping.new(rng = rng)
    nodes[index].mount(ping) ]#

    await nodes[index].start()

  let senderIndex = cryptoRandomInt(numberOfNodes)
  var receiverIndex = 0
  if senderIndex < numberOfNodes - 1:
    receiverIndex = senderIndex + 1
  echo "##################### senderIndex: ", senderIndex, " receiverIndex: ", receiverIndex, " #####################"
  let mixMsg = initMixMessage(cast[seq[byte]]("Hello World!"), OtherProtocol)
  let serializedMsg = serializeMixMessage(mixMsg)
  await mixProto[senderIndex].anonymizeLocalProtocolSend(serializedMsg, $nodes[receiverIndex].peerInfo.addrs[0])


when isMainModule:
  waitFor(mixnet_with_ping())