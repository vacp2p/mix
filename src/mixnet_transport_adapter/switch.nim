import chronicles, std/enumerate, chronos, options, std/sysrand
import ../mixnet_transport_adapter/[transport, protocol]
import
  libp2p/[crypto/secp, multiaddress, builders, protocols/ping, transports/tcptransport]

proc createSwitch*(
    libp2pPrivKey: SkPrivateKey, multiAddr: MultiAddress, nodeIndex, numberOfNodes: int
): Switch =
  let
    inTimeout: Duration = 5.minutes
    outTimeout: Duration = 5.minutes
    transportFlags: set[ServerFlags] = {}

  let switch = SwitchBuilder
    .new()
    .withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: libp2pPrivKey))
    .withAddress(multiAddr)
    .withRng(crypto.newRng())
    .withMplex(inTimeout, outTimeout)
    .withTransport(
      proc(upgrade: Upgrade): Transport =
        let
          wrappedTransport = TcpTransport.new(transportFlags, upgrade)
          mixnetAdapterResult = MixnetTransportAdapter.new(
            wrappedTransport, upgrade, nodeIndex, numberOfNodes
          )
        if mixnetAdapterResult.isOk:
          return mixnetAdapterResult.get
        else:
          error "Failed to create MixnetTransportAdapter",
            err = mixnetAdapterResult.error
          return wrappedTransport
    )
    .withNoise()
    .build()

  if switch.isNil:
    error "Failed to create Switch", nodeIndex = nodeIndex
    return
  else:
    var sendFunc = proc(conn: Connection, proto: ProtocolType): Future[void] {.async.} =
      try:
        await callHandler(switch, conn, proto)
      except CatchableError as e:
        error "Error during execution of sendThroughMixnet: ", err = e.msg
        # TODO: handle error
      return
    for index, transport in enumerate(switch.transports):
      if transport of MixnetTransportAdapter:
        MixnetTransportAdapter(transport).setCallBack(sendFunc)
        break
    return switch
