import chronicles, chronos, options, strformat, strutils, tables
import libp2p/[multiaddress, stream/connection, transports/transport, upgrademngrs/upgrade]
import ./[connection, muxer]
import ../[mix_node, tag_manager]

type MixnetTransportAdapter* = ref object of Transport
  mixNodeInfo: MixNodeInfo
  pubNodeInfo: Table[PeerId, MixPubInfo]
  transport: Transport
  tagManager: TagManager

proc loadMixNodeInfo*(index: int): MixNodeInfo {.raises: [].} =
  let mixNodeInfoOpt = readMixNodeInfoFromFile(index)
  assert mixNodeInfoOpt.isSome, "Failed to load node info from file."
  return mixNodeInfoOpt.get()

proc loadAllButIndexMixPubInfo*(index, numNodes: int): Table[PeerId, MixPubInfo] {.raises: [].} =
  var pubInfoTable = initTable[PeerId, MixPubInfo]()
  for i in 0 ..< numNodes:
    if i != index:
      let pubInfoOpt = readMixPubInfoFromFile(i)
      if pubInfoOpt.isSome:
        let pubInfo = pubInfoOpt.get()
        let (multiAddr, _, _) = getMixPubInfo(pubInfo)
        let peerId = getPeerIdFromMultiAddr(multiAddr)
        pubInfoTable[peerId] = pubInfo
  return pubInfoTable

method log*(self: MixnetTransportAdapter): string {.gcsafe.} =
  "<MixnetTransportAdapter>"

proc handlesDial(address: MultiAddress): bool {.gcsafe.} =
  return TCPMix.match(address)

proc handlesStart(address: MultiAddress): bool {.gcsafe.} =
  return TcpMix.match(address)

method start*(self: MixnetTransportAdapter, mixAddrs: seq[MultiAddress]) {.async.} =
  echo "# Start"
  var tcpAddrs: seq[MultiAddress]
  for i, ma in mixAddrs:
    if not handlesStart(ma):
      warn "Invalid address detected, skipping!", address = ma
      continue
    let tcpAddress = MultiAddress.init(($ma).split("/mix/")[0]).value()
    tcpAddrs.add(tcpAddress)

  if len(tcpAddrs) != 0 and len(mixAddrs) != 0:
    await procCall Transport(self).start(mixAddrs)
    await self.transport.start(tcpAddrs)
  else:
    raise (ref transport.TransportError)(msg: "Mix transport couldn't start, no supported addr was provided.")

method stop*(self: MixnetTransportAdapter) {.async.} =
  echo "# Stop"
  await self.transport.stop()
  await procCall self.Transport.stop()

proc acceptWithMixnet(self: MixnetTransportAdapter): Future[Connection] {.async.} =
  echo "> MixnetTransportAdapter::accept"
  let connection = await self.transport.accept()
  echo "< MixnetTransportAdapter::accept"
  MixnetConnectionAdapter.new(connection)

method accept*(self: MixnetTransportAdapter): Future[Connection] {.gcsafe.} =
  echo "# Accept"
  # self.transport.accept()
  self.acceptWithMixnet()

method dialWithMixnet*(
    self: MixnetTransportAdapter,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[Connection] {.base, async.} =
  echo "> MixnetTransportAdapter::dialWithMixnet1 - ", $peerId
  if not handlesDial(address):
    raise newException(LPError, fmt"Address not supported: {address}")
  let connection = await self.transport.dial(hostname, address, peerId)
  echo "Connection: ", connection.shortLog()
  let x = MixnetConnectionAdapter.new(connection)
  echo "MixnetConnectionAdapter: ", x.shortLog()
  x
  # connection

method dial*(
    self: MixnetTransportAdapter,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[Connection] {.gcsafe.} =
  echo "> MixnetTransportAdapter::dial1"
  self.dialWithMixnet(hostname, address, peerId)

method handles*(self: MixnetTransportAdapter, address: MultiAddress): bool {.gcsafe.} =
  echo "# Handles"
  if procCall Transport(self).handles(address):
    return handlesDial(address) or handlesStart(address)

proc new*(
    T: typedesc[MixnetTransportAdapter], transport: Transport, upgrade: Upgrade, index, numNodes: int
): MixnetTransportAdapter {.raises: [].} =
  let mixNodeInfo = loadMixNodeInfo(index)
  let pubNodeInfo = loadAllButIndexMixPubInfo(index, numNodes)
  let tagManager = initTagManager()
  T(mixNodeInfo: mixNodeInfo,
    pubNodeInfo: pubNodeInfo,
    transport: transport,
    tagManager: tagManager,
    upgrader: upgrade)
