# Uncleaned file just in case #
###############################

# Main
import chronos
import libp2p/builders
import libp2p/transports/tcptransport
import libp2p/transports/quictransport
import libp2p/upgrademngrs/muxedupgrade
import libp2p/upgrademngrs/upgrade

# Adapter
import std/[hashes]
import libp2p/stream/connection
import libp2p/transports/transport
import libp2p/muxers/muxer

# Mix
import src/[mix_protocol, mix_node], tests/utils/[async]
import std/[enumerate]

type
  P2PConnection = connection.Connection
  P2PMuxer = muxer.Muxer
  P2PTransport = transport.Transport
  P2PUpgrade = upgrade.Upgrade

################################################################################################################################################################
################################################################################################################################################################
################################################################################################################################################################

type MixnetConnectionAdapter* = ref object of Connection
  connection: Connection

method join*(
    self: MixnetConnectionAdapter
): Future[void] {.async: (raises: [CancelledError], raw: true), public.} =
  self.connection.join()

method readExactly*(
    self: MixnetConnectionAdapter, pbytes: pointer, nbytes: int
): Future[void] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readExactly(pbytes, nbytes)

method readLine*(
    self: MixnetConnectionAdapter, limit = 0, sep = "\r\n"
): Future[string] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readLine(limit, sep)

method readVarint*(
    self: MixnetConnectionAdapter
): Future[uint64] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readVarint()

method readLp*(
    self: MixnetConnectionAdapter, maxSize: int
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]), public.} =
  await self.connection.readLp(maxSize)

method writeLp*(
    self: MixnetConnectionAdapter, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.connection.writeLp(msg)

method writeLp*(
    self: MixnetConnectionAdapter, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), public.} =
  self.connection.writeLp(msg.toOpenArrayByte(0, msg.high))

# proc timeoutMonitor(self: MixnetConnectionAdapter) {.async: (raises: []).} =
#   self.connection.timeoutMonitor()

method shortLog*(self: MixnetConnectionAdapter): string {.raises: [].} =
  "[MixnetConnectionAdapter] " & self.connection.shortLog()

method initStream*(self: MixnetConnectionAdapter) =
  self.connection.initStream()

method closeImpl*(self: MixnetConnectionAdapter): Future[void] {.async: (raises: []).} =
  self.connection.closeImpl()

func hash*(self: MixnetConnectionAdapter): Hash =
  self.connection.hash()

proc new*(
    T: typedesc[MixnetConnectionAdapter], connection: P2PConnection
): MixnetConnectionAdapter =
  let instance = T(
    connection: connection,
    activity: connection.activity,
    timeout: connection.timeout,
    # timerTaskFut: connection.timerTaskFut,
    timeoutHandler: connection.timeoutHandler,
    peerId: connection.peerId,
    observedAddr: connection.observedAddr,
    protocol: connection.protocol,
    transportDir: connection.transportDir,
  )

  when defined(libp2p_agents_metrics):
    instance.shortAgent = connection.shortAgent

  instance

# proc pollActivity(self: MixnetConnectionAdapter): Future[bool] {.async: (raises: []).} =
#   self.connection.pollActivity()

# proc timeoutMonitor(self: MixnetConnectionAdapter) {.async: (raises: []).} =
#   self.connection.timeoutMonitor()

method getWrapped*(self: MixnetConnectionAdapter): Connection =
  self.connection.getWrapped()

when defined(libp2p_agents_metrics):
  proc setShortAgent*(self: MixnetConnectionAdapter, shortAgent: string) =
    self.connection.setShortAgent(shortAgent)

################################################################################################################################################################
################################################################################################################################################################
################################################################################################################################################################

type MixnetMuxerAdapter* = ref object of P2PMuxer
  muxer: P2PMuxer

func shortLog*(self: MixnetMuxerAdapter): auto =
  self.muxer.shortLog()

method newStream*(
    self: MixnetMuxerAdapter, name: string = "", lazy: bool = false
): Future[Connection] {.
    async: (raises: [CancelledError, LPStreamError, MuxerError], raw: true)
.} =
  self.muxer.newStream(name, lazy)

method close*(self: MixnetMuxerAdapter) {.async: (raises: []).} =
  self.muxer.close()

method handle*(self: MixnetMuxerAdapter): Future[void] {.async: (raises: []).} =
  self.muxer.handle()

method getStreams*(self: MixnetMuxerAdapter): seq[Connection] =
  self.muxer.getStreams()

################################################################################################################################################################
################################################################################################################################################################
################################################################################################################################################################

type MixnetUpgradeAdapter* = ref object of Upgrade
  upgrade: Upgrade

method upgrade*(
    self: MixnetUpgradeAdapter, conn: Connection, peerId: Opt[PeerId]
): Future[Muxer] {.async: (raises: [CancelledError, LPError], raw: true).} =
  assert conn of MixnetConnectionAdapter
  echo "> MixnetUpgradeAdapter::upgrade"
  self.upgrade.upgrade(conn.MixnetConnectionAdapter.connection, peerId)

method secure*(
    self: MixnetUpgradeAdapter, conn: Connection, peerId: Opt[PeerId]
): Future[Connection] {.async: (raises: [CancelledError, LPError]).} =
  assert conn of MixnetConnectionAdapter
  echo "> MixnetUpgradeAdapter::secure"
  await self.upgrade.secure(conn.MixnetConnectionAdapter.connection, peerId)

proc new*(T: typedesc[MixnetUpgradeAdapter], upgrade: Upgrade): MixnetUpgradeAdapter =
  T(upgrade: upgrade, ms: upgrade.ms, secureManagers: upgrade.secureManagers)

################################################################################################################################################################
################################################################################################################################################################
################################################################################################################################################################

type MixnetTransportAdapter* = ref object of P2PTransport
  transport: P2PTransport

method log*(self: MixnetTransportAdapter): string {.gcsafe.} =
  "<MixnetTransportAdapter>"

method start*(self: MixnetTransportAdapter, addrs: seq[MultiAddress]) {.async.} =
  echo "# Start"
  await self.transport.start(addrs)
  await procCall self.P2PTransport.start(addrs)

method stop*(self: MixnetTransportAdapter) {.async.} =
  echo "# Stop"
  await self.transport.stop()
  await procCall self.P2PTransport.stop()

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
): Future[Connection] {.async.} =
  echo "> MixnetTransportAdapter::dialWithMixnet1 - ", $peerId
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

method dialWithMixnet*(
    self: MixnetTransportAdapter,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[P2PConnection] {.async.} =
  echo "MixnetTransportAdapter::dialWithMixnet2"
  let connection = await self.transport.dial(address, peerId)
  MixnetConnectionAdapter.new(connection)

method dial*(
    self: MixnetTransportAdapter,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[P2PConnection] {.gcsafe.} =
  echo "MixnetTransportAdapter::dial2"
  self.dialWithMixnet(address, peerId)

method upgradeWithMixnet(
    self: MixnetTransportAdapter, conn: MixnetConnectionAdapter, peerId: Opt[PeerId]
): Future[MixnetMuxerAdapter] {.
    async, async: (raises: [CancelledError, LPError], raw: true)
.} =
  echo "> MixnetTransportAdapter::upgradeWithMixnet"
  # echo conn.shortLog()
  let muxer = await self.transport.upgrade(conn.connection, peerId)
  echo "< MixnetTransportAdapter::upgradeWithMixnet"
  MixnetMuxerAdapter(muxer: muxer)

method upgrade*(
    self: MixnetTransportAdapter, conn: MixnetConnectionAdapter, peerId: Opt[PeerId]
): Future[MixnetMuxerAdapter] {.async: (raises: [CancelledError, LPError], raw: true).} =
  echo "# Upgrade"
  echo conn.shortLog()
  self.upgradeWithMixnet(conn, peerId)

method handles*(self: MixnetTransportAdapter, address: MultiAddress): bool {.gcsafe.} =
  echo "# Handles"
  self.transport.handles(address)

###################
proc setUpMixNet(numberOfNodes: int) =
  # This is not actually GC-safe  
  {.gcsafe.}:
    initializeMixNodes(numberOfNodes)

    for index, node in enumerate(mixNodes):
      let nodeMixPubInfo = getMixPubInfoByIndex(index)
      let pubResult = writePubInfoToFile(nodeMixPubInfo, index)
      if pubResult == false:
        echo "Failed to write pub info to file for node ", $index

      let mixResult = writeMixNodeInfoToFile(node, index)
      if mixResult == false:
        echo "Failed to write mix node info to file for node ", $index

proc attempt() {.async.} =
  let
    numberOfNodes = 2
    nodeIndexA = 0
    nodeIndexB = 1

    # And their mix node info is initialized
  setUpMixNet(numberOfNodes)

  let
    inTimeout: Duration = 5.minutes
    outTimeout: Duration = 5.minutes
    transportFlags: set[ServerFlags] = {}

  let
    addressA = MultiAddress.init("/ip4/127.0.0.3/tcp/8081").value()
    addressB = MultiAddress.init("/ip4/127.0.0.4/tcp/8082").value()
    switchA = SwitchBuilder
      .new()
      .withAddress(addressA)
      .withRng(crypto.newRng())
      .withMplex(inTimeout, outTimeout)
      .withTransport(
        proc(upgrade: Upgrade): Transport =
          let
            wrappedTransport = TcpTransport.new(transportFlags, upgrade)
            wrappedUpgrade = MixnetUpgradeAdapter(upgrade: upgrade)
          MixnetTransportAdapter(transport: wrappedTransport, upgrader: wrappedUpgrade)
      )
      .withNoise()
      .build()
    switchB = SwitchBuilder
      .new()
      .withAddress(addressB)
      .withRng(crypto.newRng())
      .withMplex(inTimeout, outTimeout)
      .withTransport(
        proc(upgrade: Upgrade): Transport =
          let
            wrappedTransport = TcpTransport.new(transportFlags, upgrade)
            wrappedUpgrade = MixnetUpgradeAdapter(upgrade: upgrade)
          MixnetTransportAdapter(transport: wrappedTransport, upgrader: wrappedUpgrade)
      )
      .withNoise()
      .build()

  let
    mixA = MixProtocol.new(nodeIndexA, numberOfNodes, switchA)
    mixB = MixProtocol.new(nodeIndexB, numberOfNodes, switchB)

  switchA.mount(mixA)
  switchB.mount(mixB)

  let switchFut = await allFinished(switchA.start(), switchB.start())

  echo "> Dialing [PRE]"
  var conn = await switchB.dial(switchA.peerInfo.peerId, @[addressA], @[MixProtocolID])
  echo "> Dialing [POST]"
  echo conn.shortLog()

  let msg = newSeq[byte](2413)
  echo "> Writing LP"
  await conn.writeLp(msg)
  echo "> Writing LP [DONE]"
  await sleepAsync(5000)

proc main() =
  waitFor(attempt())

main()
