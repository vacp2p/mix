import chronicles, chronos, std/sysrand
import libp2p/[crypto/secp, multiaddress, builders, transports/tcptransport]
import ./noresp_ping

proc createSwitch(multiAddr: MultiAddress): Switch =
  let
    inTimeout: Duration = 5.minutes
    outTimeout: Duration = 5.minutes
  result = SwitchBuilder
    .new()
    .withAddress(multiAddr)
    .withRng(crypto.newRng())
    .withMplex(inTimeout, outTimeout)
    .withTcpTransport()
    .withNoise()
    .build()

proc noresp_ping_test() {.async.} =
  let
    addressA = MultiAddress.init("/ip4/0.0.0.0/tcp/8081").value()
    addressB = MultiAddress.init("/ip4/0.0.0.0/tcp/8082").value()
    switchA = createSwitch(addressA)
    switchB = createSwitch(addressB)
    rng = newRng()
    norespPingA = NoRespPing.new(rng = rng)
    norespPingB = NoRespPing.new(rng = rng)
  switchA.mount(norespPingA)
  switchB.mount(norespPingB)
  discard await allFinished(switchA.start(), switchB.start())
  var conn =
    await switchA.dial(switchB.peerInfo.peerId, @[addressB], @[NoRespPingCodec])

  let ping = await norespPingA.noRespPing(conn)
  info "Received ping: ", ping = ping
  await sleepAsync(1.seconds)

when isMainModule:
  waitFor(noresp_ping_test())
