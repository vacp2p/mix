import unittest
import chronos
import libp2p
import libp2p/switch
import libp2p/peerinfo
import libp2p/errors
import ../src/network_manager

# Example protocol for testing
type
  TestProtocol = ref object of LPProtocol

proc newTestProtocol(): TestProtocol =
  let testProto = TestProtocol(codecs: @["/test/1.0.0"])
  
  proc handle(conn: Connection, proto: string) {.async.} =
    let msg = await conn.readLp(1024)
    await conn.writeLp("Received: " & cast[string](msg))
    await conn.close()

  testProto.handler = handle
  testProto

suite "NetworkManager Tests":

  test "Create NetworkManager":
    let nm = newNetworkManager()
    check(nm != nil)
    check(nm.switch != nil)

  test "Start and Stop NetworkManager":
    let nm = newNetworkManager()
    waitFor nm.start()
    check(nm.switch.peerInfo != nil)
    check(nm.switch.peerInfo.addrs.len > 0)
    waitFor nm.stop()
    check(nm.switch.peerInfo != nil)

  test "Mount Protocol":
    let nm = newNetworkManager()
    let testProto = newTestProtocol()
    nm.mount(testProto)
    waitFor nm.start()
    check("/test/1.0.0" in nm.switch.peerInfo.protocols)
    waitFor nm.stop()

  test "Dial Peer":
    let nm1 = newNetworkManager()
    let nm2 = newNetworkManager()
    let testProto = newTestProtocol()
    
    nm1.mount(testProto)
    nm2.mount(testProto)
    
    waitFor nm1.start()
    waitFor nm2.start()

    let peerInfo2 = nm2.getPeerInfo()
    check(peerInfo2.addrs.len > 0)
    let multiAddr2 = $peerInfo2.addrs[0] & "/p2p/" & $peerInfo2.peerId

    echo "Attempting to dial: ", multiAddr2

    proc tryDial(nm: NetworkManager, multiAddr: string): Future[bool] {.async.} =
      try:
        echo "Dialing peer..."
        let conn = await nm.dialPeer(multiAddr, "/test/1.0.0")
        if conn == nil:
          echo "Connection is nil"
          return false
        
        echo "Connection established, sending message..."
        await conn.writeLp("Hello")
        echo "Message sent, waiting for response..."
        let response = await conn.readLp(1024)
        echo "Response received: ", cast[string](response)
        if cast[string](response) != "Received: Hello":
          echo "Unexpected response"
          return false
        
        await conn.close()
        return true
      except CatchableError as e:
        echo "Error during dial: ", e.msg
        echo "Error type: ", e.name
        return false

    let success = waitFor tryDial(nm1, multiAddr2)
    check success
    if not success:
      echo "Dial peer operation failed"

    waitFor nm1.stop()
    waitFor nm2.stop()

  test "Get PeerInfo":
    let nm = newNetworkManager()
    waitFor nm.start()
    let peerInfo = nm.getPeerInfo()
    check(peerInfo != nil)
    check(peerInfo.peerId != PeerId.default)
    check(peerInfo.addrs.len > 0)
    waitFor nm.stop()

  test "Self Dial Prevention":
    let nm = newNetworkManager()
    waitFor nm.start()
    let peerInfo = nm.getPeerInfo()
    let multiAddr = $peerInfo.addrs[0] & "/p2p/" & $peerInfo.peerId
    
    proc trySelfDial(manager: NetworkManager, address: string): Future[bool] {.async.} =
      try:
        discard await manager.dialPeer(address, "/test/1.0.0")
        return false
      except CatchableError as e:
        echo "Expected error during self-dial: ", e.msg
        return true

    let success = waitFor trySelfDial(nm, multiAddr)
    check success

    waitFor nm.stop()