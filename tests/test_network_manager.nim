import chronos
import libp2p
import ../src/network_manager
import unittest

# Test suite for NetworkManager
suite "NetworkManager Tests":

  # Test for creating a new NetworkManager
  test "Create NetworkManager":
    let nm = newNetworkManager()
    check nm != nil
    check nm.switch != nil

  # Test for starting the NetworkManager
  test "Start NetworkManager":
    let nm = newNetworkManager()
    await nm.start()

  # Test for stopping the NetworkManager
  test "Stop NetworkManager":
    let nm = newNetworkManager()
    await nm.start()
    await nm.stop()

  # Test dialing a connection to a known peer
  test "Dial Next Hop":
    let nm = newNetworkManager()
    await nm.start()

    # Create a MultiAddress for a known peer (replace with a valid address for testing)
    let testMultiAddr = "/ip4/127.0.0.1/tcp/4242/mix/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
    
    # Dial the next hop
    let conn: Connection = await nm.dialNextHop(testMultiAddr, "/mix/1.0.0")
    check conn != nil

    await conn.close()
    await nm.stop()