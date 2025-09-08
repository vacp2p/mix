import results
import chronos
import libp2p
import ./mix/[mix_protocol, mix_node, entry_connection, exit_layer]

export results

export toConnection
export MixProtocolID
export MixProtocol

export initializeMixNodes
export getMixPubInfoByIndex
export writeMixPubInfoToFile
export writeMixNodeInfoToFile
export getMixNodeInfo
export `new`
export init
export getMaxMessageSizeForCodec
export deleteNodeInfoFolder
export deletePubInfoFolder
export MixDestination
export MixParameters
export destReadBehaviorCb
export registerDestReadBehavior
export MixNodes

proc readLp*(maxSize: int): destReadBehaviorCb =
  return proc(
      conn: Connection
  ): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]).} =
    await conn.readLp(maxSize)

proc readExactly*(nBytes: int): destReadBehaviorCb =
  return proc(
      conn: Connection
  ): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]).} =
    let buf = newSeqUninitialized[byte](nBytes)
    await conn.readExactly(addr buf[0], nBytes)
    return buf
