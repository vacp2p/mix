import chronos
import libp2p/[protocols/ping, protocols/protocol, stream/connection,
    stream/lpstream, switch]
import  mix_message, mix_protocol

const PingSize = 32

type
  ProtocolWrapper[T: LPProtocol] = ref object
    originalProtocol: T  # The original protocol (e.g., Ping or GossipSub)
    mixProtocol: MixProtocol    # The mix protocol for anonymization

proc newProtocolWrapper[T: LPProtocol](original: T, mixProto: MixProtocol): ProtocolWrapper[T] =
  ProtocolWrapper[T](originalProtocol: original, mixProtocol: mixProto)

proc getProtocolType[T: LPProtocol](wrapper: ProtocolWrapper[T]): ProtocolType =
  when T is Ping:
    ProtocolType.Ping
  elif T is GossipSub:
    ProtocolType.GossipSub
  else:
    ProtocolType.OtherProtocol

proc anonymizeAndSend[T: LPProtocol](wrapper: ProtocolWrapper[T], msg: seq[byte], dest: MultiAddress) {.async.} =
  let protocolType = wrapper.getProtocolType()
  let mixMsg = initMixMessage(msg, protocolType)
  let serializedMsg = serializeMixMessage(mixMsg)
  await wrapper.mixProtocol.anonymizeLocalProtocolSend(serializedMsg, $dest)

proc ping*[T: Ping](wrapper: ProtocolWrapper[T], dest: MultiAddress) {.async.} =
  var randomBuf: array[PingSize, byte]
  wrapper.switch.rng.randomBytes(randomBuf)
  await wrapper.anonymizeAndSend(@randomBuf, destMultiAddr)