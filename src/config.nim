const
  k* = 16 # Security parameter
  r* = 5 # Maximum path length
  t* = 3 # t.k - combined length of next hop address and delay
  L* = 3 # Path length
  powSize* = 12 # 4 byte nonce + 8 byte timestamp
  alphaSize* = 32 # Group element
  betaSize* = ((r * (t + 1)) + 1) * k # (r(t+1)+1)k bytes
  gammaSize* = 16 # Output of HMAC-SHA-256, truncated to 16 bytes
  headerSize* = alphaSize + betaSize + gammaSize # Total header size
  delaySize* = 2 # Delay size
  addrSize* = (t * k) - delaySize # Address size
  messageSize* = 2413 - headerSize - k - powSize # Size of the message itself
  payloadSize* = messageSize + powSize + k # Total payload size
  packetSize* = headerSize + payloadSize # Total packet size
