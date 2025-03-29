{.push raises: [].}

import metrics

declarePublicGauge mix_messages_recvd,
  "number of mix messages received", ["type"]

declarePublicGauge mix_messages_forwarded,
  "number of mix messages forwarded", ["type"]

declarePublicGauge mix_messages_error,
  "number of mix messages failed processing",  ["type", "error"]