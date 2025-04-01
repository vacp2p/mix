{.push raises: [].}

import metrics

declarePublicCounter mix_messages_recvd,
  "number of mix messages received", ["type"]

declarePublicCounter mix_messages_forwarded,
  "number of mix messages forwarded", ["type"]

declarePublicCounter mix_messages_error,
  "number of mix messages failed processing",  ["type", "error"]