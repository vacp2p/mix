0..4 | each { |i|  docker logs node-($i) | lines | where {|l| ($l) =~ "msgId\\\":5" }} | flatten | to json | jq
