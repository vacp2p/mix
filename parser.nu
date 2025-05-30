0..4 
| each { 
  |i|  docker logs node-($i) 
  | lines 
  | where {|l| ($l) =~ "d=5" }
}
