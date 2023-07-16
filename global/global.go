package global

var CIDR *string
var Pingis *bool
var Portstring *string
var Alive_list []string
var Alive_port map[string][]int = make(map[string][]int)
var Raddr string
var Mask int
var Default_port []int
var Scan_port []int
