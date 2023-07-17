package global

var CIDR *string
var Pingis *bool
var Portstring *string
var Alive_list []string
var Alive_port map[string][]int = make(map[string][]int)
var Ident_server map[string]map[int]([6]string) = make(map[string]map[int][6]string)
var Raddr string
var Mask int
var Default_port []int
var Scan_port []int
var Title [6]string = [6]string{
	"Name:",
	"Device Type:",
	"Info:",
	"Operating System:",
	"Vendor Product Name:",
	"Version:",
}
