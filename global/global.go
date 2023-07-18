package global

var CIDR *string
var Pingis *bool
var Portstring *string
var Alive_list []string
var Alive_port map[string][]int = make(map[string][]int)
var Ident_server map[string]map[int]([6]string) = make(map[string]map[int][6]string)

type Port_service struct {
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	Service_app []string `json:"service_app"`
}
type Ip_info struct {
	Service    []Port_service `json:"service"`
	Deviceinfo []string       `json:"deviceinfo"`
	Honeypot   []string       `json:"honeypot"`
}

var Net_info map[string](*Ip_info) = make(map[string](*Ip_info))
var Final_info map[string](Ip_info) = make(map[string](Ip_info))
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
