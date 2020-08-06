package ssh

import (
	"fmt"
)

// directTCPIP request - See RFC4254 7.2 TCP/IP Forwarding Channels
// https://tools.ietf.org/html/rfc4254#page-18
type directTCPIP struct {
	Addr           string
	Rport          uint32
	OriginatorAddr string
	OriginatorPort uint32
}

func (f *directTCPIP) To() string {
	return fmt.Sprintf("%s:%d", f.Addr, f.Rport)
}
