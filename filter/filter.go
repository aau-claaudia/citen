package filter

import (
	"log"
	"net"
	"os"
)

var allowed *net.IPNet

func init() {
	c := os.Getenv("JUMP_ALLOW_CIDR")
	if c == "" {
		_, allowed, _ = net.ParseCIDR("0.0.0.0/0")
		return
	}

	var err error
	_, allowed, err = net.ParseCIDR(c)
	if err != nil {
		log.Fatalf("unable to parse CIDR %s: %s", c, err)
	}
}

// IsAllowed checks if an ip address is OK to connect to
func IsAllowed(i string) bool {
	ip := net.ParseIP(i)
	if ip == nil {
		return false
	}

	return allowed.Contains(ip)
}
