package filter

import (
	"log"
	"net"
	"os"
	"strings"
)

var allowed []*net.IPNet

func init() {
	c := os.Getenv("JUMP_ALLOW")
	if c == "" {
		_, a, _ := net.ParseCIDR("0.0.0.0/0")
		allowed = []*net.IPNet{a}
		return
	}

	split := strings.Split(c, ",")
	allowed = make([]*net.IPNet, len(split))

	for i, cidr := range split {
		_, a, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("unable to parse CIDR %s: %s", c, err)
		}

		allowed[i] = a

	}

}

// IsAllowed checks if an ip address is OK to connect to
func IsAllowed(i string) bool {
	ip := net.ParseIP(i)
	if ip == nil {
		return false
	}

	// have a go at every range
	for _, cidr := range allowed {
		if cidr.Contains(ip) {
			return true
		}
	}

	// if we end up here, access should be denied
	return false
}
