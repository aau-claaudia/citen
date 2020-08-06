package ssh

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/fasmide/jump/filter"
	"golang.org/x/crypto/ssh"
)

// Server represents a listening ssh server
type Server struct {
	// Config is the ssh serverconfig
	Config *ssh.ServerConfig
}

// Serve will accept ssh connections
func (s *Server) Serve(l net.Listener) error {
	if s.Config == nil {
		var err error
		s.Config, err = DefaultConfig()

		if err != nil {
			return fmt.Errorf("unable to set default ssh config: %w", err)
		}
	}

	for {
		nConn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept incoming connection: %w", err)
		}
		go s.accept(nConn)
	}

}

// DefaultConfig generates a default ssh.ServerConfig
func DefaultConfig() (*ssh.ServerConfig, error) {
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}

	signer, err := signer()
	if err != nil {
		return nil, err
	}
	config.AddHostKey(signer)

	return config, nil
}

func signer() (ssh.Signer, error) {
	p := "id_rsa"
	if os.Getenv("CONFIGURATION_DIRECTORY") != "" {
		p = fmt.Sprintf("%s/%s", os.Getenv("CONFIGURATION_DIRECTORY"), p)
	}

	privateBytes, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("Failed to load private key: %s", err)
	}

	signer, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key: %s", err)
	}

	return signer, nil

}

func (s *Server) accept(c net.Conn) {
	// auth timeout
	// only give people 10 seconds to ssh handshake and authenticate themselves
	authTimer := time.AfterFunc(10*time.Second, func() {
		c.Close()
	})

	// ssh handshake and auth
	conn, chans, reqs, err := ssh.NewServerConn(c, s.Config)
	if err != nil {
		log.Print("failed to handshake: ", err)
		return
	}

	authTimer.Stop()

	log.Printf("accepted session from %s", conn.RemoteAddr())

	// The incoming Request channel must be serviced.
	go func(reqs <-chan *ssh.Request) {
		for req := range reqs {
			if req.Type == "keepalive@openssh.com" {
				req.Reply(true, nil)
				continue
			}
			req.Reply(false, nil)

		}
	}(reqs)

	// Service the incoming Channel channel.
	for channelRequest := range chans {

		if channelRequest.ChannelType() != "direct-tcpip" {
			channelRequest.Reject(ssh.Prohibited, fmt.Sprintf("no %s allowed, only direct-tcpip", channelRequest.ChannelType()))
			continue
		}

		forwardInfo := directTCPIP{}
		err := ssh.Unmarshal(channelRequest.ExtraData(), &forwardInfo)
		if err != nil {
			log.Printf("unable to unmarshal forward information: %s", err)
			channelRequest.Reject(ssh.UnknownChannelType, "failed to parse forward information")
			continue
		}

		if !filter.IsAllowed(forwardInfo.Addr) {
			channelRequest.Reject(ssh.Prohibited, fmt.Sprintf("%s is not in my allowed forward list", forwardInfo.Addr))
			continue
		}

		forwardConnection, err := net.Dial("tcp", forwardInfo.To())

		if err != nil {
			log.Printf("unable to dial %s: %s", forwardInfo.To(), err)
			channelRequest.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to dial %s: %s", forwardInfo.To(), err))
			continue
		}

		// Accept channel from ssh client
		log.Printf("accepting forward to %s:%d", forwardInfo.Addr, forwardInfo.Rport)
		channel, requests, err := channelRequest.Accept()
		if err != nil {
			log.Print("could not accept forward channel: ", err)
			continue
		}

		go ssh.DiscardRequests(requests)

		// pass traffic in both directions - close channel when io.Copy returns
		go func() {
			io.Copy(forwardConnection, channel)
			channel.Close()
		}()
		go func() {
			io.Copy(channel, forwardConnection)
			channel.Close()
		}()
	}

	log.Print("client went away ", conn.RemoteAddr())
}
