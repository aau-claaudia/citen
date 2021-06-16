package main

import (
	"log"
	"net"
	"os"

	"github.com/aau-claaudia/citen/ssh"
)

func main() {

	listenAt := os.Getenv("CITEN_LISTEN")

	// default listen to localhost at a random port
	if listenAt == "" {
		listenAt = "127.0.0.1:0"
	}

	l, err := net.Listen("tcp", listenAt)
	if err != nil {
		log.Fatalf("unable to listen for ssh traffic: %s", err)
	}

	log.Print("Listening on ", l.Addr())
	sshServer := &ssh.Server{}
	err = sshServer.Serve(l)
	log.Fatalf("failed serving ssh: %s", err)
}
