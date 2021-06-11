package keyscan

import (
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func IsAllowed(target, username string, publickey []byte) bool {
	log.Printf("Trying %s@%s with key", username, target)
	key, err := ssh.ParsePublicKey(publickey)

	if err != nil {
		log.Printf("unable to parse publickey: %s", err)
		return false
	}

	signer := &fakeSigner{
		key: key,
	}

	conf := &ssh.ClientConfig{
		User: username,
	}

	signers := func() ([]ssh.Signer, error) {
		return []ssh.Signer{signer}, nil
	}

	conf.Auth = []ssh.AuthMethod{
		ssh.PublicKeysCallback(signers),
	}

	conf.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	c, err := ssh.Dial("tcp", enforceDefaultPort(target), conf)
	if err != nil && err.Error() == "ssh: handshake failed: fakeSigned" {
		return true
	}

	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}

	c.Close()

	return false
}

func enforceDefaultPort(target string) string {
	h, _, _ := net.SplitHostPort(target)
	return h + ":22"
}
