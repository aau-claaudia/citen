package keyscan

import (
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func IsAllowed(target, username string, publickey []byte) bool {
	// always communicate with targets default ssh daemon
	h, _, _ := net.SplitHostPort(target)
	target = h + ":22"

	key, err := ssh.ParsePublicKey(publickey)
	if err != nil {
		log.Printf("keyscan: unable to parse publickey: %s", err)
		return false
	}

	log.Printf("keyscan: trying %s against %s@%s", ssh.FingerprintSHA256(key), username, target)

	signers := func() ([]ssh.Signer, error) {
		return []ssh.Signer{&fakeSigner{
			key: key,
		}}, nil
	}

	conf := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(signers),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second * 10,
	}

	// dial up the target host
	c, err := ssh.Dial("tcp", target, conf)

	// if we receive this error we know that the fakeSigner tricked the
	// target ssh daemon into starting a pubkey auth challange, which it is unable
	// to complete as it does not have access to the private key
	//
	// TODO: upstream a crypto/ssh patch which properly wraps errors
	// so we can use errors.Is(err, ErrFakeSigned) insted of matching strings
	if err != nil && err.Error() == "ssh: handshake failed: fakeSigned" {
		return true
	}

	if err != nil {
		log.Printf("keyscan: unable to verify %s against %s@%s: %s",
			ssh.FingerprintSHA256(key),
			username,
			target,
			err.Error(),
		)

		return false
	}

	// this place is somewhat weird - if we reach this, the fakeSigner
	// succeeded in authenticating without a private key
	//
	// in any case - this was not what we where looking for
	// and i think we should assume the target ssh daemon is broken
	c.Close()
	return false
}
