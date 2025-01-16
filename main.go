package main

import (
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func main() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// This callback is vulnerable to GHSA-v778-237x-gjrc
			if key == nil {
				return nil, fmt.Errorf("no public key provided")
			}
			// Normally, you would check the key against a list of authorized keys
			return nil, nil
		},
	}

	privateBytes := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1z...
-----END RSA PRIVATE KEY-----`)
	_, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Fatal("Failed to listen on 2022: ", err)
	}
	defer listener.Close()

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("Failed to accept incoming connection: ", err)
		}

		_, _, _, err = ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Println("Failed to handshake: ", err)
			continue
		}

		log.Println("New SSH connection established")
	}
}
