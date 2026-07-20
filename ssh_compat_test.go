package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestLegacySSHConfigNegotiatesGroup1(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if string(password) != "test" {
			return nil, fmt.Errorf("bad password")
		}
		return nil, nil
	}}
	serverConfig.KeyExchanges = []string{"diffie-hellman-group1-sha1"}
	serverConfig.AddHostKey(signer)

	a := &App{}
	modern := a.sshClientConfig(Device{Username: "admin"}, "test", false)
	modern.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	if err := testSSHHandshake(serverConfig, modern); err == nil || !isSSHAlgorithmError(err) {
		t.Fatalf("modern config should reject group1-only server, got %v", err)
	}
	legacy := a.sshClientConfig(Device{Username: "admin"}, "test", true)
	legacy.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	if err := testSSHHandshake(serverConfig, legacy); err != nil {
		t.Fatalf("legacy config should connect to group1-only server: %v", err)
	}
}

func testSSHHandshake(serverConfig *ssh.ServerConfig, clientConfig *ssh.ClientConfig) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		conn, _, _, _ := ssh.NewServerConn(raw, serverConfig)
		if conn != nil {
			_ = conn.Close()
		} else {
			_ = raw.Close()
		}
	}()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	clientConfig.Timeout = 2 * time.Second
	conn, _, _, err := ssh.NewClientConn(raw, listener.Addr().String(), clientConfig)
	if conn != nil {
		_ = conn.Close()
	}
	return err
}

func TestSSHAlgorithmErrorDetection(t *testing.T) {
	if !isSSHAlgorithmError(fmt.Errorf("ssh: no common algorithm for key exchange")) {
		t.Fatal("expected algorithm mismatch")
	}
	if isSSHAlgorithmError(fmt.Errorf("connection refused")) {
		t.Fatal("connection errors must not trigger legacy retry")
	}
	if !strings.Contains(strings.Join((&App{}).sshClientConfig(Device{Username: "x"}, "x", true).KeyExchanges, ","), "diffie-hellman-group1-sha1") {
		t.Fatal("legacy group1 missing")
	}
}
