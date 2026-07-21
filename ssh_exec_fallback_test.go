package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestRunSSHFallsBackWhenExecHasNoExitStatus(t *testing.T) {
	listener, err := startExecRejectingSSHServer()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	cipher, err := protectString("test-password")
	if err != nil {
		t.Fatal(err)
	}
	a := &App{dataDir: t.TempDir(), knownHosts: t.TempDir() + "/known_hosts", sessions: map[string]time.Time{}, loginFails: map[string]*loginFailure{}}
	d := Device{ID: "test", Name: "Legacy-SW", Host: host, Vendor: "Huawei", SSHPort: port, Username: "admin", PasswordCipher: cipher}
	out, err := a.runSSH(d, "display version")
	if err != nil {
		t.Fatalf("fallback query failed: %v", err)
	}
	if !strings.Contains(out, "LEGACY SWITCH VERSION") {
		t.Fatalf("unexpected output: %q", out)
	}
}

func startExecRejectingSSHServer() (net.Listener, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}
	config := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if c.User() != "admin" || string(password) != "test-password" {
			return nil, fmt.Errorf("bad credentials")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		conn, channels, _, serverErr := ssh.NewServerConn(raw, config)
		if serverErr != nil {
			return
		}
		defer conn.Close()
		for incoming := range channels {
			if incoming.ChannelType() != "session" {
				_ = incoming.Reject(ssh.UnknownChannelType, "session only")
				continue
			}
			channel, requests, acceptErr := incoming.Accept()
			if acceptErr != nil {
				continue
			}
			go handleLegacySession(channel, requests)
		}
	}()
	return listener, nil
}

func handleLegacySession(channel ssh.Channel, requests <-chan *ssh.Request) {
	for request := range requests {
		switch request.Type {
		case "exec":
			_ = request.Reply(true, nil)
			_ = channel.Close()
			return
		case "pty-req":
			_ = request.Reply(true, nil)
		case "shell":
			_ = request.Reply(true, nil)
			_, _ = channel.Write([]byte("\r\n<LEGACY-SW>"))
			go serveLegacyShell(channel)
			return
		default:
			_ = request.Reply(false, nil)
		}
	}
}

func serveLegacyShell(channel ssh.Channel) {
	defer channel.Close()
	scanner := bufio.NewScanner(channel)
	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())
		switch {
		case command == "":
			_, _ = channel.Write([]byte("\r\n<LEGACY-SW>"))
		case strings.HasPrefix(command, "screen-length"):
			_, _ = channel.Write([]byte("\r\nInfo: paging disabled\r\n<LEGACY-SW>"))
		case command == "display version":
			_, _ = channel.Write([]byte("\r\nLEGACY SWITCH VERSION 1.0\r\n<LEGACY-SW>"))
		case command == "quit":
			return
		default:
			_, _ = channel.Write([]byte("\r\nError: unknown command\r\n<LEGACY-SW>"))
		}
	}
}

func TestTrailingTerminalPromptDetection(t *testing.T) {
	if !hasTrailingTerminalPrompt("output\r\n<SW-01>") {
		t.Fatal("Huawei-style prompt not detected")
	}
	if !hasTrailingTerminalPrompt("output\n[SW-01]") {
		t.Fatal("system-view prompt not detected")
	}
	if hasTrailingTerminalPrompt("display vlan\nVLAN 10") {
		t.Fatal("ordinary output mistaken for prompt")
	}
}
