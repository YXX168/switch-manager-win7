package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func newHostTestKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestHostKeyTrustOnFirstUseAndRejectChangedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	a := &App{knownHosts: path}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
	key := newHostTestKey(t)
	callback := a.hostKeyCallback()
	if err := callback("192.0.2.10:22", remote, key); err != nil {
		t.Fatalf("first use failed: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("192.0.2.10:22", remote, key); err != nil {
		t.Fatalf("known key failed: %v", err)
	}
	if err := callback("192.0.2.10:22", remote, newHostTestKey(t)); err == nil {
		t.Fatal("changed host key was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatalf("repeated or changed key modified trust records: %v", err)
	}
}

func TestHostKeyRejectsMalformedTrustFileWithoutAppending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
	key := newHostTestKey(t)
	// Include a valid entry before the broken line to prove parse errors cannot
	// silently discard an otherwise existing trust database.
	content := knownhosts.Line([]string{"192.0.2.10"}, key) + "\ninvalid known-host entry\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	a := &App{knownHosts: path}
	if err := a.hostKeyCallback()("192.0.2.10:22", remote, newHostTestKey(t)); err == nil {
		t.Fatal("malformed trust database allowed a new host key")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != content {
		t.Fatalf("malformed trust database was modified: %v", err)
	}
}

func TestHostKeyRejectsUnreadableTrustPath(t *testing.T) {
	a := &App{knownHosts: t.TempDir()}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
	if err := a.hostKeyCallback()("192.0.2.10:22", remote, newHostTestKey(t)); err == nil {
		t.Fatal("directory used as a trust file was accepted")
	}
}
