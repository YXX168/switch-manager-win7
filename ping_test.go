package main

import "testing"

func TestPingOutputIndicatesReply(t *testing.T) {
	responsive := [][]byte{[]byte("Reply from 192.0.2.1: bytes=32 time<1ms TTL=64"), []byte("来自 192.0.2.1 的回复: 字节=32 时间<1ms TTL=128"), []byte("ttl=255")}
	for _, output := range responsive {
		if !pingOutputIndicatesReply(output) {
			t.Fatalf("expected reply in %q", output)
		}
	}
	failed := [][]byte{[]byte("Request timed out."), []byte("请求超时。"), []byte("Destination host unreachable")}
	for _, output := range failed {
		if pingOutputIndicatesReply(output) {
			t.Fatalf("unexpected reply in %q", output)
		}
	}
}
