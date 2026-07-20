//go:build windows

package main

import (
	"encoding/base64"
	"fmt"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var crypt32 = syscall.NewLazyDLL("crypt32.dll")
var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var cryptProtectData = crypt32.NewProc("CryptProtectData")
var cryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
var localFree = kernel32.NewProc("LocalFree")

func blobFromBytes(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{uint32(len(b)), &b[0]}
}
func bytesFromBlob(b dataBlob) []byte {
	if b.cbData == 0 {
		return nil
	}
	src := unsafe.Slice(b.pbData, b.cbData)
	out := make([]byte, len(src))
	copy(out, src)
	return out
}
func protectString(s string) (string, error) {
	in := blobFromBytes([]byte(s))
	var out dataBlob
	r, _, e := cryptProtectData.Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return "", fmt.Errorf("Windows 凭据加密失败：%v", e)
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return base64.StdEncoding.EncodeToString(bytesFromBlob(out)), nil
}
func unprotectString(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	in := blobFromBytes(raw)
	var out dataBlob
	r, _, e := cryptUnprotectData.Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return "", fmt.Errorf("Windows 凭据解密失败：%v", e)
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return string(bytesFromBlob(out)), nil
}
