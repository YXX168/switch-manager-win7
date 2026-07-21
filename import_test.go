package main

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestImportManyIsAtomicOnDuplicate(t *testing.T) {
	dir := t.TempDir()
	s := &Store{path: filepath.Join(dir, "devices.json"), devices: []Device{{ID: "old", Name: "Existing", Host: "192.0.2.1"}}}
	items := []Device{{ID: "new1", Name: "New", Host: "192.0.2.2", CreatedAt: time.Now()}, {ID: "new2", Name: "Duplicate", Host: "192.0.2.1", CreatedAt: time.Now()}}
	if err := s.importMany(items); err == nil {
		t.Fatal("expected duplicate import to fail")
	}
	if len(s.devices) != 1 {
		t.Fatalf("atomic import changed store length: %d", len(s.devices))
	}
	if _, err := os.Stat(s.path); !os.IsNotExist(err) {
		t.Fatalf("failed import should not write file")
	}
}

func TestChineseTemplateAndPlaintextExport(t *testing.T) {
	passwordCipher, err := protectString("ssh-plain")
	if err != nil {
		t.Fatal(err)
	}
	communityCipher, err := protectString("snmp-plain")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	a := &App{dataDir: dir, settings: &SettingsStore{}, store: &Store{devices: []Device{{Name: "SW-01", Host: "192.0.2.31", Vendor: "Huawei", SSHPort: 22, Username: "admin", PasswordCipher: passwordCipher, SNMPEnabled: true, SNMPPort: 161, CommunityCipher: communityCipher}}}}
	templateRecorder := httptest.NewRecorder()
	a.importTemplateHandler(templateRecorder, httptest.NewRequest(http.MethodGet, "/api/import/template", nil))
	if templateRecorder.Code != 200 {
		t.Fatalf("template status %d", templateRecorder.Code)
	}
	templateRows, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(templateRecorder.Body.Bytes(), []byte{0xEF, 0xBB, 0xBF}))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if templateRows[0][0] != "设备名称" || templateRows[0][7] != "SSH密码" {
		t.Fatalf("unexpected template headers: %v", templateRows[0])
	}
	exportRecorder := httptest.NewRecorder()
	a.exportDevicesHandler(exportRecorder, httptest.NewRequest(http.MethodGet, "/api/export/devices", nil))
	if exportRecorder.Code != 200 {
		t.Fatalf("export status %d", exportRecorder.Code)
	}
	rows, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(exportRecorder.Body.Bytes(), []byte{0xEF, 0xBB, 0xBF}))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][7] != "ssh-plain" || rows[1][10] != "snmp-plain" {
		t.Fatalf("plaintext credentials missing: %v", rows)
	}
	view := viewOf(a.store.devices[0])
	if view.Password != "ssh-plain" || view.Community != "snmp-plain" {
		t.Fatalf("device view credentials missing: %+v", view)
	}
}

func TestImportManyPersistsAllRows(t *testing.T) {
	dir := t.TempDir()
	s := &Store{path: filepath.Join(dir, "devices.json"), devices: []Device{}}
	items := []Device{{ID: "1", Name: "One", Host: "192.0.2.11"}, {ID: "2", Name: "Two", Host: "192.0.2.12"}}
	if err := s.importMany(items); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.devices) != 2 {
		t.Fatalf("got %d devices", len(loaded.devices))
	}
}

func TestImportManyRejectsDuplicatesInsideBatch(t *testing.T) {
	dir := t.TempDir()
	s := &Store{path: filepath.Join(dir, "devices.json"), devices: []Device{}}
	items := []Device{{ID: "1", Name: "One", Host: "192.0.2.21"}, {ID: "2", Name: "Two", Host: "192.0.2.21"}}
	if err := s.importMany(items); err == nil {
		t.Fatal("expected duplicate inside batch to fail")
	}
	if len(s.devices) != 0 {
		t.Fatal("duplicate batch must be atomic")
	}
}
