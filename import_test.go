package main

import (
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
