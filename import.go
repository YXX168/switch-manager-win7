package main

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
)

const maxImportDevices = 1000

func (a *App) importTemplateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="switch-import-template.csv"`)
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"name", "host", "vendor", "model", "location", "sshPort", "username", "password", "snmpEnabled", "snmpPort", "community"})
	writer.Flush()
}

func (a *App) importDevicesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.settings.configured() && !a.requireAdmin(w, r) {
		return
	}
	var body struct {
		Devices []DeviceInput `json:"devices"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	if len(body.Devices) == 0 {
		writeError(w, 400, fmt.Errorf("导入文件中没有设备数据"))
		return
	}
	if len(body.Devices) > maxImportDevices {
		writeError(w, 400, fmt.Errorf("一次最多导入 %d 台设备", maxImportDevices))
		return
	}
	devices := make([]Device, 0, len(body.Devices))
	seen := make(map[string]int)
	for i, input := range body.Devices {
		d, err := deviceFromInput(input, nil)
		if err != nil {
			writeError(w, 400, fmt.Errorf("第 %d 行：%v", i+2, err))
			return
		}
		key := strings.ToLower(d.Host)
		if first, ok := seen[key]; ok {
			writeError(w, 400, fmt.Errorf("第 %d 行与第 %d 行的管理地址重复：%s", i+2, first+2, d.Host))
			return
		}
		seen[key] = i
		devices = append(devices, d)
	}
	if err := a.store.importMany(devices); err != nil {
		writeError(w, 409, err)
		return
	}
	a.logAction("批量导入设备", Device{}, true, fmt.Sprintf("成功导入 %d 台设备", len(devices)))
	writeJSON(w, http.StatusCreated, map[string]int{"imported": len(devices)})
}

func (s *Store) importMany(devices []Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := make(map[string]bool, len(s.devices))
	for _, d := range s.devices {
		existing[strings.ToLower(d.Host)] = true
	}
	for _, d := range devices {
		key := strings.ToLower(d.Host)
		if existing[key] {
			return fmt.Errorf("管理地址已存在：%s", d.Host)
		}
		existing[key] = true
	}
	originalLen := len(s.devices)
	s.devices = append(s.devices, devices...)
	if err := s.saveLocked(); err != nil {
		s.devices = s.devices[:originalLen]
		return err
	}
	return nil
}
