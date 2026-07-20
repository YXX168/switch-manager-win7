package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

//go:embed web/*
var webFiles embed.FS

type Device struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Host            string    `json:"host"`
	Vendor          string    `json:"vendor"`
	Model           string    `json:"model,omitempty"`
	Location        string    `json:"location,omitempty"`
	SSHPort         int       `json:"sshPort"`
	Username        string    `json:"username"`
	PasswordCipher  string    `json:"passwordCipher,omitempty"`
	SNMPEnabled     bool      `json:"snmpEnabled"`
	SNMPPort        uint16    `json:"snmpPort"`
	CommunityCipher string    `json:"communityCipher,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type DeviceView struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Host         string    `json:"host"`
	Vendor       string    `json:"vendor"`
	Model        string    `json:"model,omitempty"`
	Location     string    `json:"location,omitempty"`
	SSHPort      int       `json:"sshPort"`
	Username     string    `json:"username"`
	HasPassword  bool      `json:"hasPassword"`
	SNMPEnabled  bool      `json:"snmpEnabled"`
	SNMPPort     uint16    `json:"snmpPort"`
	HasCommunity bool      `json:"hasCommunity"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type DeviceInput struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Vendor      string `json:"vendor"`
	Model       string `json:"model"`
	Location    string `json:"location"`
	SSHPort     int    `json:"sshPort"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	SNMPEnabled bool   `json:"snmpEnabled"`
	SNMPPort    uint16 `json:"snmpPort"`
	Community   string `json:"community"`
}

type Store struct {
	mu      sync.RWMutex
	path    string
	devices []Device
}

type App struct {
	store      *Store
	dataDir    string
	knownHosts string
	sshHostMu  sync.Mutex
	logMu      sync.Mutex
	settings   *SettingsStore
	sessionMu  sync.Mutex
	sessions   map[string]time.Time
	loginMu    sync.Mutex
	loginFails map[string]*loginFailure
}

type AuditEntry struct {
	Time       time.Time `json:"time"`
	Action     string    `json:"action"`
	DeviceID   string    `json:"deviceId,omitempty"`
	DeviceName string    `json:"deviceName,omitempty"`
	Success    bool      `json:"success"`
	Detail     string    `json:"detail"`
}

func main() {
	port := flag.Int("port", 8787, "本地服务端口")
	dataFlag := flag.String("data", "", "数据目录")
	noBrowser := flag.Bool("no-browser", false, "不自动打开浏览器")
	flag.Parse()

	dataDir := *dataFlag
	if dataDir == "" {
		exe, err := os.Executable()
		if err != nil {
			log.Fatal(err)
		}
		dataDir = filepath.Join(filepath.Dir(exe), "data")
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "backups"), 0700); err != nil {
		log.Fatal(err)
	}

	store, err := loadStore(filepath.Join(dataDir, "devices.json"))
	if err != nil {
		log.Fatal(err)
	}
	settings, err := loadSettings(filepath.Join(dataDir, "settings.json"))
	if err != nil {
		log.Fatal(err)
	}
	app := &App{store: store, dataDir: dataDir, knownHosts: filepath.Join(dataDir, "known_hosts"), settings: settings, sessions: make(map[string]time.Time), loginFails: make(map[string]*loginFailure)}

	mux := http.NewServeMux()
	app.routes(mux)
	addr := "127.0.0.1:" + strconv.Itoa(*port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("无法监听 %s：%v", addr, err)
	}
	url := "http://" + addr
	log.Printf("交换机管理系统已启动：%s", url)
	if !*noBrowser {
		go func() { time.Sleep(500 * time.Millisecond); openBrowser(url) }()
	}
	server := &http.Server{Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 15 * time.Minute, IdleTimeout: 60 * time.Second}
	log.Fatal(server.Serve(ln))
}

func loadStore(path string) (*Store, error) {
	s := &Store{path: path, devices: []Device{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 0 && json.Unmarshal(b, &s.devices) != nil {
		return nil, fmt.Errorf("设备数据文件损坏")
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.devices, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) list() []Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]Device(nil), s.devices...)
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (s *Store) get(id string) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.devices {
		if d.ID == id {
			return d, true
		}
	}
	return Device{}, false
}

func (s *Store) create(d Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.devices {
		if strings.EqualFold(x.Host, d.Host) {
			return fmt.Errorf("该管理地址已存在")
		}
	}
	s.devices = append(s.devices, d)
	return s.saveLocked()
}

func (s *Store) update(d Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.devices {
		if x.ID != d.ID && strings.EqualFold(x.Host, d.Host) {
			return fmt.Errorf("该管理地址已存在")
		}
	}
	for i := range s.devices {
		if s.devices[i].ID == d.ID {
			s.devices[i] = d
			return s.saveLocked()
		}
	}
	return os.ErrNotExist
}

func (s *Store) delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.devices {
		if s.devices[i].ID == id {
			s.devices = append(s.devices[:i], s.devices[i+1:]...)
			return s.saveLocked()
		}
	}
	return os.ErrNotExist
}

func (a *App) routes(mux *http.ServeMux) {
	mux.HandleFunc("/api/devices", a.devicesHandler)
	mux.HandleFunc("/api/devices/", a.deviceHandler)
	mux.HandleFunc("/api/dashboard", a.dashboardHandler)
	mux.HandleFunc("/api/scan", a.scanHandler)
	mux.HandleFunc("/api/batch-command", a.batchCommandHandler)
	mux.HandleFunc("/api/backup-all", a.backupAllHandler)
	mux.HandleFunc("/api/logs", a.logsHandler)
	mux.HandleFunc("/api/admin/status", a.adminStatusHandler)
	mux.HandleFunc("/api/admin/setup", a.adminSetupHandler)
	mux.HandleFunc("/api/admin/login", a.adminLoginHandler)
	mux.HandleFunc("/api/admin/logout", a.adminLogoutHandler)
	mux.HandleFunc("/api/backups", a.backupsHandler)
	mux.HandleFunc("/api/backups/", a.backupDownloadHandler)
	root, _ := fs.Sub(webFiles, "web")
	mux.Handle("/", http.FileServer(http.FS(root)))
}

func (a *App) devicesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items := a.store.list()
		views := make([]DeviceView, 0, len(items))
		for _, d := range items {
			views = append(views, viewOf(d))
		}
		writeJSON(w, http.StatusOK, views)
	case http.MethodPost:
		if a.settings.configured() && !a.requireAdmin(w, r) {
			return
		}
		var in DeviceInput
		if err := decodeJSON(r, &in); err != nil {
			writeError(w, 400, err)
			return
		}
		d, err := deviceFromInput(in, nil)
		if err != nil {
			writeError(w, 400, err)
			return
		}
		if err := a.store.create(d); err != nil {
			writeError(w, 409, err)
			return
		}
		a.logAction("添加设备", d, true, d.Host)
		writeJSON(w, http.StatusCreated, viewOf(d))
	default:
		methodNotAllowed(w)
	}
}

func (a *App) deviceHandler(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/devices/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	d, ok := a.store.get(id)
	if !ok {
		writeError(w, 404, fmt.Errorf("设备不存在"))
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, 200, viewOf(d))
		case http.MethodPut:
			if a.settings.configured() && !a.requireAdmin(w, r) {
				return
			}
			var in DeviceInput
			if err := decodeJSON(r, &in); err != nil {
				writeError(w, 400, err)
				return
			}
			updated, err := deviceFromInput(in, &d)
			if err != nil {
				writeError(w, 400, err)
				return
			}
			if err := a.store.update(updated); err != nil {
				writeError(w, 409, err)
				return
			}
			a.logAction("修改设备", updated, true, updated.Host)
			writeJSON(w, 200, viewOf(updated))
		case http.MethodDelete:
			if a.settings.configured() && !a.requireAdmin(w, r) {
				return
			}
			if err := a.store.delete(id); err != nil {
				writeError(w, 500, err)
				return
			}
			a.logAction("删除设备", d, true, d.Host)
			w.WriteHeader(204)
		default:
			methodNotAllowed(w)
		}
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	switch parts[1] {
	case "test":
		a.testDevice(w, r, d)
	case "command":
		a.commandDevice(w, r, d)
	case "backup":
		a.backupDevice(w, r, d)
	case "change":
		a.changeDevice(w, r, d)
	default:
		http.NotFound(w, r)
	}
}

func deviceFromInput(in DeviceInput, old *Device) (Device, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Host = strings.TrimSpace(in.Host)
	in.Username = strings.TrimSpace(in.Username)
	if in.Name == "" {
		return Device{}, fmt.Errorf("设备名称不能为空")
	}
	if !validHost(in.Host) {
		return Device{}, fmt.Errorf("管理地址格式不正确")
	}
	if in.Vendor != "Huawei" && in.Vendor != "H3C" {
		return Device{}, fmt.Errorf("请选择华为或华三")
	}
	if in.SSHPort == 0 {
		in.SSHPort = 22
	}
	if in.SSHPort < 1 || in.SSHPort > 65535 {
		return Device{}, fmt.Errorf("SSH 端口不正确")
	}
	if in.Username == "" {
		return Device{}, fmt.Errorf("SSH 用户名不能为空")
	}
	if in.SNMPPort == 0 {
		in.SNMPPort = 161
	}
	now := time.Now()
	d := Device{ID: randomID(), Name: in.Name, Host: in.Host, Vendor: in.Vendor, Model: strings.TrimSpace(in.Model), Location: strings.TrimSpace(in.Location), SSHPort: in.SSHPort, Username: in.Username, SNMPEnabled: in.SNMPEnabled, SNMPPort: in.SNMPPort, CreatedAt: now, UpdatedAt: now}
	if old != nil {
		d.ID = old.ID
		d.CreatedAt = old.CreatedAt
		d.PasswordCipher = old.PasswordCipher
		d.CommunityCipher = old.CommunityCipher
	}
	if in.Password != "" {
		enc, err := protectString(in.Password)
		if err != nil {
			return Device{}, err
		}
		d.PasswordCipher = enc
	}
	if d.PasswordCipher == "" {
		return Device{}, fmt.Errorf("SSH 密码不能为空")
	}
	if in.Community != "" {
		enc, err := protectString(in.Community)
		if err != nil {
			return Device{}, err
		}
		d.CommunityCipher = enc
	}
	if in.SNMPEnabled && d.CommunityCipher == "" {
		return Device{}, fmt.Errorf("启用 SNMP 时团体字不能为空")
	}
	return d, nil
}

func viewOf(d Device) DeviceView {
	return DeviceView{d.ID, d.Name, d.Host, d.Vendor, d.Model, d.Location, d.SSHPort, d.Username, d.PasswordCipher != "", d.SNMPEnabled, d.SNMPPort, d.CommunityCipher != "", d.CreatedAt, d.UpdatedAt}
}

func (a *App) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	items := a.store.list()
	huawei, h3c, snmp := 0, 0, 0
	for _, d := range items {
		if d.Vendor == "Huawei" {
			huawei++
		} else {
			h3c++
		}
		if d.SNMPEnabled {
			snmp++
		}
	}
	writeJSON(w, 200, map[string]int{"total": len(items), "huawei": huawei, "h3c": h3c, "snmp": snmp})
}

func (a *App) testDevice(w http.ResponseWriter, r *http.Request, d Device) {
	result := map[string]interface{}{}
	start := time.Now()
	pingErr := pingHost(d.Host)
	result["ping"] = map[string]interface{}{"ok": pingErr == nil, "message": errMessage(pingErr, "可达"), "elapsedMs": time.Since(start).Milliseconds()}
	start = time.Now()
	_, sshErr := a.runSSH(d, "display version")
	result["ssh"] = map[string]interface{}{"ok": sshErr == nil, "message": errMessage(sshErr, "登录成功"), "elapsedMs": time.Since(start).Milliseconds()}
	if d.SNMPEnabled {
		start = time.Now()
		info, err := readSNMP(d)
		result["snmp"] = map[string]interface{}{"ok": err == nil, "message": errMessage(err, "读取成功"), "elapsedMs": time.Since(start).Milliseconds(), "info": info}
	}
	a.logAction("设备检测", d, sshErr == nil, "Ping: "+errMessage(pingErr, "可达")+"；SSH: "+errMessage(sshErr, "成功"))
	writeJSON(w, 200, result)
}

func (a *App) commandDevice(w http.ResponseWriter, r *http.Request, d Device) {
	var body struct {
		Command string `json:"command"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	body.Command = strings.TrimSpace(body.Command)
	if body.Command == "" || len(body.Command) > 2000 {
		writeError(w, 400, fmt.Errorf("命令为空或过长"))
		return
	}
	if err := validateReadOnlyCommand(body.Command); err != nil {
		a.logAction("拦截危险命令", d, false, commandSummary(body.Command))
		writeError(w, 400, err)
		return
	}
	out, err := a.runSSH(d, body.Command)
	if err != nil {
		a.logAction("执行查询", d, false, commandSummary(body.Command)+"；"+err.Error())
		writeError(w, 502, err)
		return
	}
	a.logAction("执行查询", d, true, commandSummary(body.Command))
	writeJSON(w, 200, map[string]string{"output": out})
}

func (a *App) backupDevice(w http.ResponseWriter, r *http.Request, d Device) {
	name, err := a.createBackup(d)
	if err != nil {
		a.logAction("配置备份", d, false, err.Error())
		writeError(w, 500, err)
		return
	}
	a.logAction("配置备份", d, true, name)
	writeJSON(w, 200, map[string]string{"filename": name})
}

func (a *App) createBackup(d Device) (string, error) {
	out, err := a.runSSH(d, "display current-configuration")
	if err != nil {
		return "", err
	}
	stamp := time.Now().Format("20060102-150405.000")
	name := safeName(d.Name) + "_" + safeName(d.Host) + "_" + stamp + ".cfg"
	content := fmt.Sprintf("# Device: %s\r\n# Address: %s\r\n# Vendor: %s\r\n# Backup time: %s\r\n\r\n%s", d.Name, d.Host, d.Vendor, time.Now().Format("2006-01-02 15:04:05"), out)
	if err := os.WriteFile(filepath.Join(a.dataDir, "backups", name), []byte(content), 0600); err != nil {
		return "", err
	}
	return name, nil
}

type ProbeResult struct {
	ID        string            `json:"id"`
	Ping      bool              `json:"ping"`
	SSH       bool              `json:"ssh"`
	SNMP      *bool             `json:"snmp,omitempty"`
	LatencyMS int64             `json:"latencyMs"`
	Info      map[string]string `json:"info,omitempty"`
	Message   string            `json:"message"`
}

func (a *App) scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	items := a.store.list()
	results := make([]ProbeResult, len(items))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, d := range items {
		wg.Add(1)
		go func(i int, d Device) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = probeDevice(d)
		}(i, d)
	}
	wg.Wait()
	online := 0
	for _, x := range results {
		if x.Ping || x.SSH {
			online++
		}
	}
	a.logAction("全设备巡检", Device{}, true, fmt.Sprintf("在线 %d / 总数 %d", online, len(items)))
	writeJSON(w, 200, results)
}

func probeDevice(d Device) ProbeResult {
	r := ProbeResult{ID: d.ID}
	start := time.Now()
	pingErr := pingHost(d.Host)
	r.Ping = pingErr == nil
	r.LatencyMS = time.Since(start).Milliseconds()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(d.Host, strconv.Itoa(d.SSHPort)), 2*time.Second)
	r.SSH = err == nil
	if conn != nil {
		conn.Close()
	}
	if d.SNMPEnabled {
		ok := false
		info, e := readSNMP(d)
		ok = e == nil
		r.SNMP = &ok
		if ok {
			r.Info = info
		}
	}
	if r.Ping || r.SSH {
		r.Message = "在线"
	} else {
		r.Message = "离线或不可达"
	}
	return r
}

type BatchResult struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Success bool   `json:"success"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (a *App) batchCommandHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var body struct {
		IDs     []string `json:"ids"`
		Command string   `json:"command"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	body.Command = strings.TrimSpace(body.Command)
	if len(body.IDs) == 0 || body.Command == "" {
		writeError(w, 400, fmt.Errorf("请选择设备并填写命令"))
		return
	}
	if len(body.Command) > 2000 {
		writeError(w, 400, fmt.Errorf("命令过长"))
		return
	}
	if err := validateReadOnlyCommand(body.Command); err != nil {
		a.logAction("拦截批量危险命令", Device{}, false, commandSummary(body.Command))
		writeError(w, 400, err)
		return
	}
	results := make([]BatchResult, len(body.IDs))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, id := range body.IDs {
		d, ok := a.store.get(id)
		if !ok {
			results[i] = BatchResult{ID: id, Error: "设备不存在"}
			continue
		}
		wg.Add(1)
		go func(i int, d Device) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out, err := a.runSSH(d, body.Command)
			results[i] = BatchResult{ID: d.ID, Name: d.Name, Success: err == nil, Output: out}
			if err != nil {
				results[i].Error = err.Error()
			}
			a.logAction("批量查询", d, err == nil, commandSummary(body.Command))
		}(i, d)
	}
	wg.Wait()
	writeJSON(w, 200, results)
}

func (a *App) backupAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	items := a.store.list()
	results := make([]BatchResult, len(items))
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for i, d := range items {
		wg.Add(1)
		go func(i int, d Device) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			name, err := a.createBackup(d)
			results[i] = BatchResult{ID: d.ID, Name: d.Name, Success: err == nil, Output: name}
			if err != nil {
				results[i].Error = err.Error()
			}
			a.logAction("批量备份", d, err == nil, errMessage(err, name))
		}(i, d)
	}
	wg.Wait()
	writeJSON(w, 200, results)
}

func (a *App) runSSH(d Device, command string) (string, error) {
	password, err := unprotectString(d.PasswordCipher)
	if err != nil {
		return "", fmt.Errorf("无法解密 SSH 密码：%v", err)
	}
	config := &ssh.ClientConfig{User: d.Username, Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: a.hostKeyCallback(), Timeout: 7 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var client *ssh.Client
	done := make(chan error, 1)
	go func() {
		var e error
		client, e = ssh.Dial("tcp", net.JoinHostPort(d.Host, strconv.Itoa(d.SSHPort)), config)
		done <- e
	}()
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("SSH 连接超时")
	case err := <-done:
		if err != nil {
			return "", friendlySSHError(err)
		}
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var b strings.Builder
	session.Stdout = &b
	session.Stderr = &b
	done = make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case <-ctx.Done():
		return b.String(), fmt.Errorf("命令执行超时")
	case err := <-done:
		if err != nil && b.Len() == 0 {
			return "", fmt.Errorf("命令执行失败：%v", err)
		}
	}
	return strings.TrimSpace(b.String()), nil
}

func (a *App) hostKeyCallback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		a.sshHostMu.Lock()
		defer a.sshHostMu.Unlock()
		cb, err := knownhosts.New(a.knownHosts)
		if err == nil {
			if e := cb(hostname, remote, key); e == nil {
				return nil
			} else {
				var ke *knownhosts.KeyError
				if !errors.As(e, &ke) || len(ke.Want) > 0 {
					return fmt.Errorf("SSH 主机密钥发生变化，请确认设备安全后删除 data\\known_hosts 中对应记录")
				}
			}
		}
		line := knownhosts.Line([]string{knownhosts.Normalize(remote.String())}, key) + "\n"
		f, e := os.OpenFile(a.knownHosts, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		_, e = f.WriteString(line)
		return e
	}
}

func readSNMP(d Device) (map[string]string, error) {
	community, err := unprotectString(d.CommunityCipher)
	if err != nil {
		return nil, err
	}
	g := &gosnmp.GoSNMP{Target: d.Host, Port: d.SNMPPort, Community: community, Version: gosnmp.Version2c, Timeout: 3 * time.Second, Retries: 1, MaxOids: 10}
	if err = g.Connect(); err != nil {
		return nil, err
	}
	defer g.Conn.Close()
	oids := []string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.1.5.0"}
	pkt, err := g.Get(oids)
	if err != nil {
		return nil, err
	}
	info := map[string]string{}
	names := []string{"description", "uptime", "sysName"}
	for i, p := range pkt.Variables {
		if i >= len(names) {
			break
		}
		if p.Type == gosnmp.TimeTicks {
			info[names[i]] = fmt.Sprintf("%v", p.Value)
		} else {
			info[names[i]] = fmt.Sprint(p.Value)
			if b, ok := p.Value.([]byte); ok {
				info[names[i]] = string(b)
			}
		}
	}
	return info, nil
}

type BackupInfo struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

func (a *App) backupsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	entries, err := os.ReadDir(filepath.Join(a.dataDir, "backups"))
	if err != nil {
		writeError(w, 500, err)
		return
	}
	out := []BackupInfo{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		i, _ := e.Info()
		out = append(out, BackupInfo{e.Name(), i.Size(), i.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Modified.After(out[j].Modified) })
	writeJSON(w, 200, out)
}
func (a *App) backupDownloadHandler(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/backups/")
	if name == "" || name != filepath.Base(name) {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(a.dataDir, "backups", name)
	if r.URL.Query().Get("view") == "1" {
		f, err := os.Open(path)
		if err != nil {
			writeError(w, 404, fmt.Errorf("备份文件不存在"))
			return
		}
		defer f.Close()
		content, err := io.ReadAll(io.LimitReader(f, 4<<20))
		if err != nil {
			writeError(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]string{"name": name, "content": string(content)})
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	http.ServeFile(w, r, path)
}

func (a *App) logAction(action string, d Device, success bool, detail string) {
	if len(detail) > 500 {
		detail = detail[:500]
	}
	entry := AuditEntry{Time: time.Now(), Action: action, DeviceID: d.ID, DeviceName: d.Name, Success: success, Detail: detail}
	b, err := json.Marshal(entry)
	if err != nil {
		return
	}
	a.logMu.Lock()
	defer a.logMu.Unlock()
	f, err := os.OpenFile(filepath.Join(a.dataDir, "audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

func (a *App) logsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	a.logMu.Lock()
	defer a.logMu.Unlock()
	b, err := os.ReadFile(filepath.Join(a.dataDir, "audit.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, 200, []AuditEntry{})
		return
	}
	if err != nil {
		writeError(w, 500, err)
		return
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	start := 0
	if len(lines) > 200 {
		start = len(lines) - 200
	}
	out := make([]AuditEntry, 0, len(lines)-start)
	for i := start; i < len(lines); i++ {
		var e AuditEntry
		if json.Unmarshal([]byte(lines[i]), &e) == nil {
			out = append(out, e)
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	writeJSON(w, 200, out)
}

var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

func validHost(s string) bool { return net.ParseIP(s) != nil || hostnameRE.MatchString(s) }
func pingHost(host string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	args := []string{"-n", "1", "-w", "1500", host}
	cmd := exec.CommandContext(ctx, "ping", args...)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("检测超时")
		}
		return fmt.Errorf("不可达")
	}
	return nil
}
func randomID() string { b := make([]byte, 8); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func safeName(s string) string {
	r := strings.NewReplacer("<", "_", ">", "_", ":", "_", "\"", "_", "/", "_", "\\", "_", "|", "_", "?", "_", "*", "_")
	return r.Replace(s)
}

func commandSummary(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\r", " ")
	s = strings.ReplaceAll(s, "\n", " / ")
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

func validateReadOnlyCommand(command string) error {
	if strings.ContainsRune(command, '\x00') || strings.Contains(command, ";") || strings.Contains(command, "&&") {
		return fmt.Errorf("安全模式已拦截：查询中不能包含命令连接符")
	}
	lines := strings.Split(strings.ReplaceAll(command, "\r", ""), "\n")
	if len(lines) > 20 {
		return fmt.Errorf("安全模式已拦截：一次最多执行 20 条只读查询")
	}
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		count++
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.EqualFold(fields[0], "display") {
			return fmt.Errorf("安全模式已拦截：仅允许以 display 开头的只读查询，不允许配置、保存、重启或清除命令")
		}
	}
	if count == 0 {
		return fmt.Errorf("查询命令不能为空")
	}
	return nil
}
func errMessage(err error, ok string) string {
	if err != nil {
		return err.Error()
	}
	return ok
}
func friendlySSHError(err error) error {
	s := err.Error()
	if strings.Contains(s, "unable to authenticate") {
		return fmt.Errorf("SSH 认证失败，请检查用户名和密码")
	}
	if strings.Contains(s, "connection refused") {
		return fmt.Errorf("SSH 端口拒绝连接")
	}
	if strings.Contains(s, "i/o timeout") {
		return fmt.Errorf("SSH 连接超时")
	}
	return fmt.Errorf("SSH 连接失败：%v", err)
}
func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
func methodNotAllowed(w http.ResponseWriter) { writeError(w, 405, fmt.Errorf("请求方法不支持")) }
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}
func openBrowser(url string) {
	if runtime.GOOS == "windows" {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	}
}
