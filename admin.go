package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const adminCookie = "switch_admin"

type Settings struct {
	AdminPasswordHash string `json:"adminPasswordHash,omitempty"`
	SessionMinutes    int    `json:"sessionMinutes"`
}

type SettingsStore struct {
	mu   sync.RWMutex
	path string
	data Settings
}

type loginFailure struct {
	Count        int
	BlockedUntil time.Time
}

func loadSettings(path string) (*SettingsStore, error) {
	s := &SettingsStore{path: path, data: Settings{SessionMinutes: 15}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("设置文件损坏：%v", err)
	}
	if s.data.SessionMinutes < 5 || s.data.SessionMinutes > 120 {
		s.data.SessionMinutes = 15
	}
	return s, nil
}

func (s *SettingsStore) configured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.AdminPasswordHash != ""
}
func (s *SettingsStore) sessionDuration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Duration(s.data.SessionMinutes) * time.Minute
}
func (s *SettingsStore) setPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.AdminPasswordHash = string(hash)
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
func (s *SettingsStore) checkPassword(password string) bool {
	s.mu.RLock()
	hash := s.data.AdminPasswordHash
	s.mu.RUnlock()
	return hash != "" && bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func validateAdminPassword(password string) error {
	if len([]rune(password)) < 10 {
		return fmt.Errorf("管理员密码至少需要 10 个字符")
	}
	if len(password) > 128 {
		return fmt.Errorf("管理员密码过长")
	}
	if strings.TrimSpace(password) != password {
		return fmt.Errorf("管理员密码首尾不能包含空格")
	}
	return nil
}

func (a *App) adminStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	admin, expires := a.adminSession(r)
	writeJSON(w, 200, map[string]interface{}{"configured": a.settings.configured(), "admin": admin, "expiresAt": expires})
}

func (a *App) adminSetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.settings.configured() {
		writeError(w, 409, fmt.Errorf("管理员密码已设置"))
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	if err := validateAdminPassword(body.Password); err != nil {
		writeError(w, 400, err)
		return
	}
	if err := a.settings.setPassword(body.Password); err != nil {
		writeError(w, 500, err)
		return
	}
	a.startAdminSession(w)
	a.logAction("设置管理员密码", Device{}, true, "管理员功能已启用")
	writeJSON(w, 201, map[string]bool{"admin": true})
}

func (a *App) adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !a.settings.configured() {
		writeError(w, 409, fmt.Errorf("请先设置管理员密码"))
		return
	}
	key := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		key = host
	}
	a.loginMu.Lock()
	f := a.loginFails[key]
	if f != nil && time.Now().Before(f.BlockedUntil) {
		wait := time.Until(f.BlockedUntil).Round(time.Second)
		a.loginMu.Unlock()
		writeError(w, 429, fmt.Errorf("登录失败次数过多，请在 %s 后重试", wait))
		return
	}
	a.loginMu.Unlock()
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	if !a.settings.checkPassword(body.Password) {
		a.recordLoginFailure(key)
		a.logAction("管理员登录", Device{}, false, "密码错误")
		writeError(w, 401, fmt.Errorf("管理员密码错误"))
		return
	}
	a.loginMu.Lock()
	delete(a.loginFails, key)
	a.loginMu.Unlock()
	a.startAdminSession(w)
	a.logAction("管理员登录", Device{}, true, "会话已解锁")
	writeJSON(w, 200, map[string]bool{"admin": true})
}

func (a *App) recordLoginFailure(key string) {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	f := a.loginFails[key]
	if f == nil {
		f = &loginFailure{}
		a.loginFails[key] = f
	}
	f.Count++
	if f.Count >= 5 {
		f.BlockedUntil = time.Now().Add(30 * time.Second)
		f.Count = 0
	}
}

func (a *App) adminLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if c, err := r.Cookie(adminCookie); err == nil {
		a.sessionMu.Lock()
		delete(a.sessions, c.Value)
		a.sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: "", Path: "/api", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	a.logAction("管理员退出", Device{}, true, "会话已锁定")
	w.WriteHeader(204)
}

func (a *App) startAdminSession(w http.ResponseWriter) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	expiry := time.Now().Add(a.settings.sessionDuration())
	a.sessionMu.Lock()
	a.sessions[token] = expiry
	for k, v := range a.sessions {
		if time.Now().After(v) {
			delete(a.sessions, k)
		}
	}
	a.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: token, Path: "/api", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(a.settings.sessionDuration().Seconds())})
}

func (a *App) adminSession(r *http.Request) (bool, time.Time) {
	c, err := r.Cookie(adminCookie)
	if err != nil {
		return false, time.Time{}
	}
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	expiry, ok := a.sessions[c.Value]
	if !ok || time.Now().After(expiry) {
		delete(a.sessions, c.Value)
		return false, time.Time{}
	}
	return true, expiry
}

func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	ok, _ := a.adminSession(r)
	if !ok {
		writeError(w, 401, fmt.Errorf("需要管理员权限，请先解锁"))
		return false
	}
	return true
}
