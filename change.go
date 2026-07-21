package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var ansiEscapeRE = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))`)

var forbiddenChangePrefixes = []string{
	"reboot", "reset", "format", "delete", "move", "copy", "rename", "mkdir", "rmdir",
	"startup", "boot-loader", "install", "upgrade", "patch", "rollback", "restore", "erase",
	"factory", "save", "quit", "return", "ftp", "tftp", "sftp", "scp",
}

var protectedAccessFragments = []string{
	"password", "local-user", "ssh user", "stelnet", "user-interface", "aaa", "radius-server",
	"hwtacacs-server", "snmp-agent community", "ip address", "management-port",
}

func validateChangeScript(script string) error {
	if len(script) == 0 || len(script) > 5000 {
		return fmt.Errorf("变更脚本为空或超过 5000 字符")
	}
	if strings.ContainsRune(script, '\x00') || strings.Contains(script, ";") || strings.Contains(script, "&&") {
		return fmt.Errorf("变更脚本不能包含命令连接符")
	}
	lines := strings.Split(strings.ReplaceAll(script, "\r", ""), "\n")
	if len(lines) > 50 {
		return fmt.Errorf("一次最多执行 50 行变更命令")
	}
	count := 0
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		count++
		lower := strings.ToLower(line)
		for _, prefix := range forbiddenChangePrefixes {
			if lower == prefix || strings.HasPrefix(lower, prefix+" ") {
				return fmt.Errorf("第 %d 行包含永久禁止的高危命令：%s", i+1, prefix)
			}
		}
		for _, fragment := range protectedAccessFragments {
			if strings.Contains(lower, fragment) {
				return fmt.Errorf("第 %d 行可能修改管理地址或认证信息，系统禁止通过网页执行", i+1)
			}
		}
	}
	if count == 0 {
		return fmt.Errorf("变更脚本不能为空")
	}
	return nil
}

func (a *App) changeDevice(w http.ResponseWriter, r *http.Request, d Device) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !a.requireAdmin(w, r) {
		return
	}
	var body struct {
		Script        string `json:"script"`
		ConfirmDevice string `json:"confirmDevice"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	body.Script = strings.TrimSpace(body.Script)
	if body.ConfirmDevice != d.Name {
		a.logAction("拦截配置变更", d, false, "设备名称确认不匹配")
		writeError(w, 400, fmt.Errorf("请输入完整设备名称 %s 进行确认", d.Name))
		return
	}
	if err := validateChangeScript(body.Script); err != nil {
		a.logAction("拦截配置变更", d, false, err.Error())
		writeError(w, 400, err)
		return
	}
	backup, err := a.createBackup(d)
	if err != nil {
		a.logAction("配置变更", d, false, "变更前备份失败，已中止："+err.Error())
		writeError(w, 502, fmt.Errorf("变更前配置备份失败，已中止操作：%v", err))
		return
	}
	out, err := a.runSSHShell(d, body.Script)
	digest := fmt.Sprintf("脚本 SHA256: %x；变更前备份: %s", sha256.Sum256([]byte(body.Script)), backup)
	if err != nil {
		a.logAction("配置变更", d, false, digest+"；"+err.Error())
		writeError(w, 502, fmt.Errorf("变更会话异常；部分命令可能已经生效，请立即核查设备。变更前备份：%s。详情：%v", backup, err))
		return
	}
	a.logAction("配置变更", d, true, digest)
	writeJSON(w, 200, map[string]string{"output": out, "backup": backup, "warning": "运行配置可能已改变，但系统没有执行 save。请核查后再决定是否通过设备控制台保存。"})
}

func (a *App) dialSSHClient(d Device) (*ssh.Client, error) {
	password, err := unprotectString(d.PasswordCipher)
	if err != nil {
		return nil, fmt.Errorf("无法解密 SSH 密码：%v", err)
	}
	config := a.sshClientConfig(d, password, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct {
		client *ssh.Client
		err    error
	}, 1)
	go func() {
		client, e := ssh.Dial("tcp", net.JoinHostPort(d.Host, strconv.Itoa(d.SSHPort)), config)
		done <- struct {
			client *ssh.Client
			err    error
		}{client, e}
	}()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("SSH 连接超时")
	case result := <-done:
		if result.err != nil {
			return a.dialLegacySSH(d, password, result.err)
		}
		return result.client, nil
	}
}

func (a *App) sshClientConfig(d Device, password string, legacy bool) *ssh.ClientConfig {
	config := &ssh.ClientConfig{User: d.Username, Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: a.hostKeyCallback(), Timeout: 7 * time.Second}
	if legacy {
		config.Config.SetDefaults()
		config.KeyExchanges = append(config.KeyExchanges, "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1")
		config.Ciphers = append(config.Ciphers, "aes128-cbc", "3des-cbc")
	}
	return config
}

func (a *App) dialLegacySSH(d Device, password string, modernErr error) (*ssh.Client, error) {
	if !isSSHAlgorithmError(modernErr) {
		return nil, friendlySSHError(modernErr)
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(d.Host, strconv.Itoa(d.SSHPort)), a.sshClientConfig(d, password, true))
	if err != nil {
		return nil, friendlySSHError(err)
	}
	a.logAction("SSH 兼容模式", d, true, "设备仅支持旧版 SHA-1/CBC 算法，已自动降级连接")
	return client, nil
}

func isSSHAlgorithmError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no common algorithm") || strings.Contains(s, "no common cipher")
}

func (a *App) runSSHQueryShell(client *ssh.Client, d Device, command string) (string, error) {
	if err := validateReadOnlyCommand(command); err != nil {
		return "", err
	}
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	if err = session.RequestPty("vt100", 120, 40, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return "", fmt.Errorf("设备不支持交互式 SSH 查询：%v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return "", err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", err
	}
	var output terminalCapture
	session.Stderr = &output
	if err = session.Shell(); err != nil {
		return "", fmt.Errorf("无法启动设备命令行：%v", err)
	}
	go func() { _, _ = io.Copy(&output, stdout) }()
	if err := waitForTerminalPrompt(&output, 0, 8*time.Second); err != nil {
		_, _ = fmt.Fprintln(stdin)
		if err = waitForTerminalPrompt(&output, 0, 5*time.Second); err != nil {
			return cleanTerminalOutput(output.String()), fmt.Errorf("登录后未检测到设备提示符：%v", err)
		}
	}
	paging := "screen-length 0 temporary"
	if d.Vendor == "H3C" {
		paging = "screen-length disable"
	}
	pagingStart := output.Len()
	_, _ = fmt.Fprintln(stdin, paging)
	if err = waitForTerminalPrompt(&output, pagingStart, 10*time.Second); err != nil {
		return cleanTerminalOutput(output.String()), fmt.Errorf("关闭分页时未返回提示符：%v", err)
	}
	queryStart := output.Len()
	for _, line := range strings.Split(strings.ReplaceAll(command, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		start := output.Len()
		_, _ = fmt.Fprintln(stdin, line)
		if err = waitForTerminalPrompt(&output, start, 90*time.Second); err != nil {
			return cleanTerminalOutput(output.Since(queryStart)), fmt.Errorf("查询 %q 未完成：%v", line, err)
		}
	}
	result := cleanTerminalOutput(output.Since(queryStart))
	_, _ = fmt.Fprintln(stdin, "quit")
	_ = stdin.Close()
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = session.Close()
	}
	if result == "" {
		return "", fmt.Errorf("设备没有返回查询内容")
	}
	return result, nil
}

type terminalCapture struct {
	mu sync.Mutex
	b  strings.Builder
}

func (c *terminalCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.Write(p)
}
func (c *terminalCapture) String() string { c.mu.Lock(); defer c.mu.Unlock(); return c.b.String() }
func (c *terminalCapture) Len() int       { c.mu.Lock(); defer c.mu.Unlock(); return c.b.Len() }
func (c *terminalCapture) Since(start int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.b.String()
	if start < 0 || start > len(s) {
		start = 0
	}
	return s[start:]
}

func waitForTerminalPrompt(c *terminalCapture, start int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	lastLen := -1
	stableSince := time.Time{}
	for time.Now().Before(deadline) {
		text := c.Since(start)
		length := c.Len()
		if hasTrailingTerminalPrompt(text) {
			if length != lastLen {
				lastLen = length
				stableSince = time.Now()
			} else if !stableSince.IsZero() && time.Since(stableSince) >= 180*time.Millisecond {
				return nil
			}
		} else {
			lastLen = length
			stableSince = time.Time{}
		}
		time.Sleep(40 * time.Millisecond)
	}
	return fmt.Errorf("等待设备提示符超时")
}

func hasTrailingTerminalPrompt(text string) bool {
	clean := cleanTerminalOutput(text)
	if clean == "" {
		return false
	}
	lines := strings.Split(clean, "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if len(last) < 3 || len(last) > 200 {
		return false
	}
	return (strings.HasPrefix(last, "<") && strings.HasSuffix(last, ">")) || (strings.HasPrefix(last, "[") && strings.HasSuffix(last, "]"))
}

func (a *App) runSSHShell(d Device, script string) (string, error) {
	client, err := a.dialSSHClient(d)
	if err != nil {
		return "", err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	if err = session.RequestPty("vt100", 120, 40, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return "", fmt.Errorf("设备不支持交互式 SSH 会话：%v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return "", err
	}
	var output strings.Builder
	session.Stdout = &output
	session.Stderr = &output
	if err = session.Shell(); err != nil {
		return "", fmt.Errorf("无法启动设备命令行：%v", err)
	}
	lines := strings.Split(strings.ReplaceAll(script, "\r", ""), "\n")
	go func() {
		paging := "screen-length 0 temporary"
		if d.Vendor == "H3C" {
			paging = "screen-length disable"
		}
		_, _ = fmt.Fprintln(stdin, paging)
		time.Sleep(150 * time.Millisecond)
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			_, _ = fmt.Fprintln(stdin, line)
			time.Sleep(180 * time.Millisecond)
		}
		_, _ = fmt.Fprintln(stdin, "return")
		time.Sleep(180 * time.Millisecond)
		_, _ = fmt.Fprintln(stdin, "quit")
		_ = stdin.Close()
	}()
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
		return cleanTerminalOutput(output.String()), fmt.Errorf("交互式变更超时")
	case err := <-done:
		clean := cleanTerminalOutput(output.String())
		if err != nil && clean == "" {
			return "", err
		}
		return clean, nil
	}
}

func cleanTerminalOutput(s string) string {
	s = ansiEscapeRE.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.TrimSpace(s)
}
