# Switch Manager for Windows 7

一款面向华为 VRP、华三 Comware 交换机的单机运维管理工具。后端使用 Go，前端为内嵌 Web UI，可编译成单个 Windows 可执行文件，在 Windows 7 SP1 上运行。

> 项目默认工作在只读安全模式。管理员变更能力采用独立会话、强制备份、设备名确认和高危命令拦截，不能替代正式的变更评审与现场回退方案。

## 功能

- 华为、华三设备资产管理
- CSV 模板下载、预览和最多 1000 台设备的原子批量导入
- Windows DPAPI 加密保存 SSH 密码和 SNMP 团体字
- Ping、SSH 端口、SNMP v2c 状态巡检
- 严格只读 SSH 查询，仅允许 `display ...`
- 常用版本、接口、VLAN、MAC、ARP、路由、LLDP、CPU、内存、光模块和日志查询
- 单台及限流批量只读查询
- 单台及限流全量配置备份
- 配置在线查看与两版本并排对比
- 管理员密码、15 分钟短时会话和登录失败限流
- 受控单设备配置变更
- 操作审计日志
- 仅监听 `127.0.0.1`
- 老旧设备 SSH SHA-1/CBC 算法按需兼容回退
- 不支持 SSH `exec` 通道的设备自动切换交互式只读查询

## 安全模型

### 默认只读

- 查询接口的每一行都必须以 `display` 开头。
- SNMP 只调用 GET，从不调用 SET。
- 配置备份只执行 `display current-configuration`，不会执行 `save`。
- 状态巡检只执行本机 Ping、TCP 连接探测和 SNMP GET。

### 老旧 SSH 兼容

客户端始终先使用现代 SSH 算法。只有设备明确返回“无共同算法”时，才会重试老旧设备常见的 `diffie-hellman-group1-sha1`、`group-exchange-sha1`、AES-CBC 和 3DES-CBC，并在审计日志中记录安全降级。建议优先升级交换机 SSH 算法配置。

部分旧版 VRP/Comware 不支持 SSH `exec` 通道，或关闭命令时不返回标准退出状态。此时程序会自动改用带 PTY 的交互式会话执行相同的只读 `display` 查询；该回退不会绕过只读校验。

### 管理员变更

管理员功能默认未设置。首次设置至少 10 个字符的密码后，可以解锁 15 分钟的内存会话。每次配置变更必须：

1. 验证管理员会话；
2. 输入完整设备名称确认目标；
3. 通过脚本安全校验；
4. 成功备份当前配置；
5. 执行单设备交互式 SSH 变更；
6. 写入不包含脚本正文的审计记录。

系统永久拒绝以下操作：

- 重启、清空、格式化、恢复出厂；
- 文件删除、复制、移动及启动文件修改；
- `save`，避免未经核查的运行配置直接固化；
- 修改管理 IP、SSH、AAA、用户密码和 SNMP 团体字；
- 批量配置变更。

任何配置命令仍可能导致端口或业务中断。建议使用独立低权限账号，先在非核心设备验证，并准备带外管理和人工回退方案。

## 构建

Windows 7 支持需要使用 Go 1.20.x；Go 1.21 起不再支持 Windows 7。

```powershell
go test ./...
go build -trimpath -ldflags "-s -w" -o switch-manager.exe .

$env:GOARCH="386"
go build -trimpath -ldflags "-s -w" -o switch-manager-32bit.exe .
```

## 运行

```powershell
.\switch-manager.exe
```

浏览器将打开 `http://127.0.0.1:8787`。数据默认保存在可执行文件旁的 `data` 目录，也可以指定其他目录：

```powershell
.\switch-manager.exe -data D:\switch-manager-data -port 8788
```

## 数据说明

- `data/devices.json`：设备信息，凭据字段由当前 Windows 用户的 DPAPI 加密；
- `data/settings.json`：管理员 bcrypt 密码哈希；
- `data/known_hosts`：SSH 主机指纹；
- `data/backups/`：配置备份，当前为本地明文文件；
- `data/audit.jsonl`：操作审计。

请勿将 `data` 目录、真实配置备份或设备日志提交到 GitHub。

批量导入 CSV 包含明文 SSH 密码和 SNMP 团体字。导入成功后请安全删除 CSV，不要上传到 GitHub、网盘或聊天工具。

## 兼容性

- Windows 7 SP1 32/64 位
- Windows 10 / Windows 11
- Chrome 109、Edge 109、Firefox 115 ESR 或更新浏览器
- 华为 VRP、华三 Comware 的命令可能因版本和 AAA 权限不同而变化

## 许可证

[MIT](LICENSE)
