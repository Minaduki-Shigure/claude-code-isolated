# Claude Code 隔离运行

Claude 容器使用 `network_mode: none`，通过 Unix socket 连接独立过滤网关。
网关检查域名、IP、HTTPS SNI 和请求路径，再经已有主机 HTTP 代理访问网络。
镜像仅由 GitHub Actions 构建；本机启动脚本只拉取、运行和清理容器。

## 配置并启动

在本目录执行：

```bash
cp .env.example .env
```

编辑 `.env` 中这些项目：

| 配置 | 含义 |
| --- | --- |
| `WORKSPACE` | 要开放给 Claude 的单个项目目录绝对路径 |
| `ANTHROPIC_BASE_URL` | 非 Anthropic 官方的兼容模型 API，必须为 HTTPS 443 |
| `ANTHROPIC_MODEL` | 服务商提供的模型 ID |
| `MODEL_API_KEY_FILE` | 仅保存一行密钥的文件，必须位于 workspace 外 |
| `MODEL_AUTH_MODE` | `bearer` 或 `api-key`，按服务商鉴权方式选择 |
| `HOST_PROXY_HOST` / `HOST_PROXY_PORT` | 默认 `host.docker.internal:6152` |
| `TZ` | 默认 `America/Los_Angeles`，按季节自动切换 PST/PDT |

开发资源也在 `.env` 中配置，修改后下次启动生效：

| 配置 | 默认值 | 含义 |
| --- | --- | --- |
| `CLAUDE_MEMORY_LIMIT` | `8g` | 容器总内存硬上限，包含进程、计费页缓存、tmpfs 和共享内存 |
| `CLAUDE_PIDS_LIMIT` | `1024` | 进程与线程的合计上限 |
| `CLAUDE_SHM_SIZE` | `1g` | `/dev/shm` 容量上限 |
| `CLAUDE_HOME_TMPFS_SIZE` | `2g` | `/home/node` 临时用户目录容量上限 |
| `CLAUDE_TMP_TMPFS_SIZE` | `2g` | `/tmp` 临时目录容量上限 |

容量只接受正整数加 `m` 或 `g`，对应 MiB/GiB，大小写均可。
每个临时文件系统上限不能超过总内存上限；PIDs 接受 1–65536。
这些上限不会预先分配内存，所有实际用量共享同一个 8 GiB 总预算，
不会因 HOME、`/tmp` 和共享内存的上限相加而额外获得内存。
容器 swap 继续禁用。HOME 用于运行配置、会话状态和开发工具的用户缓存，
不是 Mac 主目录；项目文件仍在 `/workspace`，临时目录随容器删除而清空。

Docker Desktop 虚拟机还需要给网关和系统留余量，例如为 8 GiB 容器配置
12 GiB VM 内存；启动器不会自行修改或重启 Docker Desktop。
网关仍限于 512 MiB，CPU 没有额外配额（受 Docker VM CPU 配置约束）。
`free` 显示的 VM 总量不代表容器可用预算，应以 cgroup 限额及 OOM 事件为准。
镜像内单独运行 `node` 测出的 V8 堆上限只描述 Node 进程，不是原生 Claude 的堆上限。

配置文件按字面值解析，不执行 shell 表达式，也不展开 `$VARIABLE`。
密钥不写入 `.env`、镜像或仓库；原始密钥文件建议设为 `0600`。
部署目录、配置和密钥都必须位于 workspace 外，不能把整个主目录作为 workspace。

```bash
./scripts/claude-docker.sh --preflight-only
./scripts/claude-docker.sh
```

常用模式：

```bash
./scripts/claude-docker.sh -p "解释这个项目"
./scripts/claude-docker.sh --shell
./scripts/claude-docker.sh --exec python3 --version
./scripts/claude-docker.sh --pull never
```

可选的本机文件 `config/startup.json` 保存启动偏好和明确批准的 workspace/凭据；
存在时启动器自动加载，也可用 `STARTUP_CONFIG_FILE` 指定其他路径。
未配置时采用 `config/startup.example.json`，默认关闭偏好回写，并保留正常的信任及密钥确认。

该配置只接受以下字段：

| 字段 | 含义 |
| --- | --- |
| `schemaVersion` | 固定为 `1` |
| `trustedWorkspaces` | 已信任的 workspace 规范绝对路径列表；只精确匹配当前目录 |
| `approvedCredentials` | `baseUrl`、`authMode`、`keySha256` 组成的批准记录；指纹为完整密钥去除首尾空白后的 SHA-256 |
| `permissionMode` | 可选 `default`、`auto`、`acceptEdits`、`plan`、`dontAsk`；`auto` 同时记住启动确认，不接受或保存 `bypassPermissions` |
| `model` | 可选的初始模型 ID，优先于 `.env` 中的 `ANTHROPIC_MODEL` |
| `effort` | 可选 `low`、`medium`、`high`、`xhigh`、`max` |
| `rememberModelEffort` | `true` 时在退出后保存交互会话的最后模型与 effort（含 Max），下次自动恢复 |
| `rememberPermissionMode` | `true` 时保存会话内最后选择的权限模式，下次恢复 |
| `rememberUltracode` | `true` 时保存会话内最后选择的 ultracode 开关，下次恢复 |
| `ultracode` | 可选 `true` 或 `false`，与 effort 独立 |

`auto`、Max、ultracode on 对应 `permissionMode: "auto"`、`effort: "max"`、`ultracode: true`。
模型和 effort 通过初始 CLI 参数恢复，不固定环境变量，因此仍可用 `/model`、`/effort` 修改。
这也能恢复 `Max`；Claude 的普通 `effortLevel` 设置不接受 Max。
自动模式仍需要服务商支持权限分类请求；模型也必须支持对应 effort 与 workflows。

该文件应为 `0600` 并放在 workspace 外；已排除在 Git 和镜像构建上下文之外。
启动器只把匹配当前 workspace、API 地址、鉴权模式及完整密钥指纹的批准转换成临时状态。
更换 workspace 或凭据后，相应确认会重新出现；不会因密钥后缀相同而继承批准。

容器内的全局状态文件仍位于 tmpfs，只在每次启动时填入有限的确认字段和偏好。
三个 `remember*` 开关彼此独立，只回写各自对应的白名单字段。`model` 和 `effort` 来自
CLI 原生结构化 statusLine 数据；权限模式和 ultracode 则通过内存中的终端解析器读取
原生终端当前界面，不保存终端输出流。本次专用临时卷最多包含这四项已识别、通过校验的偏好字段。
退出时，主机启动器只将已启用记忆的类别合并到本机配置，再删除临时卷；
下次自动恢复，并发会话按退出保存顺序更新。恢复已选模式时不会再次要求把 auto 设为默认；
对应的少量确认标记只在临时 HOME 中重建。

完整 statusLine 输入、会话 ID、聊天、历史、缓存、memory 笔记和调试日志均不回写。
用户、项目与插件 hooks，以及自定义 statusLine 命令仍不执行，只有固定的 managed 导出命令可运行。
其他界面设置变更仍是临时的。需要调整固定启动偏好，请编辑本机 `config/startup.json`；
把某个 `remember*` 开关改为 `false` 只关闭该类偏好的自动回写，不影响另外两类。
若终端界面无法可靠识别，会保留原已保存值；每日自动更新的镜像必须通过原生交互回归后才发布。

每次启动默认拉取经过 CI 验证的 `latest`，检查 Claude 与网关镜像属于同一次发布，
并固定本次运行使用的镜像内容。需要固定版本时，将两个镜像配置为相同的
`VERSION-build-RUN-ATTEMPT` 标签或对应摘要。

## 持久化与边界

- `/workspace` 是唯一可写的主机业务目录。
- 在主机编辑 `config/settings.json` 保存普通偏好；`config/startup.json` 保存上述启动偏好和批准。
  启动偏好覆盖对应的普通设置；三个独立 `remember*` 开关只回写各自启用的白名单偏好字段。
- HOME、会话、历史、缓存、临时文件均位于 tmpfs；Docker 容器日志关闭。
- 自动 memory 由 managed `autoMemoryEnabled: false` 与 `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`
  强制禁用；目录固定为 HOME tmpfs 内的 `/home/node/.claude/memory`，普通设置和 `--settings`
  不能将其重定向到 workspace。子 agent memory 也禁用；其位于 HOME 和 `/workspace/.claude`
  下的默认存储位置由 tmpfs 覆盖。
- `/workspace/.claude` 被 tmpfs 遮盖，现有项目 Claude 配置与状态不会加载或修改。
  项目根目录等 `.claude/` 外已有的 `CLAUDE.md` 仍可读取，不会删除；普通业务文件也保留。
- 密钥以只读文件挂载；启动脚本创建的暂存副本在退出时删除。
- 不挂载主机 HOME、Docker socket 或 SSH agent，不修改主机代理和其他容器。
- 普通 HTTP 80、HTTPS 443 和 HTTPS Git 可用；SSH、WebSocket、HTTP/3、
  任意 TCP 端口和拒绝临时 CA 的证书固定客户端不受支持。
- 内置强制阻断官方域名和已公布的官方 IP 段，`gateway/policy.json` 补充遥测域名、
  共享平台上的官方路径。DNS 的 A、AAAA、CNAME 与实际连接目标都要通过检查。
- 通用联网无法穷尽未来新增别名或第三方服务的转发行为；本方案不把已知端点黑名单
  宣称为“所有未来官方端点均已知”。Claude 也可以把用户要求保存的内容写入 workspace。

正常退出与 INT/TERM/HUP 会清理本次专属容器、网络、IPC 卷和密钥暂存目录。
SIGKILL、Docker 故障或主机崩溃可能留下资源；按启动输出中的唯一项目名检查，
不要使用全局 prune。tmpfs 也不等于对主机交换文件、快照或崩溃转储的取证级擦除。

## 更新与验收

GitHub Actions 每日北京时间 **11:37**、推送 main 或手动触发时：
校验官方发布签名与二进制摘要，构建原生 amd64/arm64 镜像，执行真实 CLI 集成测试，
扫描漏洞，通过后才更新两个 `latest`。运行中的 Claude 不自行更新。

验收脚本只接受已发布镜像摘要，不构建本地镜像：

```bash
python3 tests/integration.py \
  --runtime-image ghcr.io/minaduki-shigure/claude-code-isolated@sha256:实际摘要 \
  --gateway-image ghcr.io/minaduki-shigure/claude-code-isolated-gateway@sha256:实际摘要 \
  --output audit-local/integration.json

python3 tests/host_proxy_smoke.py \
  --runtime-image ghcr.io/minaduki-shigure/claude-code-isolated@sha256:实际摘要 \
  --gateway-image ghcr.io/minaduki-shigure/claude-code-isolated-gateway@sha256:实际摘要 \
  --output audit-local/host-proxy.json
```

第一项使用受控模型接口验证真实 Claude CLI 的流式响应、工具调用、网络隔离和状态清理。
第二项经真实主机代理访问 example.com，验证公网链路、端点阻断及正常/TERM 退出清理。
它们不使用真实模型账号，不证明尚未配置的服务商 API 可用。

详细机制、限制及官方参考资料见 [英文说明](README.md)；
测试范围见 [测试说明](tests/README.md)。
