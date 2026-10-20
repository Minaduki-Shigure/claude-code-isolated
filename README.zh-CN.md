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

每次启动默认拉取经过 CI 验证的 `latest`，检查 Claude 与网关镜像属于同一次发布，
并固定本次运行使用的镜像内容。需要固定版本时，将两个镜像配置为相同的
`VERSION-build-RUN-ATTEMPT` 标签或对应摘要。

## 持久化与边界

- `/workspace` 是唯一可写的主机业务目录。
- 在主机编辑 `config/settings.json` 可持久保存偏好；容器内设置修改会丢弃。
- HOME、会话、历史、缓存、临时文件均位于 tmpfs；Docker 容器日志关闭。
- `/workspace/.claude` 被 tmpfs 遮盖，现有项目 Claude 配置与状态不会加载或修改。
  项目根目录的 `CLAUDE.md` 仍可读取。
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
