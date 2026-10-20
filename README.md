# Isolated Claude Code

[中文使用说明](README.zh-CN.md)

Disposable Claude Code with general HTTP/HTTPS access through a filtering
gateway and an existing host HTTP proxy. Only the selected workspace and
explicit configuration survive a session. Images are built in GitHub Actions;
the local launcher only pulls and runs them.

```text
Claude + shell tools (network=none)
  -> 127.0.0.1:18080 -> read-only mounted Unix socket
  -> independent HTTPS-inspecting gateway
  -> existing host HTTP proxy (one IPv4 address and port)
  -> checked, pinned destination IP + verified original TLS hostname
```

## Start

Requires Docker Engine/Desktop, Docker Compose v2+, and host Python 3.9+.
On macOS the HTTP listener of Surge commonly uses port 6152. The proxy must be
reachable from Docker at `host.docker.internal` and support CONNECT to numeric
IPv4/IPv6 targets on ports 80 and 443. Nothing here changes the host proxy.

1. Copy `.env.example` to `.env`.
2. Set `WORKSPACE` to one existing project directory.
3. Set `ANTHROPIC_BASE_URL` to your compatible **HTTPS** model gateway and
   `ANTHROPIC_MODEL` to its model identifier. Official Anthropic endpoints are
   blocked. The provider's subsequent forwarding/data handling is outside this
   container's control.
4. Store the API credential in a private file **outside the workspace** and set
   `MODEL_API_KEY_FILE` to its absolute path. Use `MODEL_AUTH_MODE=bearer` for
   `Authorization: Bearer` or `api-key` for `X-Api-Key`.
5. Run:

```bash
./scripts/claude-docker.sh
```

Optional host-only `config/startup.json` stores explicit startup preferences and
scoped confirmations. The launcher uses it automatically when present; override
its path with `STARTUP_CONFIG_FILE`. Without it,
`config/startup.example.json` leaves preference writeback off and preserves normal
trust/key prompts.

The strict schema accepts `schemaVersion: 1`, `trustedWorkspaces` (canonical
absolute paths), `approvedCredentials` (objects containing `baseUrl`, `authMode`,
and a full-key `keySha256`), plus optional `permissionMode` (`default`, `auto`,
`acceptEdits`, `plan`, or `dontAsk`), `model`, `effort` (`low`, `medium`, `high`,
`xhigh`, or `max`), `ultracode` (boolean), and the three boolean writeback switches
below. `bypassPermissions` is not an accepted startup or saved preference.
Only an exact workspace match skips workspace trust. API-key approval requires
the same endpoint, auth mode and full key fingerprint; a different path, endpoint
or key restores its corresponding prompt. Keep this file outside WORKSPACE and
chmod it to 0600. It is ignored by Git and excluded from image build contexts.

The host launcher stages only matching boolean approvals and preferences as a
read-only file. The runtime seeds a small allowlist of app-state fields at
`$CLAUDE_CONFIG_DIR/.claude.json` inside tmpfs, then applies the requested user
settings. `auto` also records its startup opt-in in temporary settings;
the initial model and effort use CLI arguments, so interactive changes remain
possible. This also restores `max`, which normal `effortLevel` settings do not
accept. `ultracode: true` is independent of effort. This does not enable
`bypassPermissions`. Auto mode still depends on the provider's classifier
support, and effort/workflows depend on the selected model. The CLI's live
settings and permission mode are tested, not merely the generated JSON.

Three independent, opt-in switches remember the last interactive selections:

| Switch | Saved fields |
| --- | --- |
| `rememberModelEffort` | `model` and `effort`, including `/effort max` |
| `rememberPermissionMode` | `permissionMode`, including mode changes during the session |
| `rememberUltracode` | `ultracode`, including the on/off selection in `/effort` |

Model and effort come from the CLI's structured live status-line data. Permission
mode and ultracode come from the native terminal's current rendered interface,
parsed only in memory. The terminal stream and complete status-line payload are
not saved. Only the four recognized, validated preference fields enter the disposable
preference volume. On exit, the host launcher merges the fields enabled by these
switches into the host startup file with a private atomic write; concurrent sessions
save in exit order, and the next session restores them. An explicit saved mode
also suppresses the repeated offer to replace it with auto; only the corresponding
onboarding markers are reconstructed in temporary HOME. Setting one switch to
`false` stops writeback for that category without changing the others.

No transcript, session ID, history, debug log, cache, memory notes, or complete
app-state file is copied back. The temporary volume is removed with that launch's
containers. User/plugin hooks and user status-line commands remain disabled;
only the fixed managed exporter is permitted. Other interactive settings remain
temporary. Editing the host startup file changes future defaults. If the native
interface cannot be identified reliably, the previous saved value is preserved.
Daily image updates must pass the native interactive regression before release.

The runtime defaults to `TZ=America/Los_Angeles`, using PST in winter and PDT in
summer. Set an IANA zone with `TZ` in `.env` to override it.

The `.env` parser accepts literal `KEY=VALUE`, optionally quoted. It does not
evaluate shell expressions, expand `$VARIABLE`, or allow multiline values.
Configuration, credentials and this deployment directory must remain outside
the mounted workspace. Do not use your entire home directory as the workspace.

Other modes:

```bash
./scripts/claude-docker.sh --preflight-only
./scripts/claude-docker.sh -p "Explain this project"
./scripts/claude-docker.sh --shell
./scripts/claude-docker.sh --exec python3 --version
./scripts/claude-docker.sh --pull never --shell
./scripts/claude-docker.sh --env-file /absolute/path/other.env
```

The launcher pulls both `latest` images by default and checks that their
version, source revision and build timestamp match. It freezes their content
IDs for the session. A partially promoted pair fails closed; retry the pull or
pin both images to the same immutable `VERSION-build-RUN-ATTEMPT` release tag.
`--pull never` uses an already cached matching pair.

Do not run `docker compose up` as the interactive launcher. The wrapper creates
a unique project, starts its gateway, runs one CLI, and removes only that
project's containers, network and IPC volume. Normal exit and INT/TERM/HUP
trigger cleanup. SIGKILL, daemon failure and host crashes cannot execute cleanup.
After such an event, inspect the exact project named by the launch output;
do not globally prune Docker resources.

## Development resource limits

Set these literal values in `.env`; changes apply to the next launch:

| Setting | Default | Limit |
| --- | --- | --- |
| `CLAUDE_MEMORY_LIMIT` | `8g` | Total cgroup memory, including processes, charged page cache, tmpfs and shared memory |
| `CLAUDE_PIDS_LIMIT` | `1024` | Processes and threads combined |
| `CLAUDE_SHM_SIZE` | `1g` | `/dev/shm` capacity |
| `CLAUDE_HOME_TMPFS_SIZE` | `2g` | Ephemeral `/home/node` capacity |
| `CLAUDE_TMP_TMPFS_SIZE` | `2g` | Ephemeral `/tmp` capacity |

Sizes accept positive whole numbers followed by `m` or `g` (MiB/GiB),
case-insensitively. Each filesystem cap must fit within the memory limit;
PIDs must be an integer from 1 to 65536. These caps do not reserve memory:
all actual usage shares the single 8 GiB memory budget. The filesystem caps
are not added to that budget. `memswap_limit` always equals the RAM limit,
so container swap remains disabled.

HOME holds runtime settings, session state and development tools' user caches;
it is not the Mac user's home. Workspace files remain persistent, while HOME
and temporary storage are discarded with the container.

Leave room for the gateway and the OS in Docker Desktop's VM, for example a
12 GiB VM for an 8 GiB CLI container. The launcher never changes or restarts
Docker Desktop. The gateway stays capped at 512 MiB. No extra CPU quota is
applied; Docker VM CPU settings still apply. `free` may report VM-wide memory,
so use the cgroup limit and OOM counters when diagnosing the container.
The V8 heap limit reported by a separate `node` command describes Node,
not the official native Claude executable.

## Files and persistence

| Path | Treatment |
| --- | --- |
| `/workspace` | Only writable host business directory |
| `/workspace/.claude` | tmpfs masks existing project Claude state/config |
| `/config/settings.json` | Read-only persistent input copied into temporary HOME |
| `/config/startup.json` | Read-only, derived approvals and startup preferences; no host paths or key hashes |
| `/var/lib/claude-preferences` | Per-launch temporary volume containing only validated model/effort/permission mode/ultracode preferences |
| `/etc/claude-code/managed-settings.json` | Read-only policy, generated with fixed model endpoint |
| `/etc/claude-code/managed-mcp.json` | Empty managed MCP inventory; MCP disabled |
| `/run/secrets/model_api_key` | Read-only credential; not in image or Docker environment |
| `/home/node`, `/tmp`, `/run` | tmpfs, discarded with the container |
| `/run/claude-ipc` | Socket, readiness marker and public ephemeral CA only |

Edit `config/settings.json` on the host for ordinary preferences and
`config/startup.json` for the startup policy above. Each `remember*` switch saves
only its listed preference fields; other in-session settings changes are
discarded. Do not sync `.claude` or `.claude.json` back to the host. Existing
project `CLAUDE.md` files outside `.claude/` remain readable and are not deleted.
Project `.claude/` content is masked, and the CLI loads only user settings. Move
required preferences into the explicit settings input.
Docker may create an empty `.claude` mountpoint in a workspace that lacks one.

The staged credential is inside a mode-0700 session directory with a readable
file mode so non-root Linux containers can read macOS bind mounts. The launcher
removes the staging directory on exit; the original credential file persists.
Protect and back up the original credential as configuration. A forced crash
may leave the private staging directory under `.run/`.

Automatic memory is forcibly disabled with managed `autoMemoryEnabled: false`
and `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`. Its directory is pinned to
`/home/node/.claude/memory` on HOME tmpfs; user settings and `--settings` cannot
redirect it into the workspace. Subagent memory is also disabled; its default
locations under HOME and `/workspace/.claude` are covered by tmpfs. These controls
do not delete ordinary workspace files such as existing `CLAUDE.md` instructions.

Prompt history, transcripts, file checkpoints and caches are disabled or confined
to tmpfs. Docker's logging driver is `none`, and the gateway does not retain traffic bodies,
credentials or URL logs. Terminal scrollback is controlled by your terminal.
Docker tmpfs can use swap; `memswap_limit=mem_limit` disables the container's
Linux swap allowance, but this is not a forensic guarantee against VM/host
swap, crash dumps or snapshots.

An agent with permission to write project files can deliberately save any text
there. The guarantee concerns Claude's normal storage, not the semantic
contents of arbitrary files it creates in the authorized workspace.

## Enforced network boundary

- The CLI has only loopback networking. Unsetting proxy variables does not
  restore a network route. No Docker socket, SSH agent, host networking, host
  PID namespace or device is mounted.
- The gateway does not mount the workspace. Its init installs IPv4/IPv6 OUTPUT
  rules in **its own network namespace** allowing only its selected host proxy.
  It then changes to uid 1000, drops all capabilities and sets no-new-privileges.
- Destination DNS is queried using TLS-verified DoH through the host proxy.
  The bootstrap IP is fixed in the read-only policy. Both A and AAAA answers,
  and CNAME names, are checked before any origin connection.
- The gateway sends `CONNECT <checked-numeric-IP>:<port>` to the host proxy;
  the origin hostname is retained for TLS verification. It does not ask the
  host proxy to resolve that hostname again.
- CONNECT authority, TLS SNI and HTTPS request authority must agree. Requests
  are parsed and serialized afresh; connection-specific headers are removed.
  The Go HTTP parser canonicalizes an outer absolute HTTP URL's Host to that
  URL's authority, so a conflicting raw Host header cannot redirect it.
- Official domains and documented IP ranges are always denied. The JSON
  policy adds telemetry domains and known official paths on shared platforms.
  Mixed DNS answers containing private or forbidden IPs fail closed.
- Direct IP destinations, private/reserved networks, cloud metadata, DNS/UDP,
  arbitrary TCP, nested CONNECT and protocol upgrades are denied.
- General HTTP on port 80 and HTTPS on port 443 work; Git must use HTTPS.
  SSH, WebSockets, HTTP/3, certificate-pinned clients and arbitrary ports are
  intentionally unsupported. HTTPS uses inspected HTTP/1.1, including SSE.
- Upstream server certificates are validated. There is no insecure TLS option,
  transparent tunnel fallback, direct-network fallback or host trust-store change.
  The CA private key exists only in the gateway's memory and is regenerated for
  each new gateway. Only its public certificate is shared with the CLI.

`gateway/policy.json` is editable by the host operator. The built-in baseline
cannot be relaxed to permit official domains, official documented IP ranges,
or private/reserved destinations. The baseline is a known-endpoint denylist,
not proof that every future vendor alias is known. Arbitrary third-party
HTTPS services can also forward opaque data elsewhere; general internet
access cannot prove the eventual downstream recipient.
Shared CDN IPs may serve multiple organizations, so IP blocks may also deny
unrelated websites. Keep the policy reviewed when updating the CLI.

## Application policy

The managed policy disables known telemetry/error reporting/feedback,
OpenTelemetry exporters, updates, official marketplace autoinstall, fast mode,
artifacts, Remote Control, cloud connectors, IDE/browser integration, user/plugin
hooks, MCP, automatic memory and file checkpoints. Only the fixed managed
status-line preference exporter is allowed. The process starts with a clean
environment and does not inherit host tracing exporters.

`skipWebFetchPreflight` prevents the WebFetch domain check from contacting the
official API. `CLAUDE_CODE_SKIP_PROMPT_HISTORY=1` covers interactive mode;
`--no-session-persistence` can additionally be used with `-p`.
The selected managed endpoint and `allowedProviders=["customEndpoint"]`
require a recent Claude release. The image pipeline enforces a minimum version
and tests the actual current stable executable.

Environment flags are defense in depth. The external network and filesystem
boundaries also apply to arbitrary shell programs that ignore those flags.

## Image builds and updates

Only `.github/workflows/publish.yml` builds images. Compose has no `build`
section, and the launcher has no image-build path.

Each push to `main`, manual dispatch and daily scheduled run:

1. Checks source and gateway regression tests.
2. Resolves the official stable release and pins three base-image digests.
3. Verifies the official release manifest's GPG signature against the documented
   pinned signing-key fingerprint, then verifies each native binary's checksum
   and length. It does not run a downloaded installer.
4. Builds native Linux amd64 and arm64 runtime/gateway candidates on GitHub.
5. Tests both exact candidate digests together with an offline mock API, real
   Claude CLI tool execution, isolation probes and persistence checks.
6. Scans both candidates and blocks fixable HIGH/CRITICAL vulnerabilities.
7. Publishes multiarch manifests, provenance and SBOMs; only after all tests and
   scans pass does it promote both `latest` tags.

The runtime image contains the official Claude binary, Node, Python, Git,
curl, jq, ripgrep and basic tools. The gateway image has a standard-library Go
proxy and the small firewall/init dependencies. Model credentials and project
files are never in the build context.

The Node base's npm bundle currently needs two security repairs:
`brace-expansion` 5.0.12 and `undici` 6.28.1. CI downloads their official npm
tarballs with fixed SHA-512 integrity values and replaces only older versions
within the same major. Changed dependency requirements or unexpected layouts
stop the build; newer fixed versions are preserved. Any existing lock metadata
is updated, and npm/module smoke tests run without network access. The exact
repair record is saved at `/usr/local/share/claude-isolation/npm-security-repairs.json`.

A blocked update leaves the previous tested `latest` usable. Review Actions
failures; do not weaken the security gate just to obtain a new version.
The runtime never updates its own CLI in place.

## Verification

Run tests against published registry digests, with no local build:

```bash
python3 tests/integration.py \
  --runtime-image ghcr.io/minaduki-shigure/claude-code-isolated@sha256:ACTUAL_DIGEST \
  --gateway-image ghcr.io/minaduki-shigure/claude-code-isolated-gateway@sha256:ACTUAL_DIGEST \
  --output audit-local/verification.json
```

The harness creates a unique isolated test project and an offline fixture
upstream. It never uses a real model key, paid inference or the host proxy
configuration. See `tests/README.md` for the assertions and fixture trust scope.
Local host-proxy reachability and ordinary website access must additionally be
tested on the target machine; CI cannot establish that a user's proxy is usable.

## References

- [Claude network configuration](https://code.claude.com/docs/en/network-config)
- [Claude environment variables](https://code.claude.com/docs/en/env-vars)
- [Claude local storage](https://code.claude.com/docs/en/claude-directory)
- [Claude automatic memory](https://code.claude.com/docs/en/memory#auto-memory)
- [Subagent memory](https://code.claude.com/docs/en/sub-agents#enable-persistent-memory)
- [Official release signature verification](https://code.claude.com/docs/en/setup#verify-the-manifest-signature)
- [Official IP ranges](https://platform.claude.com/docs/en/api/ip-addresses)
- [Docker none networking](https://docs.docker.com/engine/network/drivers/none/)
- [Docker tmpfs limitations](https://docs.docker.com/engine/storage/tmpfs/)
