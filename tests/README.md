# Isolation verification

Run the integration test against the exact candidate digests published by
GitHub Actions:

```sh
python3 tests/integration.py \
  --runtime-image ghcr.io/OWNER/claude-code-isolated@sha256:RUNTIME_DIGEST \
  --gateway-image ghcr.io/OWNER/claude-code-isolated-gateway@sha256:GATEWAY_DIGEST \
  --output verification.json
```

The command rejects tag-only image references. It pulls published images and
never runs `docker build`, `docker compose build`, or Buildx. Requirements are
Python 3, OpenSSL, a running Docker daemon, and Docker Compose v2 with `--wait`.
The runtime image supplies Python and curl.

The harness uses the production `compose.yaml` and a temporary override:

- A unique Compose project owns every test container, network, and volume.
- The proxy network is `internal: true`; no fixture request reaches the internet.
- An offline upstream proxy reuses the published runtime image with a Python
  entrypoint. It never opens outgoing sockets.
- A temporary fixture CA is trusted only by the gateway. Its certificate covers
  the fixture DNS and model names. The gateway still creates its normal,
  independent interception CA.
- DoH replies resolve fixture names to public IPv4/IPv6 addresses. The gateway
  must validate these addresses and send numeric CONNECT targets to the upstream
  fixture. No production domain/IP rule is weakened for tests.
- The model key is a fixed fake string. The fixture records request type,
  hostname, path, and stream/tool flags, but never credentials or prompt bodies.
- Cleanup removes only resources created under this test's unique project and
  container names. No existing proxy configuration or container is touched.

## What is verified

1. Runtime network mode is `none`; no non-loopback interface has `IFF_UP`, the
   IPv4 route table is empty, and IPv6 routes reference only loopback. Direct
   IPv4/IPv6, direct host proxy access, and direct UDP DNS fail. AF_VSOCK creation
   fails. DOWN kernel fallback tunnel devices, which some LinuxKit versions expose
   even in an isolated namespace, do not count as usable network connectivity.
2. The runtime and actual gateway worker run as UID 1000 with zero effective and
   bounding capabilities and `NoNewPrivs=1`. Runtime rootfs is read-only and Docker
   logging is disabled. The workspace is the sole writable host bind mount.
3. A probe sharing the gateway network namespace can reach the configured
   upstream proxy port but cannot reach a second, confirmed-live fixture port.
   This verifies the gateway firewall using actual socket connections.
4. Allowed HTTP and HTTPS requests succeed through the full relay, Unix socket,
   filtering gateway, and upstream proxy chain.
5. Official and known telemetry domains, domain suffixes, case/trailing-dot
   variants, IP literals, private/metadata IPs, official CIDRs, forbidden CNAMEs,
   mixed safe/private DNS answers, and unsafe AAAA answers are rejected.
6. Redirects to an official endpoint, nonstandard CONNECT ports, missing or
   mismatched TLS SNI, HTTPS Host mismatch, inner absolute-form mismatch, nested
   CONNECT, and WebSocket upgrades are rejected.
7. A host omitted from the fixture certificate gets a gateway error, proving
   upstream certificate verification remains active.
8. A real Claude Code process calls the fake Messages API using streaming SSE,
   executes a permitted Bash tool that creates a workspace marker, returns the
   tool result to the model, and receives the final answer.
9. Print-mode session persistence is disabled. The prompt marker does not
   appear in persistent mounts or a session/history JSONL. Explicit state markers
   in HOME, `/tmp`, and the masked project `.claude` disappear in a newly created
   container. The workspace marker and pure user settings remain; the underlying
   project `.claude` file and host settings are unchanged.
10. The fixture audit confirms numeric upstream CONNECT destinations and that
    no official/telemetry HTTP request reached it. Stopping the fixture makes
    subsequent requests fail closed.

Go's `net/http` parser canonicalizes a plain HTTP absolute-form request's Host
from its request-target before handing it to the gateway. For a conflicting raw
Host header the test accepts either rejection or canonical forwarding to the
allowed target; it separately audits the Host actually received upstream.
Inside HTTPS, origin-form Host and TLS SNI must match the authorized CONNECT
origin.

## Evidence boundaries

A passing report describes these exact image digests, the tested architecture,
and the production policy present in the checkout. GitHub Actions runs it on
native amd64 and arm64 runners before updating release tags. A fixture test does
not validate the user's real API credential, real model gateway, host proxy
availability, or all internet software.

The harness tests both non-interactive print mode and an actual interactive PTY.
The default interactive test confirms only the disposable fixture workspace and
the fixed fake API key. A second, pre-approved configuration must start without
sending any confirmation keys, report auto/Max/ultracode through the live CLI,
receive a model response, and exit. The live preference regression switches model,
then effort from low to max, verifies the managed exporter captured Max despite
the ordinary settings file retaining Low, and restores those values in a fresh
container. User hooks/status lines must not execute. Fresh containers must reapply
the preferences without retaining transcripts, history or cache. The runtime zone
is checked against fixed winter and summer dates to verify PST/PDT transitions. Host-side tests bind approvals
to the exact workspace and endpoint/auth/full-key digest, including two different
keys with the same suffix. The effective global state path is also checked:
a print-mode success alone would miss a first-run onboarding failure. Arbitrary tools can deliberately write
conversation content into the writable workspace; no general-purpose writable
workspace can prevent that. Docker tmpfs is not proof of forensic zero traces on
the host. A domain/IP blacklist cannot enumerate future unknown telemetry or a
third party's server-side forwarding.

The protocol fixture follows the official
[Messages streaming event sequence](https://platform.claude.com/docs/en/build-with-claude/streaming).
The CLI test uses the documented
[`--no-session-persistence` print-mode flag](https://code.claude.com/docs/en/cli-reference).

## Real host proxy smoke test

After pulling a matched pair of tested digests, verify the actual host proxy:

```sh
python3 tests/host_proxy_smoke.py \
  --runtime-image ghcr.io/OWNER/claude-code-isolated@sha256:RUNTIME_DIGEST \
  --gateway-image ghcr.io/OWNER/claude-code-isolated-gateway@sha256:GATEWAY_DIGEST \
  --host-proxy-host host.docker.internal --host-proxy-port 6152 \
  --output host-proxy-verification.json
```

This test invokes the production launcher with `--pull never`, a disposable
workspace, and a fake key. It neither builds nor pulls images and makes no model
request. Its only allowed live origin is `example.com`, over HTTP and HTTPS;
the gateway also uses its configured DoH service. Known official endpoints,
telemetry names, and IP literals must be rejected by the local gateway. Direct
sockets and a request with all proxy variables removed must fail. Finally it
checks normal-exit and SIGTERM cleanup using each launcher's reported random
project label, including removal of staged configuration and credential files.
It does not alter the host proxy or manage unrelated Docker resources.

## Interactive preference smoke test

Use already-pulled, matching release digests to test the production launcher's
interactive preference save and restore path:

```sh
python3 tests/preferences_smoke.py \
  --runtime-image ghcr.io/OWNER/claude-code-isolated@sha256:RUNTIME_DIGEST \
  --gateway-image ghcr.io/OWNER/claude-code-isolated-gateway@sha256:GATEWAY_DIGEST \
  --host-proxy-host host.docker.internal --host-proxy-port 6152 \
  --output preferences-verification.json
```

The test uses two real host PTY launches with temporary configuration, an empty
workspace, and a fake API key. It reads no deployment `.env` or real credential,
never builds or pulls images, and sends only built-in slash commands, with no
user task prompt. Claude Code may perform its own provider/model checks. It verifies that the native status line tracks model and effort
changes, including session-only Max, and that the next launch restores them.
Only model/effort may change in the host preferences, which must remain mode 0600;
workspace session files, each test project's Docker resources, and staged
configuration must be absent after exit. Existing containers and proxy settings
are untouched.
