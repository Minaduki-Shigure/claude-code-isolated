# Images are built only by .github/workflows/publish.yml.
# CI resolves these human-readable base tags to immutable multi-platform digests.
ARG RUNTIME_BASE=node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5
ARG GATEWAY_BASE=debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
ARG GO_BASE=golang:1-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110

FROM ${GO_BASE} AS gateway-build
WORKDIR /src/gateway
COPY gateway/ ./
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN --network=none go test ./... \
    && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/claude-egress .

FROM ${GATEWAY_BASE} AS gateway
ARG BUILD_DATE
ARG VCS_REF
ARG CLAUDE_VERSION
ARG GATEWAY_BASE
RUN test -n "$BUILD_DATE" \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates iptables util-linux passwd \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 gateway \
    && useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin gateway \
    && install -d -m 0755 /opt/claude-isolation /etc/claude-isolation /run/claude-ipc
COPY --from=gateway-build /out/claude-egress /usr/local/bin/claude-egress
COPY --chmod=0555 scripts/gateway-entrypoint.sh /opt/claude-isolation/gateway-entrypoint.sh
COPY dist/build-inputs.json /usr/local/share/claude-isolation/build-inputs.json
LABEL org.opencontainers.image.title="Claude Code isolation gateway" \
      org.opencontainers.image.description="HTTP filtering over Unix socket, pinned-IP upstream proxy egress" \
      org.opencontainers.image.source="https://github.com/Minaduki-Shigure/claude-code-isolated" \
      org.opencontainers.image.version="${CLAUDE_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.base.name="${GATEWAY_BASE}"
ENV IPC_DIR=/run/claude-ipc POLICY_FILE=/etc/claude-isolation/policy.json
ENTRYPOINT ["/opt/claude-isolation/gateway-entrypoint.sh"]

FROM ${RUNTIME_BASE} AS runtime
ARG BUILD_DATE
ARG VCS_REF
ARG CLAUDE_VERSION
ARG RUNTIME_BASE
RUN test -n "$BUILD_DATE" \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl git jq less openssl python3 python3-venv ripgrep tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o node -g node /workspace /var/lib/claude-preferences \
    && install -d -m 0755 /opt/claude-isolation /etc/claude-code
# Repair only the two confirmed vulnerable npm dependencies, keeping the same
# major versions. No install hooks or network access during patch application.
COPY dist/npm-patches/ /tmp/npm-patches/
COPY scripts/upstream.py /tmp/build-upstream.py
RUN --network=none mkdir -p /usr/local/share/claude-isolation \
    && python3 /tmp/build-upstream.py apply-npm-patches --patch-dir /tmp/npm-patches \
       > /usr/local/share/claude-isolation/npm-security-repairs.json \
    && npm --version \
    && node -e "const p='/usr/local/lib/node_modules/npm/node_modules/'; const b=require(p+'brace-expansion'); if(b.expand('a{b,c}').join(',')!=='ab,ac')throw Error('brace expansion failed'); const u=require(p+'undici'); if(typeof u.request!=='function')throw Error('undici load failed')" \
    && rm -rf /tmp/npm-patches /tmp/build-upstream.py /root/.npm
# Fetch in CI first, check the signed release manifest, then copy the raw native
# executable. Never run an upstream install script or install into the user's HOME.
COPY --chmod=0555 dist/claude /usr/local/bin/claude
COPY --chmod=0555 scripts/runtime-entrypoint.py /opt/claude-isolation/runtime-entrypoint.py
COPY --chmod=0444 scripts/startup_config.py /opt/claude-isolation/startup_config.py
COPY --chmod=0555 scripts/launch-claude.py scripts/export-preferences.py /opt/claude-isolation/
COPY dist/build-inputs.json /usr/local/share/claude-isolation/build-inputs.json
ENV HOME=/home/node \
    TZ=America/Los_Angeles \
    CLAUDE_CONFIG_DIR=/home/node/.claude \
    DISABLE_AUTOUPDATER=1 \
    DISABLE_UPDATES=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    DISABLE_TELEMETRY=1 \
    DISABLE_ERROR_REPORTING=1 \
    DO_NOT_TRACK=1
RUN --network=none test "$(claude --version)" = "${CLAUDE_VERSION} (Claude Code)" \
    && rm -rf /root/.claude /root/.claude.json /home/node/.claude /home/node/.claude.json
LABEL org.opencontainers.image.title="Isolated Claude Code" \
      org.opencontainers.image.description="Verified official Claude Code, ephemeral state and socket-only proxy networking" \
      org.opencontainers.image.source="https://github.com/Minaduki-Shigure/claude-code-isolated" \
      org.opencontainers.image.version="${CLAUDE_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.base.name="${RUNTIME_BASE}"
USER node
WORKDIR /workspace
ENTRYPOINT ["python3", "/opt/claude-isolation/runtime-entrypoint.py"]
CMD []
