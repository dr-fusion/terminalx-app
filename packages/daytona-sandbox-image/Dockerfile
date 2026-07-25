# syntax=TERMINALX_REQUIRES_PREPARED_CONTENT_ADDRESSED_FRONTEND

ARG TERMINALX_TOOLCHAIN_IMAGE
ARG TERMINALX_RUNTIME_IMAGE

FROM ${TERMINALX_TOOLCHAIN_IMAGE} AS terminalx-native-build
WORKDIR /terminalx-native-source
COPY root-tools/terminalx-sandbox-init.c root-tools/terminalx-peercred.c root-tools/terminalx-isolation-probe.c ./
RUN --network=none set -eu; \
    mkdir -p /terminalx-native-output; \
    common_flags='-std=c17 -O2 -pipe -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra -Werror -Wformat=2 -Wconversion -Wsign-conversion -Wshadow -Wstrict-prototypes'; \
    link_flags='-static -pie -Wl,-z,relro,-z,now,-z,noexecstack,--build-id=none'; \
    cc $common_flags terminalx-sandbox-init.c $link_flags -o /terminalx-native-output/terminalx-sandbox-init; \
    cc $common_flags terminalx-peercred.c $link_flags -o /terminalx-native-output/terminalx-peercred; \
    cc $common_flags terminalx-isolation-probe.c $link_flags -o /terminalx-native-output/terminalx-isolation-probe; \
    chmod 0555 /terminalx-native-output/terminalx-sandbox-init /terminalx-native-output/terminalx-isolation-probe; \
    chmod 0500 /terminalx-native-output/terminalx-peercred; \
    test ! -L /terminalx-native-output/terminalx-sandbox-init; \
    test ! -L /terminalx-native-output/terminalx-peercred; \
    test ! -L /terminalx-native-output/terminalx-isolation-probe

FROM scratch AS terminalx-native-artifacts
COPY --from=terminalx-native-build --chown=0:0 --chmod=0555 /terminalx-native-output/terminalx-sandbox-init /terminalx-sandbox-init
COPY --from=terminalx-native-build --chown=0:0 --chmod=0500 /terminalx-native-output/terminalx-peercred /terminalx-peercred
COPY --from=terminalx-native-build --chown=0:0 --chmod=0555 /terminalx-native-output/terminalx-isolation-probe /terminalx-isolation-probe

FROM ${TERMINALX_RUNTIME_IMAGE} AS terminalx-sandbox

ARG SOURCE_DATE_EPOCH
ARG TERMINALX_SUPERVISOR_ARTIFACT_SHA256
ARG TERMINALX_SUPERVISOR_SHA256
ARG TERMINALX_SUPERVISOR_RELAY_SHA256
ARG TERMINALX_ASSIGNMENT_BOOTSTRAP_SHA256
ARG TERMINALX_DAYTONA_DAEMON_SHA256
ARG TERMINALX_EFFECT_ENFORCER_SHA256
ARG TERMINALX_NODE_SHA256
ARG TERMINALX_SANDBOX_INIT_SHA256
ARG TERMINALX_PEERCRED_SHA256
ARG TERMINALX_ISOLATION_PROBE_SHA256
ARG TERMINALX_DEPLOYMENT_BINDING_INSTALL_SHA256
ARG TERMINALX_SOURCE_COMMIT
ARG TERMINALX_DAYTONA_SOURCE_COMMIT

SHELL ["/bin/sh", "-eu", "-c"]
USER 0

RUN --network=none \
    command -v getent >/dev/null; \
    command -v groupadd >/dev/null; \
    command -v install >/dev/null; \
    command -v useradd >/dev/null; \
    command -v sha256sum >/dev/null; \
    command -v stat >/dev/null; \
    if getent passwd terminalx >/dev/null; then \
      test "$(id -u terminalx)" = 10001; \
      test "$(id -g terminalx)" = 10001; \
      test "$(getent passwd terminalx | cut -d: -f6)" = /home/terminalx; \
    else \
      ! getent passwd 10001 >/dev/null; \
      if getent group terminalx >/dev/null; then test "$(getent group terminalx | cut -d: -f3)" = 10001; \
      else ! getent group 10001 >/dev/null; groupadd --gid 10001 terminalx; fi; \
      useradd --uid 10001 --gid 10001 --home-dir /home/terminalx --shell /bin/sh --no-create-home terminalx; \
    fi; \
    install -d -o 10001 -g 10001 -m 0700 /home/terminalx; \
    install -d -o 0 -g 0 -m 0500 /etc/terminalx /usr/local/libexec/terminalx; \
    install -d -o 0 -g 0 -m 0700 /run/terminalx-private /run/terminalx-root /run/terminalx-root/live /var/lib/terminalx-supervisor; \
    test ! -L /usr/local/bin/node; \
    test -f /usr/local/bin/node; \
    test "$(stat -c '%h:%u:%g' /usr/local/bin/node)" = 1:0:0; \
    chmod 0555 /usr/local/bin/node

COPY --from=terminalx-native-build --chown=0:0 --chmod=0555 /terminalx-native-output/terminalx-sandbox-init /usr/local/bin/terminalx-sandbox-init
COPY --from=terminalx-native-build --chown=0:0 --chmod=0500 /terminalx-native-output/terminalx-peercred /usr/local/libexec/terminalx/terminalx-peercred
COPY --from=terminalx-native-build --chown=0:0 --chmod=0555 /terminalx-native-output/terminalx-isolation-probe /usr/local/libexec/terminalx/terminalx-isolation-probe
COPY --chown=0:0 --chmod=0555 inputs/daytona /usr/local/bin/daytona
COPY --chown=0:0 --chmod=0555 inputs/terminalx-daytona-supervisor /usr/local/libexec/terminalx/terminalx-daytona-supervisor
COPY --chown=0:0 --chmod=0555 inputs/terminalx-supervisor-relay /usr/local/libexec/terminalx/terminalx-supervisor-relay
COPY --chown=0:0 --chmod=0555 inputs/terminalx-assignment-bootstrap /usr/local/libexec/terminalx/terminalx-assignment-bootstrap
COPY --chown=0:0 --chmod=0555 inputs/terminalx-deployment-binding-install /usr/local/libexec/terminalx/terminalx-deployment-binding-install
COPY --chown=0:0 --chmod=0500 inputs/terminalx-effect-enforcer /usr/local/libexec/terminalx/terminalx-effect-enforcer
COPY --chown=0:0 --chmod=0600 inputs/bootstrap-authority-pin.json /etc/terminalx/bootstrap-authority-pin.json
COPY --chown=0:0 --chmod=0444 inputs/daytona-supervisor-artifact.json /usr/share/terminalx/daytona-supervisor-artifact.json
COPY --chown=0:0 --chmod=0600 inputs/sandbox-trust-input.json /terminalx-build/inputs/sandbox-trust-input.json
COPY --chown=0:0 --chmod=0600 native-hashes.json /terminalx-build/native-hashes.json
COPY --chown=0:0 --chmod=0500 scripts/write-static-pins.mjs /terminalx-build/write-static-pins.mjs
COPY --chown=0:0 --chmod=0500 scripts/audit-final-rootfs.mjs /terminalx-build/audit-final-rootfs.mjs

RUN --network=none \
    is_sha256() { case "$1" in (*[!0-9a-f]*|'') return 1;; esac; test "${#1}" = 64; }; \
    check_hash() { is_sha256 "$2"; test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"; }; \
    check_file() { test ! -L "$1"; test -f "$1"; test "$(stat -c '%h:%u:%g:%a' "$1")" = "1:0:0:$2"; }; \
    check_file /usr/local/bin/node 555; \
    check_file /usr/local/bin/daytona 555; \
    check_file /usr/local/bin/terminalx-sandbox-init 555; \
    check_file /usr/local/libexec/terminalx/terminalx-daytona-supervisor 555; \
    check_file /usr/local/libexec/terminalx/terminalx-supervisor-relay 555; \
    check_file /usr/local/libexec/terminalx/terminalx-assignment-bootstrap 555; \
    check_file /usr/local/libexec/terminalx/terminalx-deployment-binding-install 555; \
    check_file /usr/local/libexec/terminalx/terminalx-isolation-probe 555; \
    check_file /usr/local/libexec/terminalx/terminalx-peercred 500; \
    check_file /usr/local/libexec/terminalx/terminalx-effect-enforcer 500; \
    check_hash /usr/local/bin/node "$TERMINALX_NODE_SHA256"; \
    check_hash /usr/local/bin/daytona "$TERMINALX_DAYTONA_DAEMON_SHA256"; \
    check_hash /usr/local/bin/terminalx-sandbox-init "$TERMINALX_SANDBOX_INIT_SHA256"; \
    check_hash /usr/local/libexec/terminalx/terminalx-daytona-supervisor "$TERMINALX_SUPERVISOR_SHA256"; \
    check_hash /usr/local/libexec/terminalx/terminalx-supervisor-relay "$TERMINALX_SUPERVISOR_RELAY_SHA256"; \
    check_hash /usr/local/libexec/terminalx/terminalx-assignment-bootstrap "$TERMINALX_ASSIGNMENT_BOOTSTRAP_SHA256"; \
    check_hash /usr/local/libexec/terminalx/terminalx-deployment-binding-install "$TERMINALX_DEPLOYMENT_BINDING_INSTALL_SHA256"; \
    check_hash /usr/local/libexec/terminalx/terminalx-isolation-probe "$TERMINALX_ISOLATION_PROBE_SHA256"; \
    check_hash /usr/local/libexec/terminalx/terminalx-peercred "$TERMINALX_PEERCRED_SHA256"; \
    check_hash /usr/local/libexec/terminalx/terminalx-effect-enforcer "$TERMINALX_EFFECT_ENFORCER_SHA256"; \
    /usr/local/bin/node /terminalx-build/write-static-pins.mjs; \
    check_file /etc/terminalx/bootstrap-authority-pin.json 600; \
    check_file /etc/terminalx/sandbox-trust-pins.json 600; \
    find / -xdev -type f -perm /6000 -exec chmod a-s '{}' +; \
    /usr/local/bin/node /terminalx-build/audit-final-rootfs.mjs; \
    rm -rf /terminalx-build; \
    chmod 0500 /etc/terminalx /usr/local/libexec/terminalx; \
    chmod 0700 /run/terminalx-private /run/terminalx-root /run/terminalx-root/live /var/lib/terminalx-supervisor; \
    test ! -e /run/terminalx-private/daytona-daemon.sock; \
    test ! -e /run/terminalx-root/deployment-binding.json; \
    test ! -e /run/terminalx-root/assignment; \
    test -z "$(find /run/terminalx-root/live -mindepth 1 -maxdepth 1 -print -quit)"

LABEL io.terminalx.sandbox.profile="v1" \
      io.terminalx.supervisor-relay.sha256="${TERMINALX_SUPERVISOR_RELAY_SHA256}" \
      io.terminalx.assignment-bootstrap.sha256="${TERMINALX_ASSIGNMENT_BOOTSTRAP_SHA256}" \
      io.terminalx.node.sha256="${TERMINALX_NODE_SHA256}" \
      io.terminalx.deployment-binding-installer.sha256="${TERMINALX_DEPLOYMENT_BINDING_INSTALL_SHA256}" \
      io.terminalx.isolation-probe.sha256="${TERMINALX_ISOLATION_PROBE_SHA256}" \
      io.terminalx.sandbox-init.sha256="${TERMINALX_SANDBOX_INIT_SHA256}" \
      io.terminalx.peercred.sha256="${TERMINALX_PEERCRED_SHA256}" \
      io.terminalx.daytona-daemon.sha256="${TERMINALX_DAYTONA_DAEMON_SHA256}" \
      io.terminalx.effect-enforcer.sha256="${TERMINALX_EFFECT_ENFORCER_SHA256}" \
      io.terminalx.supervisor.sha256="${TERMINALX_SUPERVISOR_SHA256}" \
      io.terminalx.supervisor-artifact.sha256="${TERMINALX_SUPERVISOR_ARTIFACT_SHA256}" \
      io.terminalx.daytona-source.commit="${TERMINALX_DAYTONA_SOURCE_COMMIT}" \
      org.opencontainers.image.revision="${TERMINALX_SOURCE_COMMIT}" \
      io.terminalx.source-date-epoch="${SOURCE_DATE_EPOCH}"

WORKDIR /home/terminalx
USER 0
STOPSIGNAL SIGTERM
HEALTHCHECK NONE
ENTRYPOINT ["/usr/local/bin/terminalx-sandbox-init"]
CMD []
