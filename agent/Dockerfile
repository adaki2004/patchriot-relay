# Official Hermes 0.22.5 image, pinned multi-platform manifest (Debian 13).
FROM nousresearch/hermes-agent@sha256:9c5561579f3ffdf333401797094ac3a743738d6c25d40f4331c7bf77b694238d AS base
FROM base AS scanner
USER root
COPY install_nuclei.py /tmp/install_nuclei.py
RUN /opt/hermes/.venv/bin/python /tmp/install_nuclei.py

FROM base
USER root
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    openjdk-21-jre-headless curl jq ripgrep ffuf chromium \
    && rm -rf /var/lib/apt/lists/*
RUN /opt/hermes/.venv/bin/python -m ensurepip --upgrade && \
    /opt/hermes/.venv/bin/python -m pip install --no-cache-dir playwright==1.60.0 schemathesis==4.33.1
# Pinned upstream scanner distribution, used only inside the scoped container.
ADD --checksum=sha256:efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz /tmp/zap.tar.gz
RUN mkdir -p /opt/zap && tar -xzf /tmp/zap.tar.gz -C /opt/zap --strip-components=1 && rm /tmp/zap.tar.gz
# Match the pinned Hermes manifest. Install at build time; task containers have
# no network/package installation and attach only to our scoped Chromium.
ADD --checksum=sha256:8a48cf4110d7dc2c12c1c4d6d25e0babdfa31604b537f05df0dc835fe2f854bf https://registry.npmjs.org/agent-browser/-/agent-browser-0.26.0.tgz /tmp/agent-browser.tgz
RUN mkdir -p /opt/agent-browser && \
    tar -xzf /tmp/agent-browser.tgz -C /opt/agent-browser --strip-components=1 && \
    case "$(dpkg --print-architecture)" in amd64) browser_arch=x64 ;; arm64) browser_arch=arm64 ;; *) exit 1 ;; esac && \
    chmod 755 "/opt/agent-browser/bin/agent-browser-linux-${browser_arch}" && \
    ln -s "/opt/agent-browser/bin/agent-browser-linux-${browser_arch}" /usr/local/bin/agent-browser && \
    rm /tmp/agent-browser.tgz
COPY --from=scanner /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=scanner /usr/share/licenses/nuclei /usr/share/licenses/nuclei
COPY scoped_scanners.py schema_cases.py coverage_ledger.py adapter.py access.py check.py inspect_site.py inspect_source.py live_http.py live_review.py live-review-skill.txt web_tools.py baseline.py deep_checks.py deep_extra.py ares_web.py workflow.py report_finish.py conversation_recovery.py /patchriot/
COPY ares-LICENSE.txt /usr/share/licenses/ares/LICENSE
COPY browser_access.py browser_wallet.js test_browser_access.py /patchriot/
COPY templates /patchriot/templates
COPY toolchain.py /patchriot/toolchain.py
RUN /opt/hermes/.venv/bin/python /patchriot/toolchain.py
USER 65534:65534
WORKDIR /work
ENV HOME=/opt/data HERMES_HOME=/opt/data/hermes PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/opt/hermes TERMINAL_ENV=local TERMINAL_CWD=/work HERMES_API_TIMEOUT=540
LABEL io.patchriot.agent-adapter="25"
ENTRYPOINT ["/opt/hermes/.venv/bin/python", "/patchriot/adapter.py"]
