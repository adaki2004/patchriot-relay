# Upstream ARTEX engine; do not run its installer or expose its web service.
FROM golang@sha256:386d475a660466863d9f8c766fec64d7fdad3edac2c6a05020c09534d71edb4b AS engine
ADD --checksum=sha256:e11f67df2f400c965fcf6ef580c86408f8081b8452851d3421300f0215b2f36b https://codeload.github.com/BaaRai/ARTEX/tar.gz/9ebc8b6703ead14dc83979d44a4bc482d36cecd8 /tmp/artex.tar.gz
WORKDIR /src
RUN tar -xzf /tmp/artex.tar.gz --strip-components=1 && \
    GOMAXPROCS=2 CGO_ENABLED=0 go build -p 2 -mod=readonly -trimpath -ldflags='-s -w -X main.version=9ebc8b6703ead14dc83979d44a4bc482d36cecd8' -o /out/artex ./cmd/artex && \
    go mod vendor -o /out/vendor && tar -czf /out/dependency-source.tar.gz -C /out vendor

# Official Hermes 0.22.5 image, pinned multi-platform manifest (Debian 13).
FROM nousresearch/hermes-agent@sha256:9c5561579f3ffdf333401797094ac3a743738d6c25d40f4331c7bf77b694238d AS base
FROM base AS scanner
USER root
COPY install_nuclei.py /tmp/install_nuclei.py
RUN /opt/hermes/.venv/bin/python /tmp/install_nuclei.py

FROM base
USER root
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    postgresql-17 curl wget jq ripgrep git dnsutils nmap netcat-openbsd ffuf sqlmap \
    && rm -rf /var/lib/apt/lists/* /var/lib/postgresql/17/main \
    && mkdir -p /opt/artex /usr/share/licenses/artex \
    && ln -s /work/artex-auth/jwt.key /opt/artex/jwt.key
COPY --from=scanner /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=scanner /usr/share/licenses/nuclei /usr/share/licenses/nuclei
COPY --from=engine /out/artex /opt/artex/artex
COPY --from=engine /src/skills /opt/artex/skills
COPY --from=engine /src/LICENSE /usr/share/licenses/artex/LICENSE
COPY --from=engine /tmp/artex.tar.gz /usr/share/licenses/artex/corresponding-source.tar.gz
COPY --from=engine /out/dependency-source.tar.gz /usr/share/licenses/artex/dependency-source.tar.gz
COPY adapter.py access.py check.py inspect_site.py inspect_source.py live_http.py live_review.py live-review-skill.txt web_tools.py baseline.py artex.py /patchriot/
COPY templates /patchriot/templates
USER 65534:65534
WORKDIR /work
ENV HOME=/opt/data HERMES_HOME=/opt/data/hermes PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/opt/hermes TERMINAL_ENV=local TERMINAL_CWD=/work HERMES_API_TIMEOUT=540 NORMA_RIPGREP_NO_INSTALL=1
LABEL io.patchriot.agent-adapter="11"
ENTRYPOINT ["/opt/hermes/.venv/bin/python", "/patchriot/adapter.py"]
