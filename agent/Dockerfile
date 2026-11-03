# Official Hermes 0.22.5 image, pinned multi-platform manifest.
FROM nousresearch/hermes-agent@sha256:9c5561579f3ffdf333401797094ac3a743738d6c25d40f4331c7bf77b694238d AS base
FROM base AS scanner
USER root
COPY install_nuclei.py /tmp/install_nuclei.py
RUN /opt/hermes/.venv/bin/python /tmp/install_nuclei.py

FROM base
COPY --from=scanner /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=scanner /usr/share/licenses/nuclei /usr/share/licenses/nuclei
COPY adapter.py access.py check.py inspect_site.py inspect_source.py live_http.py live_review.py live-review-skill.txt web_tools.py /patchriot/
COPY templates /patchriot/templates
USER 65534:65534
WORKDIR /work
ENV HOME=/opt/data HERMES_HOME=/opt/data/hermes PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/opt/hermes TERMINAL_ENV=local TERMINAL_CWD=/work HERMES_API_TIMEOUT=540
LABEL io.patchriot.agent-adapter="6"
ENTRYPOINT ["/opt/hermes/.venv/bin/python", "/patchriot/adapter.py"]
