# Official Hermes 0.22.5 image, pinned multi-platform manifest.
FROM nousresearch/hermes-agent@sha256:9c5561579f3ffdf333401797094ac3a743738d6c25d40f4331c7bf77b694238d
COPY adapter.py access.py check.py /patchriot/
USER 65534:65534
WORKDIR /work
ENV HOME=/opt/data HERMES_HOME=/opt/data/hermes PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/opt/hermes TERMINAL_ENV=local TERMINAL_CWD=/work HERMES_API_TIMEOUT=540
LABEL io.patchriot.agent-adapter="1"
ENTRYPOINT ["/opt/hermes/.venv/bin/python", "/patchriot/adapter.py"]
