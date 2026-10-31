# rust:1.94.1-alpine3.23, pinned multi-platform manifest.
FROM rust@sha256:77237dd363a0b127bb5ef532c2d64c0deb380b738e43a9c4bdac73398d6d0a08 AS build
WORKDIR /build
COPY probe.rs /build/probe.rs
RUN rustc --edition=2024 -D warnings -C opt-level=2 -C strip=symbols /build/probe.rs -o /probe

FROM scratch
COPY --from=build /probe /probe
USER 65534:65534
ENV PATH=/ HOME=/work
LABEL io.patchriot.fixture-probe="1"
ENTRYPOINT ["/probe"]
