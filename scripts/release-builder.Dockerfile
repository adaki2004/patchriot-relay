# Native crypto libraries used by the NEAR attestation verifier. Kept in the
# build image; the released musl binary does not require a host OpenSSL install.
FROM rust@sha256:7c094ad1afb45a61e28dd007a2add9d8ac171fd3a268e5f8f74b8aebe6c723ae
RUN apk add --no-cache openssl-dev openssl-libs-static pkgconf
ENV OPENSSL_STATIC=1
