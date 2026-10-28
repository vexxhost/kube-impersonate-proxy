# Copyright (c) 2025 VEXXHOST, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.26@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS builder
WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download
COPY . /src
RUN CGO_ENABLED=0 go build -o /kube-impersonate-proxy ./cmd/kube-impersonate-proxy

FROM gcr.io/distroless/static-debian12
COPY --from=builder /kube-impersonate-proxy /bin/kube-impersonate-proxy
ENTRYPOINT ["/bin/kube-impersonate-proxy"]
