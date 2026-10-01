# Copyright (c) 2025 VEXXHOST, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27@sha256:e0174e51e81218523251d85d248a90d24c3d5e81543b4f07a5d66229397db190 AS builder
WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download
COPY . /src
RUN CGO_ENABLED=0 go build -o /kube-impersonate-proxy ./cmd/kube-impersonate-proxy

FROM gcr.io/distroless/static-debian12
COPY --from=builder /kube-impersonate-proxy /bin/kube-impersonate-proxy
ENTRYPOINT ["/bin/kube-impersonate-proxy"]
