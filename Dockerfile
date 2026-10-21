# Copyright (c) 2025 VEXXHOST, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.26@sha256:672c944cfd07599b5f1bb179869270cdc94c6254e41db4d431259693cb286b82 AS builder
WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download
COPY . /src
RUN CGO_ENABLED=0 go build -o /kube-impersonate-proxy ./cmd/kube-impersonate-proxy

FROM gcr.io/distroless/static-debian12
COPY --from=builder /kube-impersonate-proxy /bin/kube-impersonate-proxy
ENTRYPOINT ["/bin/kube-impersonate-proxy"]
