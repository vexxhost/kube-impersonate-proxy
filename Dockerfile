# Copyright (c) 2025 VEXXHOST, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.26@sha256:b54cbf583d390341599d7bcbc062425c081105cc5ef6d170ced98ef9d047c716 AS builder
WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download
COPY . /src
RUN CGO_ENABLED=0 go build -o /kube-impersonate-proxy ./cmd/kube-impersonate-proxy

FROM gcr.io/distroless/static-debian12
COPY --from=builder /kube-impersonate-proxy /bin/kube-impersonate-proxy
ENTRYPOINT ["/bin/kube-impersonate-proxy"]
