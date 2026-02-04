// Copyright (c) 2025 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/url"

	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
)

//go:generate go run github.com/kazhuravlev/options-gen/cmd/options-gen@latest -out-filename=options_generated.go -from-struct=Options

type Options struct {
	oidcAuthenticator oidc.AuthenticatorTokenWithHealthCheck `option:"mandatory"`
	transport         http.RoundTripper                      `option:"mandatory"`
	targetURL         *url.URL                               `option:"mandatory"`
}
