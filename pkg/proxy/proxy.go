// Copyright (c) 2025 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/util/proxy"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/klog/v2"
)

// NewHandler creates the proxy handler from options.
func NewHandler(opts Options) http.Handler {
	mux := http.NewServeMux()
	healthz.InstallHandler(mux, healthz.PingHealthz)
	healthz.InstallReadyzHandler(mux,
		healthz.PingHealthz,
		healthz.NamedCheck("oidc", func(_ *http.Request) error {
			return opts.oidcAuthenticator.HealthCheck()
		}),
	)
	mux.Handle("/", filters.WithAuthentication(
		impersonate(proxy.NewUpgradeAwareHandler(opts.targetURL, opts.transport, true, false, nil)),
		bearertoken.New(opts.oidcAuthenticator),
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}),
		nil,
		nil,
	))

	return mux
}

func impersonate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := request.UserFrom(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		klog.FromContext(r.Context()).Info("proxying request",
			"user", user.GetName(),
			"groups", user.GetGroups(),
			"method", r.Method,
			"path", r.URL.Path,
		)

		r.Header.Set(authenticationv1.ImpersonateUserHeader, user.GetName())
		for _, group := range user.GetGroups() {
			r.Header.Add(authenticationv1.ImpersonateGroupHeader, group)
		}

		next.ServeHTTP(w, r)
	})
}
