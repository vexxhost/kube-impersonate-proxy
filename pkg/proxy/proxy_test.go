// Copyright (c) 2025 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
)

type mockAuthenticator struct {
	authFunc  func(context.Context, string) (*authenticator.Response, bool, error)
	healthErr error
}

func (m *mockAuthenticator) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	return m.authFunc(ctx, token)
}

func (m *mockAuthenticator) HealthCheck() error {
	return m.healthErr
}

var _ oidc.AuthenticatorTokenWithHealthCheck = (*mockAuthenticator)(nil)

var _ = Describe("Proxy", func() {
	Describe("healthz endpoints", func() {
		It("should return 200 OK on /healthz", func() {
			targetURL, err := url.Parse("http://localhost")
			Expect(err).NotTo(HaveOccurred())

			handler := NewHandler(NewOptions(
				&mockAuthenticator{
					authFunc: func(_ context.Context, _ string) (*authenticator.Response, bool, error) {
						return nil, false, nil
					},
				},
				http.DefaultTransport,
				targetURL,
			))

			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
		})

		It("should return 200 OK on /readyz when OIDC is healthy", func() {
			targetURL, err := url.Parse("http://localhost")
			Expect(err).NotTo(HaveOccurred())

			handler := NewHandler(NewOptions(
				&mockAuthenticator{
					authFunc:  func(_ context.Context, _ string) (*authenticator.Response, bool, error) { return nil, false, nil },
					healthErr: nil,
				},
				http.DefaultTransport,
				targetURL,
			))

			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
		})

		It("should return 500 on /readyz when OIDC is unhealthy", func() {
			targetURL, err := url.Parse("http://localhost")
			Expect(err).NotTo(HaveOccurred())

			handler := NewHandler(NewOptions(
				&mockAuthenticator{
					authFunc:  func(_ context.Context, _ string) (*authenticator.Response, bool, error) { return nil, false, nil },
					healthErr: errors.New("oidc provider unavailable"),
				},
				http.DefaultTransport,
				targetURL,
			))

			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusInternalServerError))
		})
	})

	Describe("impersonate middleware", func() {
		It("should return 401 when no user in context", func() {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)
			w := httptest.NewRecorder()

			impersonate(next).ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusUnauthorized))
		})

		It("should set impersonation headers when user in context", func() {
			var capturedReq *http.Request
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedReq = r
				w.WriteHeader(http.StatusOK)
			})

			ctx := request.WithUser(context.Background(), &user.DefaultInfo{
				Name:   "alice",
				Groups: []string{"developers", "admins"},
			})
			req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil).WithContext(ctx)
			w := httptest.NewRecorder()

			impersonate(next).ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			Expect(capturedReq.Header.Get(authenticationv1.ImpersonateUserHeader)).To(Equal("alice"))
			Expect(capturedReq.Header.Values(authenticationv1.ImpersonateGroupHeader)).To(ConsistOf("developers", "admins"))
		})
	})

	Describe("NewHandler", func() {
		var (
			backend     *httptest.Server
			proxy       *httptest.Server
			capturedReq *http.Request
			client      *http.Client
		)

		BeforeEach(func() {
			capturedReq = nil
			backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedReq = r
				w.WriteHeader(http.StatusOK)
			}))
			client = &http.Client{}
		})

		AfterEach(func() {
			if proxy != nil {
				proxy.Close()
			}
			backend.Close()
		})

		It("should return 401 when authentication fails", func() {
			targetURL, err := url.Parse(backend.URL)
			Expect(err).NotTo(HaveOccurred())

			proxy = httptest.NewServer(NewHandler(NewOptions(
				&mockAuthenticator{
					authFunc: func(_ context.Context, _ string) (*authenticator.Response, bool, error) {
						return nil, false, nil
					},
				},
				http.DefaultTransport,
				targetURL,
			)))

			req, err := http.NewRequest(http.MethodGet, proxy.URL+"/api/v1/pods", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", "Bearer invalid-token")

			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = resp.Body.Close() }()

			Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
			Expect(capturedReq).To(BeNil())
		})

		It("should return 401 when authenticator returns error", func() {
			targetURL, err := url.Parse(backend.URL)
			Expect(err).NotTo(HaveOccurred())

			proxy = httptest.NewServer(NewHandler(NewOptions(
				&mockAuthenticator{
					authFunc: func(_ context.Context, _ string) (*authenticator.Response, bool, error) {
						return nil, false, errors.New("oidc provider unavailable")
					},
				},
				http.DefaultTransport,
				targetURL,
			)))

			req, err := http.NewRequest(http.MethodGet, proxy.URL+"/api/v1/pods", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", "Bearer some-token")

			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = resp.Body.Close() }()

			Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
			Expect(capturedReq).To(BeNil())
		})

		It("should proxy request with impersonation headers when auth succeeds", func() {
			targetURL, err := url.Parse(backend.URL)
			Expect(err).NotTo(HaveOccurred())

			proxy = httptest.NewServer(NewHandler(NewOptions(
				&mockAuthenticator{
					authFunc: func(_ context.Context, _ string) (*authenticator.Response, bool, error) {
						return &authenticator.Response{
							User: &user.DefaultInfo{
								Name:   "charlie",
								Groups: []string{"team-a"},
							},
						}, true, nil
					},
				},
				http.DefaultTransport,
				targetURL,
			)))

			req, err := http.NewRequest(http.MethodGet, proxy.URL+"/api/v1/pods", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = resp.Body.Close() }()

			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			Expect(capturedReq).NotTo(BeNil())
			Expect(capturedReq.Header.Get(authenticationv1.ImpersonateUserHeader)).To(Equal("charlie"))
			Expect(capturedReq.Header.Values(authenticationv1.ImpersonateGroupHeader)).To(ConsistOf("team-a"))
		})

		It("should remove Authorization header from proxied request", func() {
			targetURL, err := url.Parse(backend.URL)
			Expect(err).NotTo(HaveOccurred())

			proxy = httptest.NewServer(NewHandler(NewOptions(
				&mockAuthenticator{
					authFunc: func(_ context.Context, _ string) (*authenticator.Response, bool, error) {
						return &authenticator.Response{User: &user.DefaultInfo{Name: "dave"}}, true, nil
					},
				},
				http.DefaultTransport,
				targetURL,
			)))

			req, err := http.NewRequest(http.MethodGet, proxy.URL+"/api/v1/pods", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", "Bearer secret-token")

			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = resp.Body.Close() }()

			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			Expect(capturedReq.Header.Get("Authorization")).To(BeEmpty())
		})
	})
})
