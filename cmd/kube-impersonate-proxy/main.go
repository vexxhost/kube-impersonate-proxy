// Copyright (c) 2025 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apiserver/pkg/apis/apiserver"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/cli"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/logs"
	logsapi "k8s.io/component-base/logs/api/v1"
	"k8s.io/component-base/term"
	"k8s.io/component-base/version/verflag"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"github.com/vexxhost/kube-impersonate-proxy/pkg/proxy"
)

func main() {
	command := NewProxyCommand()
	code := cli.Run(command)
	os.Exit(code)
}

func NewProxyCommand() *cobra.Command {
	logOptions := logs.NewOptions()

	var (
		listenAddr    = ":8080"
		issuerURL     string
		clientID      string
		usernameClaim = "email"
		groupsClaim   = "groups"
	)

	cmd := &cobra.Command{
		Use:   "kube-impersonate-proxy",
		Short: "OIDC authentication proxy for Kubernetes API using impersonation",
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			if err := logsapi.ValidateAndApply(logOptions, nil); err != nil {
				return fmt.Errorf("failed to apply logging configuration: %w", err)
			}

			if issuerURL == "" {
				return fmt.Errorf("--oidc-issuer-url is required")
			}
			if clientID == "" {
				return fmt.Errorf("--oidc-client-id is required")
			}

			ctx := genericapiserver.SetupSignalContext()

			klog.InfoS("Starting kube-impersonate-proxy",
				"issuerURL", issuerURL,
				"clientID", clientID,
				"usernameClaim", usernameClaim,
				"groupsClaim", groupsClaim,
				"listenAddr", listenAddr,
			)

			oidcAuth, err := oidc.New(ctx, oidc.Options{
				JWTAuthenticator: apiserver.JWTAuthenticator{
					Issuer: apiserver.Issuer{
						URL:       issuerURL,
						Audiences: []string{clientID},
					},
					ClaimMappings: apiserver.ClaimMappings{
						Username: apiserver.PrefixedClaimOrExpression{
							Claim:  usernameClaim,
							Prefix: ptr.To(""),
						},
						Groups: apiserver.PrefixedClaimOrExpression{
							Claim:  groupsClaim,
							Prefix: ptr.To(""),
						},
					},
				},
			})
			if err != nil {
				return fmt.Errorf("failed to create OIDC authenticator: %w", err)
			}

			restConfig, err := rest.InClusterConfig()
			if err != nil {
				return fmt.Errorf("failed to get in-cluster config: %w", err)
			}

			transport, err := rest.TransportFor(restConfig)
			if err != nil {
				return fmt.Errorf("failed to create transport: %w", err)
			}

			targetURL, err := url.Parse(restConfig.Host)
			if err != nil {
				return fmt.Errorf("failed to parse API server URL: %w", err)
			}

			handler := proxy.NewHandler(proxy.NewOptions(oidcAuth, transport, targetURL))

			ln, err := net.Listen("tcp", listenAddr)
			if err != nil {
				return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
			}

			klog.InfoS("Listening", "addr", ln.Addr())

			server := &http.Server{
				Handler:           handler,
				MaxHeaderBytes:    1 << 20,
				IdleTimeout:       90 * time.Second,
				ReadHeaderTimeout: 32 * time.Second,
			}

			stoppedCh, _, err := genericapiserver.RunServer(server, ln, 30*time.Second, ctx.Done())
			if err != nil {
				return fmt.Errorf("failed to run server: %w", err)
			}

			<-stoppedCh
			klog.InfoS("Server stopped")

			return nil
		},
	}

	var fss cliflag.NamedFlagSets

	authFS := fss.FlagSet("authentication")
	authFS.StringVar(&issuerURL, "oidc-issuer-url", issuerURL, "URL of the OpenID issuer.")
	authFS.StringVar(&clientID, "oidc-client-id", clientID, "Client ID for the OpenID Connect client.")
	authFS.StringVar(&usernameClaim, "oidc-username-claim", usernameClaim, "JWT claim to use as the username.")
	authFS.StringVar(&groupsClaim, "oidc-groups-claim", groupsClaim, "JWT claim to use for user groups.")

	fss.FlagSet("misc").StringVar(&listenAddr, "listen-addr", listenAddr, "Address to listen on.")
	logsapi.AddFlags(logOptions, fss.FlagSet("logs"))
	verflag.AddFlags(fss.FlagSet("global"))

	fs := cmd.Flags()
	for _, f := range fss.FlagSets {
		fs.AddFlagSet(f)
	}

	cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
	cliflag.SetUsageAndHelpFunc(cmd, fss, cols)

	return cmd
}
