// Copyright (c) 2025 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Proxy Suite")
}
