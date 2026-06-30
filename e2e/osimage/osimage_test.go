// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || windows

// Package osimage runs e2e tests for OS image management commands.
// These tests do not require the VM to be running.
package osimage

import (
	"os"
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/runfinch/finch/e2e"
	"github.com/runfinch/finch/pkg/osimage"
)

// newImageRunID is the GitHub Actions run ID embedded in the file name of the image the
// local test server advertises. It must be numerically larger than the run ID of the image
// currently referenced in the base finch.yaml so the updater treats it as newer.
const newImageRunID = "99999999999"

// depsServer is the local server standing in for deps.runfinch.com. It is started once for
// the whole suite so every "os-image update" invocation downloads the same deterministic,
// locally signed image instead of depending on a newer image being staged remotely.
var depsServer *localDepsServer

//nolint:paralleltest // TestOSImage is like TestMain for the os-image tests.
func TestOSImage(t *testing.T) {
	const description = "Finch OS Image E2E Tests"

	o, err := e2e.CreateOption()
	if err != nil {
		t.Fatal(err)
	}

	ginkgo.Describe("", ginkgo.Ordered, ginkgo.Serial, func() {
		ginkgo.BeforeAll(func() {
			requireCosign()

			// Keyless signing needs an ambient OIDC token. Without one, cosign would block on
			// an interactive login that "go test" cannot drive, so skip rather than hang. The
			// signed round-trip runs in CI where id-token: write provides the token.
			requireAmbientOIDC()

			signDir, err := os.MkdirTemp("", "finch-osimage-e2e")
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			ginkgo.DeferCleanup(func() {
				os.RemoveAll(signDir)
				if depsServer != nil {
					depsServer.Close()
				}
			})

			depsServer = startLocalDepsServer(signDir, newImageRunID)

			// Point the binary's updater at the local server and configure its verifier to
			// trust exactly the identity that signed the locally generated manifest. These
			// runtime overrides are honored only when the binary under test is built with
			// FINCH_OSIMAGE_ALLOW_ENV_OVERRIDES=true (see the test-e2e-osimage Makefile target).
			o.UpdateEnv(osimage.EnvDepsURL, depsServer.BaseURL)
			o.UpdateEnv(osimage.EnvCosignIssuer, depsServer.CosignIssuer)
			o.UpdateEnv(osimage.EnvCosignIdentity, depsServer.CosignIdentity)
		})

		testOSImageList(o)
		testOSImageUpdate(o)
		testOSImageRollback(o)
	})

	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, description)
}
