// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || windows

// Package osimage runs e2e tests for OS image management commands.
// These tests do not require the VM to be running.
package osimage

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/runfinch/finch/e2e"
)

// TODO: These tests expect a new os image update to available and therefore must only be run
// when a new manifest (and os image) is available in the staging environment.
//
//nolint:paralleltest // TestOSImage is like TestMain for the os-image tests.
func TestOSImage(t *testing.T) {
	const description = "Finch OS Image E2E Tests"

	o, err := e2e.CreateOption()
	if err != nil {
		t.Fatal(err)
	}

	ginkgo.Describe("", func() {
		testOSImageList(o)
		testOSImageUpdate(o)
		testOSImageRollback(o)
	})

	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, description)
}
