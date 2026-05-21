// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || windows

package osimage

import (
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyDigest(t *testing.T) {
	t.Parallel()

	t.Run("valid digest passes", func(t *testing.T) {
		t.Parallel()
		data := "hello world"
		// SHA-256 of "hello world"
		expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
		err := verifyDigest(strings.NewReader(data), expected, crypto.SHA256)
		assert.NoError(t, err)
	})

	t.Run("invalid digest fails", func(t *testing.T) {
		t.Parallel()
		data := "hello world"
		err := verifyDigest(strings.NewReader(data), "wrongdigest", crypto.SHA256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "digest mismatch")
	})
}

func TestVerifyManifestExpiry(t *testing.T) {
	t.Parallel()

	t.Run("non-expired manifest passes", func(t *testing.T) {
		t.Parallel()
		manifest := &Manifest{ExpiresAt: time.Now().Add(24 * time.Hour)}
		err := verifyManifestExpiry(manifest)
		assert.NoError(t, err)
	})

	t.Run("expired manifest fails", func(t *testing.T) {
		t.Parallel()
		manifest := &Manifest{ExpiresAt: time.Now().Add(-1 * time.Hour)}
		err := verifyManifestExpiry(manifest)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})
}

func TestVerifyImageIsNewer(t *testing.T) {
	t.Parallel()

	t.Run("newer image returns true", func(t *testing.T) {
		t.Parallel()
		isNewer, err := verifyImageIsNewer(
			"finch-al2023-os-image-arm64-25872286438.qcow2",
			"finch-al2023-os-image-arm64-24789639918.qcow2",
		)
		require.NoError(t, err)
		assert.True(t, isNewer)
	})

	t.Run("older image returns false", func(t *testing.T) {
		t.Parallel()
		isNewer, err := verifyImageIsNewer(
			"finch-al2023-os-image-arm64-24789639918.qcow2",
			"finch-al2023-os-image-arm64-25872286438.qcow2",
		)
		require.NoError(t, err)
		assert.False(t, isNewer)
	})

	t.Run("same image returns false", func(t *testing.T) {
		t.Parallel()
		isNewer, err := verifyImageIsNewer(
			"finch-al2023-os-image-arm64-24789639918.qcow2",
			"finch-al2023-os-image-arm64-24789639918.qcow2",
		)
		require.NoError(t, err)
		assert.False(t, isNewer)
	})
}

func TestExtractGHRunID(t *testing.T) {
	t.Parallel()

	t.Run("extracts run ID from valid filename", func(t *testing.T) {
		t.Parallel()
		runID, err := extractGHRunID("finch-al2023-os-image-arm64-24789639918.qcow2")
		require.NoError(t, err)
		assert.Equal(t, int64(24789639918), runID)
	})

	t.Run("returns error for non-numeric run ID", func(t *testing.T) {
		t.Parallel()
		_, err := extractGHRunID("finch-al2023-os-image-arm64-notanumber.qcow2")
		assert.Error(t, err)
	})
}
