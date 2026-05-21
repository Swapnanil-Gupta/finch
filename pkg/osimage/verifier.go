// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || windows

package osimage

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	issuer   = "https://token.actions.githubusercontent.com"
	identity = "https://github.com/Swapnanil-Gupta/finch-core/.github/workflows/test-keyless-signing.yaml@refs/heads/main"
)

func verifySignatureWithCosign(dataBytes, signatureBytes []byte) error {
	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return fmt.Errorf("failed to fetch trusted root: %w\n", err)
	}

	verifier, err := verify.NewVerifier(trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithIntegratedTimestamps(1),
		verify.WithSignedTimestamps(1),
		verify.WithTransparencyLog(1),
	)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w\n", err)
	}

	certID, err := verify.NewShortCertificateIdentity(issuer, "", identity, "")
	if err != nil {
		return fmt.Errorf("failed to create certificate identity: %w\n", err)
	}

	policy := verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(dataBytes)),
		verify.WithCertificateIdentity(certID),
	)

	var sigBundle bundle.Bundle
	err = sigBundle.UnmarshalJSON(signatureBytes)
	if err != nil {
		return fmt.Errorf("failed to load signature bundle: %w\n", err)
	}

	_, err = verifier.Verify(&sigBundle, policy)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w\n", err)
	}
	return nil
}

func verifySignatureWithPublicKey(dataBytes, signatureBytes, pubKeyBytes []byte) error {
	hashedData := sha256.Sum256(dataBytes)
	pubKey, err := getRsaPublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashedData[:], signatureBytes); err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}
	return nil
}

func verifyDigest(reader io.Reader, expectedDigest string, hash crypto.Hash) error {
	hasher := hash.New()
	if _, err := io.Copy(hasher, reader); err != nil {
		return fmt.Errorf("failed to read data for digest verification: %w", err)
	}

	computedDigest := hex.EncodeToString(hasher.Sum(nil))
	if computedDigest != expectedDigest {
		return fmt.Errorf("digest mismatch: expected %s, got %s", expectedDigest, computedDigest)
	}
	return nil
}

func verifyManifestExpiry(manifest *Manifest) error {
	if time.Now().After(manifest.ExpiresAt) {
		return fmt.Errorf("the downloaded manifest has expired")
	}
	return nil
}

func verifyImageIsNewer(newImage, currentImage string) (bool, error) {
	currentRunID, err := extractGHRunID(filepath.Base(currentImage))
	if err != nil {
		return false, fmt.Errorf("failed to extract run ID from current image: %w", err)
	}
	newRunID, err := extractGHRunID(filepath.Base(newImage))
	if err != nil {
		return false, fmt.Errorf("failed to extract run ID from new image: %w", err)
	}
	return newRunID > currentRunID, nil
}

// TODO: move to utils
func extractGHRunID(filename string) (int64, error) {
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	parts := strings.Split(name, "-")
	if len(parts) == 0 {
		return 0, fmt.Errorf("invalid image filename: %s", filename)
	}
	runID, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse run ID from filename %s: %w", filename, err)
	}
	return runID, nil
}

func getRsaPublicKeyFromBytes(pubKeyBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubKeyBytes)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key")
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to parse public key")
	}
	return rsaPub, nil
}
