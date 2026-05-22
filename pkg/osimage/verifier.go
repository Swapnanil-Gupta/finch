// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || windows

package osimage

import (
	"bytes"
	"crypto"
	"encoding/hex"
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
	CosignIssuer = "https://token.actions.githubusercontent.com"
	// TODO: change this to actual values from runfinch/finch-core
	CosignIdentity = "https://github.com/Swapnanil-Gupta/finch-core/.github/workflows/test-keyless-signing.yaml@refs/heads/main"
)

// ManifestVerifier verifies the integrity and authenticity of a manifest.
type ManifestVerifier interface {
	Verify(data, signature []byte) error
}

// TrustedRootProvider abstracts where the Sigstore trusted root comes from.
type TrustedRootProvider interface {
	FetchTrustedRoot() (*root.TrustedRoot, error)
}

// DefaultTrustedRootProvider fetches the trusted root from Sigstore's TUF repository.
type DefaultTrustedRootProvider struct{}

func (DefaultTrustedRootProvider) FetchTrustedRoot() (*root.TrustedRoot, error) {
	return root.FetchTrustedRoot()
}

var DefaultVerifierOptions = []verify.VerifierOption{
	verify.WithSignedCertificateTimestamps(1),
	verify.WithIntegratedTimestamps(1),
	verify.WithSignedTimestamps(1),
	verify.WithTransparencyLog(1),
}

// CosignVerifier verifies manifest signatures using Sigstore/cosign.
type CosignVerifier struct {
	rootProvider    TrustedRootProvider
	issuer          string
	identity        string
	verifierOptions []verify.VerifierOption
}

func NewCosignVerifier(rootProvider TrustedRootProvider, issuer, identity string, opts []verify.VerifierOption) *CosignVerifier {
	return &CosignVerifier{
		rootProvider:    rootProvider,
		issuer:          issuer,
		identity:        identity,
		verifierOptions: opts,
	}
}

func (v *CosignVerifier) Verify(data, bundleBytes []byte) error {
	trustedRoot, err := v.rootProvider.FetchTrustedRoot()
	if err != nil {
		return fmt.Errorf("failed to fetch trusted root: %w", err)
	}

	verifier, err := verify.NewVerifier(trustedRoot, v.verifierOptions...)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	certID, err := verify.NewShortCertificateIdentity(v.issuer, "", v.identity, "")
	if err != nil {
		return fmt.Errorf("failed to create certificate identity: %w", err)
	}

	policy := verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(data)),
		verify.WithCertificateIdentity(certID),
	)

	var sigBundle bundle.Bundle
	if err := sigBundle.UnmarshalJSON(bundleBytes); err != nil {
		return fmt.Errorf("failed to load signature bundle: %w", err)
	}

	if _, err := verifier.Verify(&sigBundle, policy); err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}
	return nil
}

// func verifySignatureWithPublicKey(dataBytes, signatureBytes, pubKeyBytes []byte) error {
// 	hashedData := sha256.Sum256(dataBytes)
// 	pubKey, err := getRsaPublicKeyFromBytes(pubKeyBytes)
// 	if err != nil {
// 		return fmt.Errorf("failed to parse public key: %w", err)
// 	}

// 	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashedData[:], signatureBytes); err != nil {
// 		return fmt.Errorf("failed to verify signature: %w", err)
// 	}
// 	return nil
// }

// TODO: change expectedDigest to byte[]
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

// func getRsaPublicKeyFromBytes(pubKeyBytes []byte) (*rsa.PublicKey, error) {
// 	block, _ := pem.Decode(pubKeyBytes)
// 	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse public key")
// 	}
// 	rsaPub, ok := pub.(*rsa.PublicKey)
// 	if !ok {
// 		return nil, fmt.Errorf("failed to parse public key")
// 	}
// 	return rsaPub, nil
// }
