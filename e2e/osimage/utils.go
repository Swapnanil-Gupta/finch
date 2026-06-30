// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || windows

package osimage

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/runfinch/finch/e2e"
	"github.com/runfinch/finch/pkg/osimage"
)

const (
	// manifestFileName and manifestBundleFileName mirror the constants the updater uses to
	// derive download paths from the deps base URL.
	manifestFileName       = "manifest.json"
	manifestBundleFileName = "manifest.json.bundle"
)

func getE2EFinchRoot() string {
	if *e2e.Installed {
		path, err := exec.LookPath(e2e.InstalledTestSubject)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		realPath, err := filepath.EvalSymlinks(path)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		return filepath.Join(realPath, "..", "..")
	}
	return filepath.Join("..", "..", "_output")
}

func getOSImageDir() string {
	return filepath.Join(getE2EFinchRoot(), "os")
}

func getBaseYamlFilePath() string {
	return filepath.Join(getE2EFinchRoot(), "os", "finch.yaml")
}

func getFinchDir() string {
	home, err := os.UserHomeDir()
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	return filepath.Join(home, ".finch")
}

func getMetadataFilePath() string {
	return filepath.Join(getFinchDir(), "os-image-metadata.json")
}

func getFinchConfigFilePath() string {
	return filepath.Join(getFinchDir(), "finch.yaml")
}

// requireCosign fails the calling spec when the cosign CLI is not available on PATH.
// The local-server e2e fixture signs its manifest with cosign keyless signing, so the
// tests cannot run deterministically without it.
func requireCosign() {
	if _, err := exec.LookPath("cosign"); err != nil {
		ginkgo.Skip("cosign not found on PATH; it is required for os-image e2e tests")
	}
}

// hasAmbientOIDC reports whether an ambient OIDC token is available for non-interactive
// cosign keyless signing. Without one (e.g. on a developer laptop) cosign falls back to an
// interactive browser/device flow that cannot complete under "go test", so the signed
// update specs are skipped. In CI with "id-token: write", ACTIONS_ID_TOKEN_REQUEST_URL is
// set and signing proceeds without interaction.
func requireAmbientOIDC() {
	if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") == "" && os.Getenv("SIGSTORE_ID_TOKEN") == "" {
		ginkgo.Skip("no ambient OIDC token available for cosign keyless signing; " +
			"skipping os-image e2e (runs in CI with id-token: write)")
	}
}

// localDepsServer is a local HTTP server that serves an OS image manifest, its signature
// bundle, and the image artifact itself, standing in for deps.runfinch.com so the tests
// do not depend on a newer image being staged remotely.
type localDepsServer struct {
	server *httptest.Server
	// NewImageName is the file name of the artifact served by this server.
	NewImageName string
	// NewImageDigest is the "sha512:"-prefixed digest of the served artifact.
	NewImageDigest string
	// BaseURL is the value to pass to the binary via FINCH_DEPS_URL.
	BaseURL string
	// CosignIssuer and CosignIdentity are extracted from the signing certificate so the
	// binary's verifier can be configured to trust exactly the identity that signed the
	// manifest.
	CosignIssuer   string
	CosignIdentity string
}

// Close shuts down the underlying HTTP server.
func (s *localDepsServer) Close() {
	if s.server != nil {
		s.server.Close()
	}
}

// startLocalDepsServer builds a manifest advertising a new image with the given run ID,
// signs it with cosign keyless signing, extracts the signing identity, and serves the
// manifest, bundle, and artifact from a local HTTP server. The run ID must be numerically
// greater than the run ID embedded in the current image so the updater considers it newer.
func startLocalDepsServer(tmpDir, newRunID string) *localDepsServer {
	imageContent := []byte("finch-e2e-os-image-" + newRunID)
	hash := sha512.Sum512(imageContent)
	digest := "sha512:" + hex.EncodeToString(hash[:])
	newImageName := fmt.Sprintf("finch-al2023-os-image-%s-%s.qcow2", runtime.GOARCH, newRunID)

	// The artifact URL is embedded in the signed manifest, so the manifest cannot be signed
	// until the server URL is known. httptest assigns a random port, so capture the URL via a
	// closure and sign after the server is listening but before any request is served.
	var serverURL string
	manifestHolder := &struct{ bytes, bundle []byte }{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + manifestFileName:
			_, _ = w.Write(manifestHolder.bytes)
		case "/" + manifestBundleFileName:
			_, _ = w.Write(manifestHolder.bundle)
		default:
			_, _ = w.Write(imageContent)
		}
	}))
	serverURL = server.URL

	manifest := osimage.Manifest{
		PublishedAt: time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Artifacts: []*osimage.ManifestArtifact{
			{
				Platform: runtime.GOOS,
				Arch:     runtime.GOARCH,
				URL:      serverURL + "/" + newImageName,
				Digest:   digest,
				Size:     int64(len(imageContent)),
			},
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	bundleBytes, issuer, identity := signManifest(tmpDir, manifestBytes)

	manifestHolder.bytes = manifestBytes
	manifestHolder.bundle = bundleBytes

	return &localDepsServer{
		server:         server,
		NewImageName:   newImageName,
		NewImageDigest: digest,
		BaseURL:        serverURL,
		CosignIssuer:   issuer,
		CosignIdentity: identity,
	}
}

// signManifest writes the manifest to a temp file, signs it with cosign keyless signing
// using the new bundle format, and returns the bundle bytes along with the issuer and
// identity extracted from the signing certificate.
func signManifest(tmpDir string, manifestBytes []byte) (bundleBytes []byte, issuer, identity string) {
	manifestPath := filepath.Join(tmpDir, manifestFileName)
	bundlePath := filepath.Join(tmpDir, manifestBundleFileName)
	gomega.Expect(os.WriteFile(manifestPath, manifestBytes, 0o644)).ShouldNot(gomega.HaveOccurred())

	// --yes skips the interactive confirmation; --new-bundle-format produces a bundle that
	// sigstore-go's bundle.UnmarshalJSON (used by the binary's verifier) can parse.
	cmd := exec.Command("cosign", "sign-blob", //nolint:gosec // args are test-controlled
		"--yes",
		"--bundle", bundlePath,
		manifestPath,
	)
	cmd.Stderr = os.Stderr
	gomega.Expect(cmd.Run()).ShouldNot(gomega.HaveOccurred(), "cosign sign-blob failed")

	bundleBytes, err := os.ReadFile(bundlePath)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	issuer, identity = extractCosignIdentity(bundleBytes)
	return bundleBytes, issuer, identity
}

// extractCosignIdentity parses a signature bundle and returns the OIDC issuer and the
// subject alternative name (identity) from the signing certificate. These are fed to the
// binary so its verifier trusts exactly the identity that produced the signature.
func extractCosignIdentity(bundleBytes []byte) (issuer, identity string) {
	var b bundle.Bundle
	gomega.Expect(b.UnmarshalJSON(bundleBytes)).ShouldNot(gomega.HaveOccurred())

	content, err := b.VerificationContent()
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	cert := content.Certificate()
	gomega.Expect(cert).ShouldNot(gomega.BeNil(), "bundle has no signing certificate")

	summary, err := certificate.SummarizeCertificate(cert)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	return summary.Extensions.Issuer, summary.SubjectAlternativeName
}
