// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || windows

package osimage

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/runfinch/finch/pkg/flog"
	finchPath "github.com/runfinch/finch/pkg/path"
)

type Manifest struct {
	PublishedAt time.Time           `json:"published_at"`
	ExpiresAt   time.Time           `json:"expires_at"`
	Artifacts   []*ManifestArtifact `json:"artifacts"`
}

type ManifestArtifact struct {
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
	URL      string `json:"url"`
	Digest   string `json:"digest"`
	Size     int64  `json:"size"`
}

type FinchYAML struct {
	Images []*OSImage `yaml:"images"`
}

type OSImage struct {
	Location string `yaml:"location"`
	Arch     string `yaml:"arch"`
	Digest   string `yaml:"digest"`
}

type CheckUpdateResult struct {
	Available     bool
	CurrentImage  string
	CurrentDigest string
	NewImage      string
	Artifact      *ManifestArtifact
}

const (
	manifestFileName       = "manifest.json"
	manifestBundleFileName = "manifest.json.bundle"
	// manifestSignatureFileName    = "manifest.json.sig"
)

// DepsURLs holds the URLs for downloading OS image manifest and signature.
// The artifact URLs are part of the manifest.
type DepsURLs struct {
	ManifestURL       string
	ManifestBundleURL string
}

// Overridable via ldflags at build time for staging/testing.
var (
	depsManifestURL       = "https://deps.runfinch.com/" + manifestFileName
	depsManifestBundleURL = "https://deps.runfinch.com/" + manifestBundleFileName
)

func GetDefaultDepsURLs() DepsURLs {
	return DepsURLs{
		ManifestURL:       depsManifestURL,
		ManifestBundleURL: depsManifestBundleURL,
	}
}

func CheckForUpdate(logger flog.Logger, fp finchPath.Finch, urls DepsURLs, verifier ManifestVerifier) (*CheckUpdateResult, error) {
	manifest, err := fetchManifest(logger, urls, verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}

	artifact, err := findMatchingArtifact(manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to find matching OS image artifact: %w", err)
	}

	logger.Info("Checking current config...")
	currentImage, err := GetCurrentImage(fp)
	if err != nil {
		return nil, fmt.Errorf("failed to get current os image")
	}
	currentImageName := path.Base(currentImage.Location)

	newImageName := path.Base(artifact.URL)
	isNewer, err := verifyImageIsNewer(newImageName, currentImageName)
	if err != nil {
		return nil, fmt.Errorf("failed to validate if new OS image is newer: %w", err)
	}
	return &CheckUpdateResult{
		Available:     isNewer,
		CurrentImage:  currentImageName,
		CurrentDigest: currentImage.Digest,
		NewImage:      newImageName,
		Artifact:      artifact,
	}, nil
}

func Update(logger flog.Logger, fp finchPath.Finch, result *CheckUpdateResult) error {
	if !result.Available {
		return nil
	}

	artifact := result.Artifact
	osImageDir := fp.OSImageDir()
	newImagePath := filepath.Join(osImageDir, result.NewImage)

	// TODO: maybe skip download if the file already exists?
	if err := downloadToFile(
		artifact.URL,
		newImagePath,
		withProgressBar("Downloading new OS image..."),
	); err != nil {
		return fmt.Errorf("failed to download OS image artifact: %w", err)
	}

	logger.Info("Verifying downloaded OS image...")
	newImageFile, err := os.Open(newImagePath)
	if err != nil {
		return fmt.Errorf("failed to read downloaded OS image: %w", err)
	}
	defer newImageFile.Close()
	if err := verifyDigest(newImageFile, strings.TrimPrefix(artifact.Digest, "sha512:"), crypto.SHA512); err != nil {
		newImageFile.Close()
		os.Remove(newImagePath)
		return fmt.Errorf("failed to verify downloaded OS image: %w", err)
	}

	logger.Info("Updating current config with new OS image...")
	if err := ApplyImage(fp.BaseYamlFilePath(), newImagePath, artifact.Digest); err != nil {
		return err
	}
	return nil
}

func fetchManifest(logger flog.Logger, urls DepsURLs, verifier ManifestVerifier) (*Manifest, error) {
	logger.Info("Fetching manifest...")
	var manifestBuf bytes.Buffer
	if err := download(urls.ManifestURL, &manifestBuf); err != nil {
		return nil, fmt.Errorf("failed to download manifest: %w", err)
	}
	manifestBytes := manifestBuf.Bytes()
	// TODO: remove local read
	// signDir := "/Users/swpnlg/Projects/finch/signing"
	// manifestBytes, err := os.ReadFile(filepath.Join(signDir, manifestFileName))
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to read manifest: %w", err)
	// }

	logger.Info("Validating manifest...")
	var manifestBundleBuf bytes.Buffer
	if err := download(urls.ManifestBundleURL, &manifestBundleBuf); err != nil {
		return nil, fmt.Errorf("failed to download manifest bundle: %w", err)
	}
	manifestBundleBytes := manifestBundleBuf.Bytes()
	// TODO: remove local read
	// manifestSignBytes, err := os.ReadFile(filepath.Join(signDir, manifestSignatureFileName))
	// manifestSignBundleBytes, err := os.ReadFile(filepath.Join(signDir, manifestBundleFileName))
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to read manifest signature: %w", err)
	// }

	// TODO: Decide b/w asymmetric key vs cosign signature verification
	// TODO: remove hardcoded path public key path
	// pubKeyBytes, err := os.ReadFile(filepath.Join(signDir, "pubkey.pem"))
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to read public key for signature validation: %w", err)
	// }
	// if err := verifySignatureWithPublicKey(manifestBytes, manifestSignBytes, pubKeyBytes); err != nil {
	// 	return nil, fmt.Errorf("manifest signature validation failed: %w", err)
	// }
	if err := verifier.Verify(manifestBytes, manifestBundleBytes); err != nil {
		return nil, fmt.Errorf("manifest signature validation failed: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}
	if err := verifyManifestExpiry(&manifest); err != nil {
		return nil, fmt.Errorf("manifest validation failed: %w", err)
	}
	return &manifest, nil
}

func findMatchingArtifact(manifest *Manifest) (*ManifestArtifact, error) {
	for _, artifact := range manifest.Artifacts {
		if artifact.Platform == runtime.GOOS && artifact.Arch == runtime.GOARCH {
			return artifact, nil
		}
	}
	return nil, fmt.Errorf("no matching OS image artifact found for platform %s and arch %s", runtime.GOOS, runtime.GOARCH)
}

func GetCurrentImage(fp finchPath.Finch) (*OSImage, error) {
	finchYAML, err := readBaseFinchYaml(fp)
	if err != nil {
		return nil, err
	}
	if len(finchYAML.Images) == 0 {
		return nil, fmt.Errorf("no OS image found in finch.yaml")
	}
	return finchYAML.Images[0], nil
}

func readBaseFinchYaml(fp finchPath.Finch) (*FinchYAML, error) {
	finchYamlPath := fp.BaseYamlFilePath()
	finchYamlBytes, err := os.ReadFile(finchYamlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read finch.yaml: %w", err)
	}
	var finchYAML FinchYAML
	if err := yaml.Unmarshal(finchYamlBytes, &finchYAML); err != nil {
		return nil, fmt.Errorf("failed to unmarshal finch.yaml: %w", err)
	}
	return &finchYAML, nil
}
