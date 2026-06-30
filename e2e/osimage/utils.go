// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || windows

package osimage

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/onsi/gomega"

	"github.com/runfinch/finch/e2e"
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
