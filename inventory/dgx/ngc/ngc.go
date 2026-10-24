// Package ngc inventories NGC container images and Triton/Inference Server
// versions on a DGX host.
package ngc

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Image describes a container image discovered on the host.
type Image struct {
	Name   string // repository reference as reported, e.g. "nvcr.io/nvidia/tritonserver"
	Tag    string // image tag, e.g. "24.08-py3"
	Digest string // content digest, e.g. "sha256:..." (empty if unavailable)
	Purl   string // package URL, e.g. "pkg:docker/nvidia/tritonserver@sha256:..."
}

var errNoRuntime = errors.New("no container runtime available")

// registryHost reports whether the first path segment of repo is a registry
// host (contains a "." or a ":"), e.g. "nvcr.io/nvidia/tritonserver" -> true.
func registryHost(repo string) bool {
	first := repo
	if i := strings.IndexByte(repo, '/'); i >= 0 {
		first = repo[:i]
	}
	return strings.ContainsAny(first, ".:")
}

// imageName strips a leading registry host from a repository reference so the
// result is usable as a purl name, e.g. "nvcr.io/nvidia/tritonserver" ->
// "nvidia/tritonserver".
func imageName(repo string) string {
	if !registryHost(repo) {
		return repo
	}
	if i := strings.IndexByte(repo, '/'); i >= 0 {
		return repo[i+1:]
	}
	return repo
}

// escapePurl percent-encodes the characters that would otherwise break a purl
// name or version segment.
func escapePurl(s string) string {
	return strings.NewReplacer("%", "%25", "@", "%40", " ", "%20", "#", "%23", "?", "%3F").Replace(s)
}

// ImagePurl builds a pkg:docker/... purl for an image. The version is the
// digest when available, otherwise the tag.
func ImagePurl(name, tag, digest string) string {
	version := digest
	if version == "" || version == "<none>" {
		version = tag
	}
	return "pkg:docker/" + escapePurl(imageName(name)) + "@" + escapePurl(version)
}

// ParseDockerImages parses the output of `docker images --digests`. The same
// layout (REPOSITORY, TAG, DIGEST, ...) is used by nerdctl. Header rows and
// dangling <none> images are skipped.
func ParseDockerImages(out string) []Image {
	var images []Image
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "REPOSITORY") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		name, tag, digest := fields[0], fields[1], fields[2]
		if name == "<none>" {
			continue
		}
		images = append(images, Image{
			Name:   name,
			Tag:    tag,
			Digest: digest,
			Purl:   ImagePurl(name, tag, digest),
		})
	}
	return images
}

// ParseCrictlImages parses `crictl images` output. crictl reports no digest
// column, so the purl falls back to the tag.
func ParseCrictlImages(out string) []Image {
	var images []Image
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "IMAGE") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name, tag := fields[0], fields[1]
		if name == "<none>" {
			continue
		}
		images = append(images, Image{
			Name: name,
			Tag:  tag,
			Purl: ImagePurl(name, tag, ""),
		})
	}
	return images
}

// Collect discovers images from whichever container runtimes are present,
// trying docker, nerdctl and crictl in turn and de-duplicating by purl.
func Collect() ([]Image, error) {
	runtimes := []struct {
		cmd   string
		args  []string
		parse func(string) []Image
	}{
		{"docker", []string{"images", "--digests"}, ParseDockerImages},
		{"nerdctl", []string{"images", "--digests"}, ParseDockerImages},
		{"crictl", []string{"images"}, ParseCrictlImages},
	}

	seen := make(map[string]bool)
	var images []Image
	ran := false
	for _, rt := range runtimes {
		stdout, err := runStdout(rt.cmd, rt.args...)
		if err != nil {
			continue // runtime not installed or not usable
		}
		ran = true
		for _, img := range rt.parse(stdout) {
			if seen[img.Purl] {
				continue
			}
			seen[img.Purl] = true
			images = append(images, img)
		}
	}
	if !ran {
		return nil, errNoRuntime
	}
	return images, nil
}

var versionRE = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)

// ParseTritonVersion extracts the Triton/Inference Server version from the
// output of `tritonserver --version`. It returns "" when no version is found.
func ParseTritonVersion(out string) string {
	return versionRE.FindString(out)
}

// TritonVersionFromTag derives the Triton release from an NGC image tag, e.g.
// "24.08-py3" -> "24.08" and "2.45.0-py3" -> "2.45.0".
func TritonVersionFromTag(tag string) string {
	if i := strings.IndexByte(tag, '-'); i >= 0 {
		return tag[:i]
	}
	return tag
}

// DetectTritonVersion runs `tritonserver --version` and parses its output.
func DetectTritonVersion() (string, error) {
	out, err := runCombined("tritonserver", "--version")
	if err != nil {
		return "", err
	}
	v := ParseTritonVersion(out)
	if v == "" {
		return "", fmt.Errorf("no version found in tritonserver output")
	}
	return v, nil
}

// runStdout runs name and returns its standard output.
func runStdout(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

// runCombined runs name and returns stdout and stderr together.
func runCombined(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}
