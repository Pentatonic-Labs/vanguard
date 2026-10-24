package ngc

import "testing"

const dockerImagesDigests = `REPOSITORY                          TAG         DIGEST                                                                    IMAGE ID       CREATED         SIZE
nvcr.io/nvidia/tritonserver         24.08-py3   sha256:244fd47e07d1004f0aed9c1f4e1f2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a   abc123def456   2 weeks ago     8.5GB
nvcr.io/nvidia/pytorch              24.08-py3   sha256:1111111111111111111111111111111111111111111111111111111111111111   abc123def457   2 weeks ago     6.1GB
ubuntu                              22.04       <none>                                                                    abc123def458   3 weeks ago     77MB
<none>                              <none>      <none>                                                                    abc123def459   3 weeks ago     1GB
`

func TestParseDockerImages(t *testing.T) {
	images := ParseDockerImages(dockerImagesDigests)
	if got, want := len(images), 3; got != want {
		t.Fatalf("len(images) = %d, want %d (dangling <none> row must be skipped)", got, want)
	}

	first := images[0]
	if first.Name != "nvcr.io/nvidia/tritonserver" {
		t.Errorf("Name = %q, want %q", first.Name, "nvcr.io/nvidia/tritonserver")
	}
	if first.Tag != "24.08-py3" {
		t.Errorf("Tag = %q, want %q", first.Tag, "24.08-py3")
	}
	const digest = "sha256:244fd47e07d1004f0aed9c1f4e1f2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a"
	if first.Digest != digest {
		t.Errorf("Digest = %q, want %q", first.Digest, digest)
	}
	if want := "pkg:docker/nvidia/tritonserver@" + digest; first.Purl != want {
		t.Errorf("Purl = %q, want %q", first.Purl, want)
	}

	if want := "pkg:docker/nvidia/pytorch@sha256:1111111111111111111111111111111111111111111111111111111111111111"; images[1].Purl != want {
		t.Errorf("images[1].Purl = %q, want %q", images[1].Purl, want)
	}

	// No digest: the purl must fall back to the tag.
	if want := "pkg:docker/ubuntu@22.04"; images[2].Purl != want {
		t.Errorf("images[2].Purl = %q, want %q", images[2].Purl, want)
	}
}

func TestParseDockerImagesHeaderOnly(t *testing.T) {
	const header = "REPOSITORY   TAG   DIGEST   IMAGE ID   CREATED   SIZE\n"
	if got := ParseDockerImages(header); len(got) != 0 {
		t.Fatalf("got %d images, want 0", len(got))
	}
}

const crictlImages = `IMAGE                                    TAG                 IMAGE ID            SIZE
nvcr.io/nvidia/tritonserver              24.08-py3           abc123def456        8.5GB
`

func TestParseCrictlImages(t *testing.T) {
	images := ParseCrictlImages(crictlImages)
	if len(images) != 1 {
		t.Fatalf("len(images) = %d, want 1", len(images))
	}
	if got, want := images[0].Name, "nvcr.io/nvidia/tritonserver"; got != want {
		t.Errorf("Name = %q, want %q", got, want)
	}
	if got, want := images[0].Purl, "pkg:docker/nvidia/tritonserver@24.08-py3"; got != want {
		t.Errorf("Purl = %q, want %q", got, want)
	}
}

func TestImagePurl(t *testing.T) {
	cases := []struct {
		name, tag, digest, want string
	}{
		{"nvcr.io/nvidia/tritonserver", "24.08-py3", "sha256:abc", "pkg:docker/nvidia/tritonserver@sha256:abc"},
		{"nvidia/tritonserver", "24.08-py3", "<none>", "pkg:docker/nvidia/tritonserver@24.08-py3"},
		{"ubuntu", "22.04", "", "pkg:docker/ubuntu@22.04"},
		{"registry.example.com:5000/team/app", "v1", "sha256:def", "pkg:docker/team/app@sha256:def"},
	}
	for _, c := range cases {
		if got := ImagePurl(c.name, c.tag, c.digest); got != c.want {
			t.Errorf("ImagePurl(%q, %q, %q) = %q, want %q", c.name, c.tag, c.digest, got, c.want)
		}
	}
}

func TestParseTritonVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"tritonserver version: 2.45.0\n", "2.45.0"},
		{"2.45.0\n", "2.45.0"},
		{"Triton Inference Server 24.08\n", "24.08"},
		{"no version here\n", ""},
	}
	for _, c := range cases {
		if got := ParseTritonVersion(c.in); got != c.want {
			t.Errorf("ParseTritonVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTritonVersionFromTag(t *testing.T) {
	cases := map[string]string{
		"24.08-py3":  "24.08",
		"2.45.0-py3": "2.45.0",
		"24.08":      "24.08",
		"":           "",
	}
	for tag, want := range cases {
		if got := TritonVersionFromTag(tag); got != want {
			t.Errorf("TritonVersionFromTag(%q) = %q, want %q", tag, got, want)
		}
	}
}
