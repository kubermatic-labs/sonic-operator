// SPDX-License-Identifier: Apache-2.0
// Package releasebundle builds offline public, content-addressed publication
// inputs. Review/approval and Kubernetes UID binding belong to the parent.
package releasebundle

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
)

const Format = "host-artifact-v1"

// Floors lists commits that every release build must descend from, for example
// fixes that older agents in the field must not be rolled back below. It is a
// source ancestry floor, not an approval attestation. Empty means only that each
// build commit must exist in the repository.
var Floors = []string{}
var fullCommit = regexp.MustCompile(`^[a-f0-9]{40}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Binary struct {
	releaseinfo.Info
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	GoVersion string `json:"goVersion"`
}
type Release struct {
	Format         string                           `json:"format"`
	ReviewRequired bool                             `json:"reviewRequired"`
	Builds         map[string]Binary                `json:"builds"`
	Fallbacks      []Binary                         `json:"fallbacks"`
	AgentBuilds    map[string]artifact.ReleaseBuild `json:"agentBuilds"`
	SourceFloors   []string                         `json:"sourceFloors"`
}

func ReadBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("release input unavailable")
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > limit {
		return nil, fmt.Errorf("release input outside size bound")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, fmt.Errorf("bounded release input unreadable")
	}
	return b, nil
}

func CheckAncestry(repo, commit string) error {
	if !fullCommit.MatchString(commit) {
		return fmt.Errorf("full source commit required")
	}
	if exec.Command("git", "-C", repo, "cat-file", "-e", commit+"^{commit}").Run() != nil {
		return fmt.Errorf("source commit not in repository")
	}
	for _, floor := range Floors {
		if exec.Command("git", "-C", repo, "merge-base", "--is-ancestor", floor, commit).Run() != nil {
			return fmt.Errorf("source is below integrated ancestry floor")
		}
	}
	return nil
}

func CheckCleanSource(repo string) (string, error) {
	out, err := exec.Command("git", "-C", repo, "status", "--porcelain", "--untracked-files=normal").Output()
	if err != nil || len(out) != 0 {
		return "", fmt.Errorf("clean committed source required")
	}
	out, err = exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("source identity unavailable")
	}
	commit := strings.TrimSpace(string(out))
	return commit, CheckAncestry(repo, commit)
}

func InspectBinary(repo, path, role string) (Binary, error) {
	b, _, err := readInspectedBinary(repo, path, role)
	return b, err
}

// Read once: metadata inspection, release-hash comparison and source chunking
// must all describe this owned buffer, even if a build replaces the input path.
func readInspectedBinary(repo, path, role string) (Binary, []byte, error) {
	raw, err := ReadBounded(path, 96<<20)
	if err != nil {
		return Binary{}, nil, err
	}
	b, err := inspectBinaryBytes(repo, role, raw)
	if err != nil {
		return Binary{}, nil, err
	}
	return b, raw, nil
}

func inspectBinaryBytes(repo, role string, raw []byte) (Binary, error) {
	var result Binary
	pkg := map[string]string{"agent": "/cmd/agent", "supervisor": "/cmd/artifact-supervisor", "watchdog": "/cmd/host-recovery", "controller": "/cmd"}[role]
	if pkg == "" {
		return result, fmt.Errorf("unknown release role")
	}
	image, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return result, fmt.Errorf("release binary must be ELF")
	}
	defer func() { _ = image.Close() }()
	if image.Machine != elf.EM_X86_64 || image.Class != elf.ELFCLASS64 || (image.Type != elf.ET_EXEC && image.Type != elf.ET_DYN) {
		return result, fmt.Errorf("release binary must be Linux amd64")
	}
	b, err := buildinfo.Read(bytes.NewReader(raw))
	if err != nil || b.Path != "github.com/ironcore-dev/sonic-operator"+pkg {
		return result, fmt.Errorf("release binary build provenance unavailable")
	}
	settings := map[string]string{}
	for _, s := range b.Settings {
		settings[s.Key] = s.Value
	}
	if settings["vcs.modified"] != "false" || settings["GOOS"] != "linux" || settings["GOARCH"] != "amd64" || settings["-trimpath"] != "true" {
		return result, fmt.Errorf("release requires clean trimpath Linux build provenance")
	}
	// Do not permit a link-time source override to disagree with VCS provenance.
	if strings.Contains(settings["-ldflags"], "-X") {
		return result, fmt.Errorf("unqualified release link-time override")
	}
	result.Info = releaseinfo.Info{SourceCommit: settings["vcs.revision"], Capabilities: releaseinfo.Current().Capabilities}
	if CheckAncestry(repo, result.SourceCommit) != nil || !bytes.Contains(raw, []byte(releaseinfo.Marker)) || releaseinfo.Validate(result.Info) != nil {
		return result, fmt.Errorf("binary lacks integrated compiled release floor")
	}
	result.SHA256 = artifact.Digest(raw)
	result.Size = int64(len(raw))
	result.GoVersion = b.GoVersion
	return result, nil
}

func NewRelease(repo string, paths map[string]string, fallbackPaths []string) (Release, error) {
	r := Release{Format: Format, ReviewRequired: true, Builds: map[string]Binary{}, AgentBuilds: map[string]artifact.ReleaseBuild{}, Fallbacks: []Binary{}}
	commit, err := CheckCleanSource(repo)
	if err != nil {
		return r, err
	}
	var sizes []int64
	for _, role := range []string{"controller", "agent", "supervisor", "watchdog"} {
		b, err := InspectBinary(repo, paths[role], role)
		if err != nil {
			return r, fmt.Errorf("%s: %w", role, err)
		}
		if b.SourceCommit != commit {
			return r, fmt.Errorf("candidate build is not current committed source")
		}
		r.Builds[role] = b
		if role != "controller" {
			sizes = append(sizes, b.Size)
		}
	}
	if len(fallbackPaths) == 0 || len(fallbackPaths) > 15 {
		return r, fmt.Errorf("explicit accepted fallback binary required")
	}
	r.AgentBuilds[r.Builds["agent"].SHA256] = r.Builds["agent"].Info
	for _, path := range fallbackPaths {
		b, err := InspectBinary(repo, path, "agent")
		if err != nil {
			return r, err
		}
		r.Fallbacks = append(r.Fallbacks, b)
		r.AgentBuilds[b.SHA256] = b.Info
	}
	if err := CheckAggregate(sizes); err != nil {
		return r, err
	}
	r.SourceFloors = []string{}
	for _, floor := range Floors {
		out, err := exec.Command("git", "-C", repo, "rev-parse", floor).Output()
		if err != nil {
			return r, fmt.Errorf("floor identity unavailable")
		}
		r.SourceFloors = append(r.SourceFloors, strings.TrimSpace(string(out)))
	}
	return r, nil
}

func ValidateRelease(r Release) error {
	if r.Format != Format || !r.ReviewRequired || len(r.Builds) != 4 || len(r.Fallbacks) == 0 || len(r.Fallbacks) > 15 || len(r.SourceFloors) != len(Floors) {
		return fmt.Errorf("invalid offline release manifest")
	}
	seenFloors := map[string]bool{}
	for _, s := range r.SourceFloors {
		if !fullCommit.MatchString(s) || seenFloors[s] {
			return fmt.Errorf("invalid release source floor")
		}
		seenFloors[s] = true
	}
	expected := map[string]artifact.ReleaseBuild{}
	commit := ""
	for _, role := range []string{"controller", "agent", "supervisor", "watchdog"} {
		b := r.Builds[role]
		if releaseinfo.Validate(b.Info) != nil || !hashPattern.MatchString(b.SHA256) || b.Size <= 0 || b.Size > 96<<20 || !strings.HasPrefix(b.GoVersion, "go") {
			return fmt.Errorf("invalid release build")
		}
		if commit != "" && commit != b.SourceCommit {
			return fmt.Errorf("mixed candidate source commits")
		}
		commit = b.SourceCommit
	}
	expected[r.Builds["agent"].SHA256] = r.Builds["agent"].Info
	for _, b := range r.Fallbacks {
		if releaseinfo.Validate(b.Info) != nil || !hashPattern.MatchString(b.SHA256) || b.Size <= 0 || b.Size > 96<<20 {
			return fmt.Errorf("invalid fallback build")
		}
		expected[b.SHA256] = b.Info
	}
	if len(expected) != len(r.AgentBuilds) {
		return fmt.Errorf("accepted binary set differs from release")
	}
	for hash, i := range expected {
		if !releaseinfo.Equal(i, r.AgentBuilds[hash]) {
			return fmt.Errorf("accepted binary set differs from release")
		}
	}
	return CheckAggregate([]int64{r.Builds["agent"].Size, r.Builds["supervisor"].Size, r.Builds["watchdog"].Size})
}

func CheckAggregate(sizes []int64) error {
	var total int64
	for _, n := range sizes {
		if n < 0 || n > int64(artifact.MaxBundleBytes)-total {
			return fmt.Errorf("publication exceeds unchanged 128-MiB aggregate")
		}
		total += n
	}
	return nil
}

func JSON(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	return append(b, '\n'), err
}

func WriteAddressed(dir string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	name := filepath.Join(dir, artifact.Digest(data)+".json")
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if os.IsExist(err) {
		old, e := os.ReadFile(name)
		if e == nil && bytes.Equal(old, data) {
			return name, nil
		}
		return "", fmt.Errorf("content-addressed output conflict")
	}
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	return name, closeErr
}
