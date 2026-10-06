// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var bufferNamePattern = regexp.MustCompile(`^[A-Za-z0-9][-A-Za-z0-9_]{0,31}$`)

// BufferRange parses a canonical selector within a schema ceiling, not a hardware limit.
func BufferRange(value string, max uint64) (uint64, uint64, error) {
	loText, hiText, ranged := strings.Cut(value, "-")
	if !ranged {
		hiText = loText
	}
	lo, e1 := strconv.ParseUint(loText, 10, 64)
	hi, e2 := strconv.ParseUint(hiText, 10, 64)
	if e1 != nil || e2 != nil || lo > max || hi > max || strconv.FormatUint(lo, 10) != loText || strconv.FormatUint(hi, 10) != hiText || lo > hi || (ranged && lo == hi) {
		return 0, 0, fmt.Errorf("invalid canonical buffer range")
	}
	return lo, hi, nil
}

// ValidateBufferSpec mirrors admission validation for controllers and strict agent RPC decoding.
// Dependency direction, available memory and actual hardware bounds require native checks.
func ValidateBufferSpec(spec any) (string, error) {
	name := func(n BufferName) bool { return bufferNamePattern.MatchString(string(n)) }
	bytes := func(values ...*uint64) bool {
		for _, v := range values {
			if v != nil && *v > math.MaxInt64 {
				return false
			}
		}
		return true
	}
	binding := func(port, selector string, profile BufferName, max uint64) (string, error) {
		n, err := strconv.ParseUint(strings.TrimPrefix(port, "Ethernet"), 10, 32)
		if err != nil || port != "Ethernet"+strconv.FormatUint(n, 10) || !name(profile) {
			return "", fmt.Errorf("invalid buffer port or profile")
		}
		if _, _, err := BufferRange(selector, max); err != nil {
			return "", err
		}
		return port + "/" + selector, nil
	}
	switch s := spec.(type) {
	case *SwitchBufferPoolSpec:
		if !name(s.Name) || (s.Type != "ingress" && s.Type != "egress") || (s.Mode != "static" && s.Mode != "dynamic") || s.Size == nil || *s.Size == 0 || !bytes(s.Size, s.Xoff) {
			return "", fmt.Errorf("invalid buffer pool")
		}
		if s.Xoff != nil && (s.Type != "ingress" || *s.Xoff > *s.Size) {
			return "", fmt.Errorf("shared headroom requires ingress pool and cannot exceed size")
		}
		return string(s.Name), nil
	case *SwitchBufferProfileSpec:
		if !name(s.Name) || !name(s.Pool) || s.Size == nil || !bytes(s.Size, s.StaticThreshold, s.Xon, s.Xoff, s.XonOffset) || (s.DynamicThreshold == nil) == (s.StaticThreshold == nil) {
			return "", fmt.Errorf("profile requires pool, size and exactly one threshold")
		}
		if s.DynamicThreshold != nil && (*s.DynamicThreshold < -8 || *s.DynamicThreshold > 7) {
			return "", fmt.Errorf("dynamic threshold must be -8..7")
		}
		return string(s.Name), nil
	case *SwitchBufferPGSpec:
		return binding(s.InterfaceName, s.Range, s.Profile, 7)
	case *SwitchBufferQueueSpec:
		return binding(s.InterfaceName, s.Range, s.Profile, 255)
	default:
		return "", fmt.Errorf("unsupported buffer spec")
	}
}
