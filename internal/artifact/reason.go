// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// MaxReasonBytes bounds failure reasons passed between supervisor, agent and
// controller.
const MaxReasonBytes = 200

// Artifact errors are fixed texts by design: command output, artifact bytes and
// Secret values are never formatted into them. Reasons are still filtered so a
// future error that wraps foreign text cannot leak it across the boundary.
var safeReasonPattern = regexp.MustCompile(`^[a-zA-Z0-9 ,;:/._()+=-]+$`)

var sensitiveReasonWords = []string{"begin", "private", "password", "secret", "community", "credential", "key="}

// Long hex runs are confirmation tokens, digests or key material.
var hexRunPattern = regexp.MustCompile(`[a-fA-F0-9]{24,}`)

// SafeReason returns a bounded, non-secret description of err for logs and
// status, or "unclassified" when the text cannot be shown safely.
func SafeReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	return SafeText(err.Error())
}

// SafeText applies the SafeReason filter to text received from another process.
func SafeText(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if len(text) > MaxReasonBytes || !safeReasonPattern.MatchString(text) || hexRunPattern.MatchString(text) {
		return "unclassified"
	}
	lower := strings.ToLower(text)
	for _, word := range sensitiveReasonWords {
		if strings.Contains(lower, word) {
			return "unclassified"
		}
	}
	return text
}
