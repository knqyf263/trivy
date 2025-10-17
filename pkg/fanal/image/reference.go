package image

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// Reference represents a container image reference that can be either a tag or digest.
// It embeds name.Reference from go-containerregistry and implements custom JSON marshaling.
type Reference struct {
	name.Reference
}

// NewReference creates a new Reference from a string.
func NewReference(s string) (*Reference, error) {
	if s == "" {
		return nil, nil
	}

	ref, err := name.ParseReference(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference %q: %w", s, err)
	}

	return &Reference{Reference: ref}, nil
}

// String returns the string representation of the reference.
func (r *Reference) String() string {
	if r == nil || r.Reference == nil {
		return ""
	}
	return r.Reference.String()
}

// IsTag returns true if this reference is a tag.
func (r *Reference) IsTag() bool {
	if r == nil || r.Reference == nil {
		return false
	}
	_, ok := r.Reference.(name.Tag)
	return ok
}

// IsDigest returns true if this reference is a digest.
func (r *Reference) IsDigest() bool {
	if r == nil || r.Reference == nil {
		return false
	}
	_, ok := r.Reference.(name.Digest)
	return ok
}

// MarshalJSON implements json.Marshaler interface.
func (r Reference) MarshalJSON() ([]byte, error) {
	if r.Reference == nil {
		return json.Marshal(nil)
	}
	return json.Marshal(r.Reference.String())
}

// UnmarshalJSON implements json.Unmarshaler interface.
func (r *Reference) UnmarshalJSON(data []byte) error {
	var s *string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	if s == nil || *s == "" {
		r.Reference = nil
		return nil
	}

	ref, err := name.ParseReference(*s)
	if err != nil {
		return fmt.Errorf("failed to parse reference %q: %w", *s, err)
	}

	r.Reference = ref
	return nil
}

// DetermineReference determines the best reference based on the provided image name and available references.
// It handles three cases:
// 1. If imageName is empty and RepoTags exist, use the first RepoTag
// 2. If imageName contains a tag, find matching RepoTag
// 3. If imageName contains a digest, find matching RepoDigest
func DetermineReference(repoTags []string, repoDigests []string, imageName string) (*Reference, error) {
	// Case 1: No image name provided (e.g., tarball), use first RepoTag
	if imageName == "" {
		if len(repoTags) > 0 {
			return NewReference(repoTags[0])
		}
		return nil, nil
	}

	// Parse the provided image name to determine if it's a tag or digest
	parsedRef, err := name.ParseReference(imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image name %q: %w", imageName, err)
	}

	switch ref := parsedRef.(type) {
	case name.Tag:
		// Case 2: Image name with tag - match by comparing normalized references
		return SelectReferenceByTag(repoTags, ref)

	case name.Digest:
		// Case 3: Image name with digest - match by comparing normalized references
		return SelectReferenceByDigest(repoDigests, ref)
	}

	// No matching reference found
	return nil, nil
}

// SelectReferenceByTag finds a matching tag reference from RepoTags
func SelectReferenceByTag(repoTags []string, targetTag name.Tag) (*Reference, error) {
	targetContext := targetTag.Context().Name()
	targetIdentifier := targetTag.Identifier()

	for _, repoTag := range repoTags {
		parsedTag, err := name.ParseReference(repoTag)
		if err != nil {
			continue
		}

		tag, ok := parsedTag.(name.Tag)
		if !ok {
			continue
		}

		// Compare both context (registry/namespace/repo) and identifier (tag)
		if normalizeContext(tag.Context().Name()) == normalizeContext(targetContext) &&
		   tag.Identifier() == targetIdentifier {
			return &Reference{Reference: tag}, nil
		}
	}

	return nil, nil
}

// SelectReferenceByDigest finds a matching digest reference from RepoDigests
func SelectReferenceByDigest(repoDigests []string, targetDigest name.Digest) (*Reference, error) {
	targetContext := targetDigest.Context().Name()
	targetIdentifier := targetDigest.Identifier()

	for _, repoDigest := range repoDigests {
		parsedDigest, err := name.ParseReference(repoDigest)
		if err != nil {
			continue
		}

		digest, ok := parsedDigest.(name.Digest)
		if !ok {
			continue
		}

		// Compare both context (registry/namespace/repo) and identifier (digest)
		if normalizeContext(digest.Context().Name()) == normalizeContext(targetContext) &&
		   digest.Identifier() == targetIdentifier {
			return &Reference{Reference: digest}, nil
		}
	}

	return nil, nil
}

// normalizeContext normalizes the registry context for comparison
// e.g., "alpine" -> "index.docker.io/library/alpine"
func normalizeContext(context string) string {
	// Handle Docker Hub special cases
	if !strings.Contains(context, "/") {
		// Bare name like "alpine" -> "index.docker.io/library/alpine"
		return "index.docker.io/library/" + context
	}
	if strings.HasPrefix(context, "library/") {
		// library/alpine -> index.docker.io/library/alpine
		return "index.docker.io/" + context
	}
	if !strings.Contains(context, ".") && !strings.Contains(context, ":") && !strings.HasPrefix(context, "localhost") {
		// user/repo without registry -> index.docker.io/user/repo
		return "index.docker.io/" + context
	}
	return context
}