package artifact

import (
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
)

// ImageReference represents a container image reference that can be either a tag or digest.
// It wraps name.Reference from go-containerregistry and implements custom JSON marshaling.
type ImageReference struct {
	ref name.Reference
}

// NewImageReference creates a new ImageReference from a string.
func NewImageReference(s string) (*ImageReference, error) {
	if s == "" {
		return nil, nil
	}

	ref, err := name.ParseReference(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference %q: %w", s, err)
	}

	return &ImageReference{ref: ref}, nil
}

// String returns the string representation of the reference.
func (r *ImageReference) String() string {
	if r == nil || r.ref == nil {
		return ""
	}
	return r.ref.String()
}

// Name returns the repository name without tag or digest.
func (r *ImageReference) Name() string {
	if r == nil || r.ref == nil {
		return ""
	}
	return r.ref.Context().Name()
}

// Identifier returns the tag or digest portion of the reference.
func (r *ImageReference) Identifier() string {
	if r == nil || r.ref == nil {
		return ""
	}
	return r.ref.Identifier()
}

// IsTag returns true if this reference is a tag.
func (r *ImageReference) IsTag() bool {
	if r == nil || r.ref == nil {
		return false
	}
	_, ok := r.ref.(name.Tag)
	return ok
}

// IsDigest returns true if this reference is a digest.
func (r *ImageReference) IsDigest() bool {
	if r == nil || r.ref == nil {
		return false
	}
	_, ok := r.ref.(name.Digest)
	return ok
}

// MarshalJSON implements json.Marshaler interface.
func (r ImageReference) MarshalJSON() ([]byte, error) {
	if r.ref == nil {
		return json.Marshal(nil)
	}
	return json.Marshal(r.ref.String())
}

// UnmarshalJSON implements json.Unmarshaler interface.
func (r *ImageReference) UnmarshalJSON(data []byte) error {
	var s *string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	if s == nil || *s == "" {
		r.ref = nil
		return nil
	}

	ref, err := name.ParseReference(*s)
	if err != nil {
		return fmt.Errorf("failed to parse reference %q: %w", *s, err)
	}

	r.ref = ref
	return nil
}

// SetImageReference sets the reference for the given ImageMetadata based on the provided image name.
// It handles three cases:
// 1. If imageName is empty and RepoTags exist, use the first RepoTag
// 2. If imageName contains a tag, find matching RepoTag
// 3. If imageName contains a digest, find matching RepoDigest
func SetImageReference(metadata *ImageMetadata, imageName string) error {
	if metadata == nil {
		return nil
	}

	// Case 1: No image name provided (e.g., tarball), use first RepoTag
	if imageName == "" {
		if len(metadata.RepoTags) > 0 {
			ref, err := NewImageReference(metadata.RepoTags[0])
			if err != nil {
				// Log error but don't fail
				return nil
			}
			metadata.Reference = ref
		}
		return nil
	}

	// Parse the provided image name to determine if it's a tag or digest
	parsedRef, err := name.ParseReference(imageName)
	if err != nil {
		return fmt.Errorf("failed to parse image name %q: %w", imageName, err)
	}

	switch parsedRef.(type) {
	case name.Tag:
		// Case 2: Image name with tag
		for _, repoTag := range metadata.RepoTags {
			if repoTag == imageName {
				ref, err := NewImageReference(repoTag)
				if err != nil {
					continue
				}
				metadata.Reference = ref
				return nil
			}
		}
	case name.Digest:
		// Case 3: Image name with digest
		for _, repoDigest := range metadata.RepoDigests {
			if repoDigest == imageName {
				ref, err := NewImageReference(repoDigest)
				if err != nil {
					continue
				}
				metadata.Reference = ref
				return nil
			}
		}
	}

	// No matching reference found, leave Reference as nil
	return nil
}