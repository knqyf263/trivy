package image

import (
	"encoding/json"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewReference(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "tag reference",
			input: "alpine:3.20",
			want:  "alpine:3.20",
		},
		{
			name:  "digest reference",
			input: "alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			want:  "alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
		},
		{
			name:  "registry with tag",
			input: "ghcr.io/aquasecurity/trivy:latest",
			want:  "ghcr.io/aquasecurity/trivy:latest",
		},
		{
			name:  "registry with digest",
			input: "ghcr.io/aquasecurity/trivy@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			want:  "ghcr.io/aquasecurity/trivy@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
		},
		{
			name:  "empty string returns nil",
			input: "",
			want:  "",
		},
		{
			name:    "invalid reference",
			input:   "invalid:reference:with:colons",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewReference(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.input == "" {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.want, got.String())
			}
		})
	}
}

func TestReference_MarshalJSON(t *testing.T) {
	tests := []struct {
		name  string
		ref   *Reference
		want  string
	}{
		{
			name: "tag reference",
			ref: func() *Reference {
				r, _ := NewReference("alpine:3.20")
				return r
			}(),
			want: `"alpine:3.20"`,
		},
		{
			name: "digest reference",
			ref: func() *Reference {
				r, _ := NewReference("alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872")
				return r
			}(),
			want: `"alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872"`,
		},
		{
			name: "registry with tag",
			ref: func() *Reference {
				r, _ := NewReference("ghcr.io/aquasecurity/trivy:latest")
				return r
			}(),
			want: `"ghcr.io/aquasecurity/trivy:latest"`,
		},
		{
			name: "nil reference",
			ref:  nil,
			want: `null`,
		},
		{
			name: "empty reference",
			ref:  &Reference{},
			want: `null`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []byte
			var err error
			if tt.ref == nil {
				// Handle nil case explicitly
				got, err = json.Marshal((*Reference)(nil))
			} else {
				got, err = json.Marshal(tt.ref)
			}
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))
		})
	}
}

func TestReference_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantNil bool
		wantErr bool
	}{
		{
			name:  "tag reference",
			input: `"alpine:3.20"`,
			want:  "alpine:3.20",
		},
		{
			name:  "digest reference",
			input: `"alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872"`,
			want:  "alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
		},
		{
			name:  "registry with tag",
			input: `"ghcr.io/aquasecurity/trivy:latest"`,
			want:  "ghcr.io/aquasecurity/trivy:latest",
		},
		{
			name:    "null value",
			input:   `null`,
			wantNil: true,
		},
		{
			name:    "empty string",
			input:   `""`,
			wantNil: true,
		},
		{
			name:    "invalid reference",
			input:   `"invalid:reference:with:colons"`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			input:   `{not valid json}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ref Reference
			err := json.Unmarshal([]byte(tt.input), &ref)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Empty(t, ref.String())
			} else {
				assert.Equal(t, tt.want, ref.String())
			}
		})
	}
}

func TestReference_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "tag reference",
			input: "alpine:3.20",
		},
		{
			name:  "digest reference",
			input: "alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
		},
		{
			name:  "registry with tag",
			input: "ghcr.io/aquasecurity/trivy:latest",
		},
		{
			name:  "registry with digest",
			input: "ghcr.io/aquasecurity/trivy@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create reference
			ref1, err := NewReference(tt.input)
			require.NoError(t, err)
			require.NotNil(t, ref1)

			// Marshal to JSON
			data, err := json.Marshal(ref1)
			require.NoError(t, err)

			// Unmarshal from JSON
			var ref2 Reference
			err = json.Unmarshal(data, &ref2)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, ref1.String(), ref2.String())
		})
	}
}

func TestReference_Properties(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantName     string
		wantID       string
		wantIsTag    bool
		wantIsDigest bool
	}{
		{
			name:         "tag reference",
			input:        "alpine:3.20",
			wantName:     "index.docker.io/library/alpine",
			wantID:       "3.20",
			wantIsTag:    true,
			wantIsDigest: false,
		},
		{
			name:         "digest reference",
			input:        "alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			wantName:     "index.docker.io/library/alpine",
			wantID:       "sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			wantIsTag:    false,
			wantIsDigest: true,
		},
		{
			name:         "registry with tag",
			input:        "ghcr.io/aquasecurity/trivy:latest",
			wantName:     "ghcr.io/aquasecurity/trivy",
			wantID:       "latest",
			wantIsTag:    true,
			wantIsDigest: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := NewReference(tt.input)
			require.NoError(t, err)
			require.NotNil(t, ref)

			assert.Equal(t, tt.wantName, ref.Context().Name())
			assert.Equal(t, tt.wantID, ref.Identifier())
			assert.Equal(t, tt.wantIsTag, ref.IsTag())
			assert.Equal(t, tt.wantIsDigest, ref.IsDigest())
		})
	}
}

func TestDetermineReference(t *testing.T) {
	tests := []struct {
		name        string
		repoTags    []string
		repoDigests []string
		imageName   string
		wantRef     string
	}{
		{
			name: "tarball with repo tags",
			repoTags: []string{
				"alpine:3.20",
				"alpine:latest",
			},
			imageName: "",
			wantRef:   "alpine:3.20",
		},
		{
			name: "image name with matching tag",
			repoTags: []string{
				"index.docker.io/library/alpine:3.20",
				"index.docker.io/library/alpine:latest",
			},
			imageName: "alpine:3.20",
			wantRef:   "index.docker.io/library/alpine:3.20",
		},
		{
			name: "registry image with matching tag",
			repoTags: []string{
				"ghcr.io/aquasecurity/trivy:0.45.0",
				"ghcr.io/aquasecurity/trivy:latest",
			},
			imageName: "ghcr.io/aquasecurity/trivy:latest",
			wantRef:   "ghcr.io/aquasecurity/trivy:latest",
		},
		{
			name: "image name with matching digest",
			repoDigests: []string{
				"index.docker.io/library/alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			},
			imageName: "alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			wantRef:   "index.docker.io/library/alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
		},
		{
			name: "registry image with matching digest",
			repoDigests: []string{
				"ghcr.io/aquasecurity/trivy@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			},
			imageName: "ghcr.io/aquasecurity/trivy@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			wantRef:   "ghcr.io/aquasecurity/trivy@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
		},
		{
			name: "no matching tag",
			repoTags: []string{
				"alpine:3.19",
				"alpine:latest",
			},
			imageName: "alpine:3.20",
			wantRef:   "",
		},
		{
			name: "no matching digest",
			repoDigests: []string{
				"alpine@sha256:different",
			},
			imageName: "alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			wantRef:   "",
		},
		{
			name:      "nil slices",
			repoTags:  nil,
			repoDigests: nil,
			imageName: "alpine:3.20",
			wantRef:   "",
		},
		{
			name:        "empty repo tags and digests",
			repoTags:    []string{},
			repoDigests: []string{},
			imageName:   "",
			wantRef:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := DetermineReference(tt.repoTags, tt.repoDigests, tt.imageName)
			require.NoError(t, err)

			if tt.wantRef == "" {
				assert.Nil(t, ref)
			} else {
				require.NotNil(t, ref)
				assert.Equal(t, tt.wantRef, ref.String())
			}
		})
	}
}

func TestSelectReferenceByTag(t *testing.T) {
	tests := []struct {
		name     string
		repoTags []string
		target   string
		wantRef  string
	}{
		{
			name: "exact match",
			repoTags: []string{
				"alpine:3.20",
			},
			target:  "alpine:3.20",
			wantRef: "alpine:3.20",
		},
		{
			name: "normalized match - bare name",
			repoTags: []string{
				"index.docker.io/library/alpine:3.20",
			},
			target:  "alpine:3.20",
			wantRef: "index.docker.io/library/alpine:3.20",
		},
		{
			name: "no match",
			repoTags: []string{
				"alpine:3.19",
			},
			target:  "alpine:3.20",
			wantRef: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetTag, err := name.ParseReference(tt.target)
			require.NoError(t, err)

			ref, err := SelectReferenceByTag(tt.repoTags, targetTag.(name.Tag))
			require.NoError(t, err)

			if tt.wantRef == "" {
				assert.Nil(t, ref)
			} else {
				require.NotNil(t, ref)
				assert.Equal(t, tt.wantRef, ref.String())
			}
		})
	}
}

