package artifact

import (
	"encoding/json"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewImageReference(t *testing.T) {
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
			got, err := NewImageReference(tt.input)
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

func TestImageReference_MarshalJSON(t *testing.T) {
	tests := []struct {
		name  string
		ref   *ImageReference
		want  string
	}{
		{
			name: "tag reference",
			ref: func() *ImageReference {
				r, _ := NewImageReference("alpine:3.20")
				return r
			}(),
			want: `"alpine:3.20"`,
		},
		{
			name: "digest reference",
			ref: func() *ImageReference {
				r, _ := NewImageReference("alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872")
				return r
			}(),
			want: `"alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872"`,
		},
		{
			name: "registry with tag",
			ref: func() *ImageReference {
				r, _ := NewImageReference("ghcr.io/aquasecurity/trivy:latest")
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
			ref:  &ImageReference{},
			want: `null`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []byte
			var err error
			if tt.ref == nil {
				// Handle nil case explicitly
				got, err = json.Marshal((*ImageReference)(nil))
			} else {
				got, err = json.Marshal(tt.ref)
			}
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))
		})
	}
}

func TestImageReference_UnmarshalJSON(t *testing.T) {
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
			var ref ImageReference
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

func TestImageReference_JSONRoundTrip(t *testing.T) {
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
			ref1, err := NewImageReference(tt.input)
			require.NoError(t, err)
			require.NotNil(t, ref1)

			// Marshal to JSON
			data, err := json.Marshal(ref1)
			require.NoError(t, err)

			// Unmarshal from JSON
			var ref2 ImageReference
			err = json.Unmarshal(data, &ref2)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, ref1.String(), ref2.String())
		})
	}
}

func TestImageReference_Properties(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantName   string
		wantID     string
		wantIsTag  bool
		wantIsDigest bool
	}{
		{
			name:       "tag reference",
			input:      "alpine:3.20",
			wantName:   "index.docker.io/library/alpine",
			wantID:     "3.20",
			wantIsTag:  true,
			wantIsDigest: false,
		},
		{
			name:       "digest reference",
			input:      "alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			wantName:   "index.docker.io/library/alpine",
			wantID:     "sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			wantIsTag:  false,
			wantIsDigest: true,
		},
		{
			name:       "registry with tag",
			input:      "ghcr.io/aquasecurity/trivy:latest",
			wantName:   "ghcr.io/aquasecurity/trivy",
			wantID:     "latest",
			wantIsTag:  true,
			wantIsDigest: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := NewImageReference(tt.input)
			require.NoError(t, err)
			require.NotNil(t, ref)

			assert.Equal(t, tt.wantName, ref.Name())
			assert.Equal(t, tt.wantID, ref.Identifier())
			assert.Equal(t, tt.wantIsTag, ref.IsTag())
			assert.Equal(t, tt.wantIsDigest, ref.IsDigest())
		})
	}
}

func TestSetImageReference(t *testing.T) {
	tests := []struct {
		name      string
		metadata  *ImageMetadata
		imageName string
		wantRef   string
	}{
		{
			name: "tarball with repo tags",
			metadata: &ImageMetadata{
				RepoTags: []string{
					"alpine:3.20",
					"alpine:latest",
				},
			},
			imageName: "",
			wantRef:   "alpine:3.20",
		},
		{
			name: "image name with matching tag",
			metadata: &ImageMetadata{
				RepoTags: []string{
					"alpine:3.20",
					"alpine:latest",
				},
			},
			imageName: "alpine:3.20",
			wantRef:   "alpine:3.20",
		},
		{
			name: "registry image with matching tag",
			metadata: &ImageMetadata{
				RepoTags: []string{
					"ghcr.io/aquasecurity/trivy:0.45.0",
					"ghcr.io/aquasecurity/trivy:latest",
				},
			},
			imageName: "ghcr.io/aquasecurity/trivy:latest",
			wantRef:   "ghcr.io/aquasecurity/trivy:latest",
		},
		{
			name: "image name with matching digest",
			metadata: &ImageMetadata{
				RepoDigests: []string{
					"alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
				},
			},
			imageName: "alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			wantRef:   "alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
		},
		{
			name: "registry image with matching digest",
			metadata: &ImageMetadata{
				RepoDigests: []string{
					"ghcr.io/aquasecurity/trivy@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
				},
			},
			imageName: "ghcr.io/aquasecurity/trivy@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			wantRef:   "ghcr.io/aquasecurity/trivy@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
		},
		{
			name: "no matching tag",
			metadata: &ImageMetadata{
				RepoTags: []string{
					"alpine:3.19",
					"alpine:latest",
				},
			},
			imageName: "alpine:3.20",
			wantRef:   "",
		},
		{
			name: "no matching digest",
			metadata: &ImageMetadata{
				RepoDigests: []string{
					"alpine@sha256:different",
				},
			},
			imageName: "alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
			wantRef:   "",
		},
		{
			name:      "nil metadata",
			metadata:  nil,
			imageName: "alpine:3.20",
			wantRef:   "",
		},
		{
			name: "empty repo tags and digests",
			metadata: &ImageMetadata{
				RepoTags:    []string{},
				RepoDigests: []string{},
			},
			imageName: "",
			wantRef:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetImageReference(tt.metadata, tt.imageName)
			require.NoError(t, err)

			if tt.wantRef == "" {
				if tt.metadata != nil {
					assert.Nil(t, tt.metadata.Reference)
				}
			} else {
				require.NotNil(t, tt.metadata)
				require.NotNil(t, tt.metadata.Reference)
				assert.Equal(t, tt.wantRef, tt.metadata.Reference.String())
			}
		})
	}
}

func TestImageMetadata_JSONMarshaling(t *testing.T) {
	ref, err := NewImageReference("alpine:3.20")
	require.NoError(t, err)

	metadata := ImageMetadata{
		ID:      "sha256:abc123",
		DiffIDs: []string{"sha256:layer1", "sha256:layer2"},
		RepoTags: []string{
			"alpine:3.20",
			"alpine:latest",
		},
		RepoDigests: []string{
			"alpine@sha256:7580ece7963bfa863801466c0a488f11c86f85d9988051a9f9c68cb27f6b7872",
		},
		ConfigFile: v1.ConfigFile{
			Architecture: "amd64",
		},
		Reference: ref,
	}

	// Marshal
	data, err := json.Marshal(metadata)
	require.NoError(t, err)

	// Unmarshal
	var metadata2 ImageMetadata
	err = json.Unmarshal(data, &metadata2)
	require.NoError(t, err)

	// Compare
	assert.Equal(t, metadata.ID, metadata2.ID)
	assert.Equal(t, metadata.DiffIDs, metadata2.DiffIDs)
	assert.Equal(t, metadata.RepoTags, metadata2.RepoTags)
	assert.Equal(t, metadata.RepoDigests, metadata2.RepoDigests)
	assert.Equal(t, metadata.ConfigFile.Architecture, metadata2.ConfigFile.Architecture)
	require.NotNil(t, metadata2.Reference)
	assert.Equal(t, metadata.Reference.String(), metadata2.Reference.String())
}