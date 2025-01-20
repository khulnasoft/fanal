package daemon

import (
	"io/ioutil"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/testdocker/engine"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/docker/api/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func setupPodmanSock(t *testing.T) *httptest.Server {
	t.Helper()

	runtimeDir, err := ioutil.TempDir("", "daemon")
	require.NoError(t, err)

	os.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	dir := filepath.Join(runtimeDir, "podman")
	err = os.MkdirAll(dir, os.ModePerm)
	require.NoError(t, err)

	sockPath := filepath.Join(dir, "podman.sock")

	opt := engine.Option{
		APIVersion: "1.40",
		ImagePaths: map[string]string{
			"index.docker.io/library/alpine:3.11": "../../test/testdata/alpine-311.tar.gz",
		},
		UnixDomainSocket: sockPath,
	}
	te := engine.NewDockerEngine(opt)
	return te
}

func TestPodmanImage(t *testing.T) {
	type fields struct {
		Image   v1.Image
		opener  opener
		inspect types.ImageInspect
	}
	tests := []struct {
		name           string
		imageName      string
		fields         fields
		wantConfigName string
		wantErr        bool
	}{
		{
			name:           "happy path",
			imageName:      "alpine:3.11",
			wantConfigName: "sha256:a787cb9865032e5b5a407ecdf34b57a23a4a076aaa043d71742ddb6726ec9229",
			wantErr:        false,
		},
		{
			name:      "unknown image",
			imageName: "alpine:unknown",
			wantErr:   true,
		},
	}

	te := setupPodmanSock(t)
	defer te.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := name.ParseReference(tt.imageName)
			require.NoError(t, err)

			img, cleanup, err := PodmanImage(ref.Name())
			defer cleanup()

			if tt.wantErr {
				assert.NotNil(t, err)
				return
			}
			assert.NoError(t, err)

			confName, err := img.ConfigName()
			require.NoError(t, err)
			assert.Equal(t, tt.wantConfigName, confName.String())
		})
	}
}
