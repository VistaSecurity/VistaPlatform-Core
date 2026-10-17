package services

// Where image attachment bytes live (DCIM BUILD_PLAN row 2.8; the bytes never
// live in Postgres). Two backends behind one interface, chosen per write and
// recorded in the ref so a read never has to guess:
//
//	s3:<key>             shared/storage's dcim_images artifact type, when an
//	                     admin has enabled it (the same switch CBOM artifacts use)
//	local:<tenant>/<id>  a directory on the service's disk (DCIM_IMAGE_DIR,
//	                     default <tmp>/vista-dcim-images) — the compose / brand
//	                     new install path, mirroring cbom-service's inline fallback
//
// A local directory is per pod: a chart install that wants images to outlive a
// restart enables the S3 artifact type or mounts a volume at DCIM_IMAGE_DIR.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"

	sharedstorage "github.com/vistasecurity/vistaplatform/shared/storage"
)

// ImageBlobStore stores the bytes of image attachments.
type ImageBlobStore interface {
	// Put stores data and returns the ref to keep in image_attachments.
	Put(ctx context.Context, tenant uuid.UUID, filename, contentType string, data []byte) (string, error)
	// Open streams a stored image; the caller closes it.
	Open(ctx context.Context, tenant uuid.UUID, ref string) (io.ReadCloser, error)
	// Delete removes a stored image; a missing one is not an error.
	Delete(ctx context.Context, tenant uuid.UUID, ref string) error
}

const (
	refS3    = "s3:"
	refLocal = "local:"
)

var localName = regexp.MustCompile(`^[0-9a-f-]{36}/[0-9a-f-]{36}\.(png|jpg|webp|svg)$`)

// BlobStore is the production ImageBlobStore.
type BlobStore struct {
	s3  sharedstorage.ArtifactStorageService // nil = local only
	dir string
}

// NewBlobStore returns the store: s3 may be nil; dir "" uses DCIM_IMAGE_DIR,
// then a directory under the OS temp dir.
func NewBlobStore(s3 sharedstorage.ArtifactStorageService, dir string) *BlobStore {
	if dir == "" {
		dir = os.Getenv("DCIM_IMAGE_DIR")
	}
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "vista-dcim-images")
	}
	return &BlobStore{s3: s3, dir: dir}
}

func (b *BlobStore) s3On() bool {
	return b.s3 != nil && b.s3.IsEnabled(sharedstorage.ArtifactTypeDcimImages)
}

func (b *BlobStore) Put(ctx context.Context, tenant uuid.UUID, filename, contentType string, data []byte) (string, error) {
	if b.s3On() {
		res, err := b.s3.Upload(ctx, sharedstorage.ArtifactTypeDcimImages, &tenant, filename, bytes.NewReader(data), contentType, int64(len(data)))
		if err != nil {
			return "", fmt.Errorf("storing image: %w", err)
		}
		return refS3 + res.Key, nil
	}
	rel := tenant.String() + "/" + filename
	if !localName.MatchString(rel) {
		return "", fmt.Errorf("storing image: bad file name %q", filename)
	}
	full := filepath.Join(b.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return "", fmt.Errorf("storing image: %w", err)
	}
	if err := os.WriteFile(full, data, 0o640); err != nil {
		return "", fmt.Errorf("storing image: %w", err)
	}
	return refLocal + rel, nil
}

func (b *BlobStore) localPath(tenant uuid.UUID, ref string) (string, error) {
	rel := strings.TrimPrefix(ref, refLocal)
	// The ref must name this tenant's own directory and match the generated
	// shape — a stored ref is never trusted to be a path.
	if !strings.HasPrefix(rel, tenant.String()+"/") || !localName.MatchString(rel) {
		return "", errors.New("image reference is not valid for this tenant")
	}
	return filepath.Join(b.dir, filepath.FromSlash(rel)), nil
}

func (b *BlobStore) Open(ctx context.Context, tenant uuid.UUID, ref string) (io.ReadCloser, error) {
	switch {
	case strings.HasPrefix(ref, refS3):
		if b.s3 == nil {
			return nil, sharedstorage.ErrStorageNotConfigured
		}
		key := strings.TrimPrefix(ref, refS3)
		if !strings.Contains(key, tenant.String()) {
			return nil, errors.New("image reference is not valid for this tenant")
		}
		return b.s3.Stream(ctx, sharedstorage.ArtifactTypeDcimImages, key, &tenant)
	case strings.HasPrefix(ref, refLocal):
		p, err := b.localPath(tenant, ref)
		if err != nil {
			return nil, err
		}
		return os.Open(p)
	}
	return nil, fmt.Errorf("unknown image reference %q", ref)
}

func (b *BlobStore) Delete(ctx context.Context, tenant uuid.UUID, ref string) error {
	switch {
	case strings.HasPrefix(ref, refS3):
		if b.s3 == nil {
			return sharedstorage.ErrStorageNotConfigured
		}
		key := strings.TrimPrefix(ref, refS3)
		if !strings.Contains(key, tenant.String()) {
			return errors.New("image reference is not valid for this tenant")
		}
		return b.s3.Delete(ctx, sharedstorage.ArtifactTypeDcimImages, key, &tenant)
	case strings.HasPrefix(ref, refLocal):
		p, err := b.localPath(tenant, ref)
		if err != nil {
			return err
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return fmt.Errorf("unknown image reference %q", ref)
}

// MemoryBlobStore is an in-memory ImageBlobStore for tests.
type MemoryBlobStore struct {
	Blobs map[string][]byte
}

// NewMemoryBlobStore returns an empty MemoryBlobStore.
func NewMemoryBlobStore() *MemoryBlobStore { return &MemoryBlobStore{Blobs: map[string][]byte{}} }

func (m *MemoryBlobStore) Put(_ context.Context, tenant uuid.UUID, filename, _ string, data []byte) (string, error) {
	ref := refLocal + tenant.String() + "/" + filename
	m.Blobs[ref] = append([]byte(nil), data...)
	return ref, nil
}

func (m *MemoryBlobStore) Open(_ context.Context, _ uuid.UUID, ref string) (io.ReadCloser, error) {
	d, ok := m.Blobs[ref]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(d)), nil
}

func (m *MemoryBlobStore) Delete(_ context.Context, _ uuid.UUID, ref string) error {
	delete(m.Blobs, ref)
	return nil
}
