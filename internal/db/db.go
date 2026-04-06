// Package db provides a simple JSON-file-backed image approval store.
// Records are persisted atomically (write-to-temp + rename) and access
// within a process is serialised with a sync.RWMutex.
package db

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ImageStatus is the set of valid status values for an image record.
type ImageStatus string

const (
	StatusApproved  ImageStatus = "approved"
	StatusRescinded ImageStatus = "rescinded"
	StatusRejected  ImageStatus = "rejected"
)

// Image represents one tracked OCI image tag.
type Image struct {
	ID          int64       `json:"id"`
	Registry    string      `json:"registry"`
	Repository  string      `json:"repository"`
	Tag         string      `json:"tag"`
	Digest      string      `json:"digest"`
	Manifest    string      `json:"manifest,omitempty"`
	TrivyReport string      `json:"trivy_report,omitempty"`
	Status      ImageStatus `json:"status"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// ImageRef is the decomposed lookup key for an image reference.
type ImageRef struct {
	Registry   string
	Repository string
	Tag        string
}

type store struct {
	Images []Image `json:"images"`
	NextID int64   `json:"next_id"`
}

// DB is a JSON-file-backed image store.
type DB struct {
	path string
	mu   sync.RWMutex
}

// Open opens (or creates) the JSON store at path.
func Open(path string) (*DB, error) {
	d := &DB{path: path}
	// Ensure the file exists with a valid empty store.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := d.save(&store{NextID: 1}); err != nil {
			return nil, fmt.Errorf("init store: %w", err)
		}
	}
	// Validate that the file is readable and well-formed.
	if _, err := d.load(); err != nil {
		return nil, fmt.Errorf("open store %q: %w", path, err)
	}
	return d, nil
}

// Close is a no-op; it satisfies a common interface.
func (d *DB) Close() error { return nil }

// UpsertApproved inserts or fully updates an image record with status=approved.
func (d *DB) UpsertApproved(ref ImageRef, digest, manifest, trivyReport string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	s, err := d.load()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	for i, img := range s.Images {
		if img.Registry == ref.Registry && img.Repository == ref.Repository && img.Tag == ref.Tag {
			s.Images[i].Digest = digest
			s.Images[i].Manifest = manifest
			s.Images[i].TrivyReport = trivyReport
			s.Images[i].Status = StatusApproved
			s.Images[i].UpdatedAt = now
			return d.save(s)
		}
	}

	s.Images = append(s.Images, Image{
		ID:          s.NextID,
		Registry:    ref.Registry,
		Repository:  ref.Repository,
		Tag:         ref.Tag,
		Digest:      digest,
		Manifest:    manifest,
		TrivyReport: trivyReport,
		Status:      StatusApproved,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	s.NextID++
	return d.save(s)
}

// UpsertStatus inserts a skeleton row or updates only status+updated_at,
// preserving any existing digest/manifest/trivy_report data.
func (d *DB) UpsertStatus(ref ImageRef, status ImageStatus) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	s, err := d.load()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	for i, img := range s.Images {
		if img.Registry == ref.Registry && img.Repository == ref.Repository && img.Tag == ref.Tag {
			s.Images[i].Status = status
			s.Images[i].UpdatedAt = now
			return d.save(s)
		}
	}

	// Not found — insert a skeleton record.
	s.Images = append(s.Images, Image{
		ID:         s.NextID,
		Registry:   ref.Registry,
		Repository: ref.Repository,
		Tag:        ref.Tag,
		Status:     status,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	s.NextID++
	return d.save(s)
}

// GetByRef returns the Image matching the given reference, or nil if not found.
func (d *DB) GetByRef(ref ImageRef) (*Image, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	s, err := d.load()
	if err != nil {
		return nil, err
	}
	for _, img := range s.Images {
		if img.Registry == ref.Registry && img.Repository == ref.Repository && img.Tag == ref.Tag {
			cp := img
			return &cp, nil
		}
	}
	return nil, nil
}

// GetApproved returns an approved image by repository+tag (registry-agnostic).
// Used by the API where the registry is not known from the request path.
func (d *DB) GetApproved(repository, tag string) (*Image, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	s, err := d.load()
	if err != nil {
		return nil, err
	}
	for _, img := range s.Images {
		if img.Repository == repository && img.Tag == tag && img.Status == StatusApproved {
			cp := img
			return &cp, nil
		}
	}
	return nil, nil
}

// List returns all images, optionally filtered by status (empty = all),
// ordered by UpdatedAt descending.
func (d *DB) List(status ImageStatus) ([]Image, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	s, err := d.load()
	if err != nil {
		return nil, err
	}

	var out []Image
	for _, img := range s.Images {
		if status == "" || img.Status == status {
			out = append(out, img)
		}
	}

	// Sort by updated_at descending (simple insertion-sort for small sets).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].UpdatedAt.After(out[j-1].UpdatedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

// load reads and parses the JSON store file. Must be called with mu held.
func (d *DB) load() (*store, error) {
	data, err := os.ReadFile(d.path)
	if err != nil {
		return nil, fmt.Errorf("read store: %w", err)
	}
	var s store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse store: %w", err)
	}
	if s.NextID == 0 {
		s.NextID = 1
	}
	return &s, nil
}

// save writes the store to disk atomically. Must be called with mu held (write).
func (d *DB) save(s *store) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal store: %w", err)
	}

	dir := filepath.Dir(d.path)
	tmp, err := os.CreateTemp(dir, ".hermes-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, d.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename store file: %w", err)
	}
	return nil
}
