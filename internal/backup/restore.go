package backup

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/store"
)

// Inspect reads a bundle's manifest without touching anything on disk, so a
// page can say what is in a file before anybody commits to loading it.
func Inspect(r io.ReaderAt, size int64) (Manifest, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return Manifest{}, fmt.Errorf("this file is not a readable backup: %w", err)
	}
	return readManifest(zr)
}

func readManifest(zr *zip.Reader) (Manifest, error) {
	for _, f := range zr.File {
		if f.Name != manifestName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return Manifest{}, err
		}
		defer rc.Close()
		body, err := io.ReadAll(io.LimitReader(rc, 1<<20))
		if err != nil {
			return Manifest{}, err
		}
		var m Manifest
		if err := json.Unmarshal(body, &m); err != nil {
			return Manifest{}, fmt.Errorf("the backup's manifest is unreadable: %w", err)
		}
		if m.Format != Format {
			return Manifest{}, fmt.Errorf("this is a zip file but not an ENCLAVE backup")
		}
		if m.Schema > store.SchemaVersion {
			return Manifest{}, &store.ErrNewerSchema{
				Found: m.Schema, Understood: store.SchemaVersion, WrittenBy: m.CreatedBy,
			}
		}
		return m, nil
	}
	return Manifest{}, fmt.Errorf(
		"this zip has no %s, so it was not produced by ENCLAVE", manifestName)
}

// Result reports what a restore did.
type Result struct {
	Manifest Manifest
	// Replaced is where the data that was there beforehand was saved, so that
	// a restore onto the wrong directory is recoverable.
	Replaced string
	Files    int
}

// Restore replaces everything in dataDir with the contents of a bundle.
//
// It is deliberately a replacement rather than a merge. Merging two data sets
// means deciding what happens when both sides changed the same enclave, and
// guessing at that quietly is worse than not offering it. The data that was
// there is written to a bundle of its own first, and the path is reported.
func Restore(dataDir string, r io.ReaderAt, size int64, buildVersion string) (*Result, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("this file is not a readable backup: %w", err)
	}
	man, err := readManifest(zr)
	if err != nil {
		return nil, err
	}

	// Unpack into a staging directory first. Nothing that is already on disk is
	// touched until the incoming data has been read and proved loadable.
	staging, err := os.MkdirTemp(dataDir, ".restore-")
	if err != nil {
		return nil, fmt.Errorf("preparing to restore: %w", err)
	}
	defer os.RemoveAll(staging)

	written := 0
	for _, f := range zr.File {
		if f.Name == manifestName {
			continue
		}
		rel, ok := safeRelative(f.Name)
		if !ok {
			return nil, fmt.Errorf("the backup contains an unsafe path (%q) and was not loaded", f.Name)
		}
		if f.FileInfo().IsDir() {
			continue
		}
		dest := filepath.Join(staging, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return nil, err
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("reading %s from the backup: %w", rel, err)
		}
		if err := os.WriteFile(dest, body, 0o644); err != nil {
			return nil, err
		}
		written++
	}
	if written == 0 {
		return nil, fmt.Errorf("the backup contains no data files")
	}

	// Proving the staged data loads means a corrupt bundle is refused before
	// the live directory is disturbed, rather than after.
	if _, err := store.Open(staging); err != nil {
		return nil, fmt.Errorf("the backup did not load, so nothing was changed: %w", err)
	}

	res := &Result{Manifest: man, Files: written}

	// Save what is being replaced. A restore onto the wrong data directory is
	// an easy mistake and should not be the end of the story.
	if hasRecords(dataDir) {
		saved, err := saveCurrent(dataDir, buildVersion)
		if err != nil {
			return nil, fmt.Errorf("could not save the data being replaced, so nothing was changed: %w", err)
		}
		res.Replaced = saved
	}

	if err := clearData(dataDir); err != nil {
		return nil, fmt.Errorf("clearing the old data: %w", err)
	}
	if err := moveInto(staging, dataDir); err != nil {
		return nil, fmt.Errorf("putting the restored data in place: %w", err)
	}
	// The restored data is stamped by this build, since this build has now
	// established it loads.
	if err := store.WriteStamp(dataDir, buildVersion); err != nil {
		return nil, err
	}
	return res, nil
}

// hasRecords reports whether a data directory holds anything worth preserving.
// A directory containing only a version stamp has nothing in it, and writing a
// bundle of that would leave a confusing file behind on every fresh install.
func hasRecords(dataDir string) bool {
	files, err := collect(dataDir)
	if err != nil {
		return false
	}
	for _, rel := range files {
		if rel == "schema.json" {
			continue
		}
		if info, err := os.Stat(filepath.Join(dataDir, filepath.FromSlash(rel))); err == nil && info.Size() > 2 {
			return true
		}
	}
	return false
}

// safeRelative rejects the archive paths that would let a bundle write outside
// the directory it is being restored into.
func safeRelative(name string) (string, bool) {
	if !strings.HasPrefix(name, dataPrefix) {
		return "", false
	}
	rel := strings.TrimPrefix(name, dataPrefix)
	if rel == "" {
		return "", false
	}
	if strings.Contains(rel, "\\") || strings.HasPrefix(rel, "/") {
		return "", false
	}
	clean := filepath.ToSlash(filepath.Clean(rel))
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." ||
		filepath.IsAbs(clean) || strings.HasPrefix(clean, ".") {
		return "", false
	}
	if !wanted(clean) {
		return "", false
	}
	return clean, true
}

// SaveCurrent writes the data directory to a bundle inside its own backups
// folder and returns the path.
func SaveCurrent(dataDir, buildVersion string) (string, error) {
	return saveCurrent(dataDir, buildVersion)
}

func saveCurrent(dataDir, buildVersion string) (string, error) {
	dir := filepath.Join(dataDir, BackupsDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("before-restore-%s.zip", time.Now().UTC().Format("20060102-150405"))
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := Write(dataDir, f, buildVersion); err != nil {
		return "", err
	}
	return path, nil
}

// clearData removes the files a data set is made of, leaving anything else in
// the directory alone. In particular it leaves the backups folder, which is
// where the copy of what is being replaced has just gone.
func clearData(dataDir string) error {
	files, err := collect(dataDir)
	if err != nil {
		return err
	}
	for _, rel := range files {
		if err := os.Remove(filepath.Join(dataDir, filepath.FromSlash(rel))); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func moveInto(staging, dataDir string) error {
	entries, err := collect(staging)
	if err != nil {
		return err
	}
	for _, rel := range entries {
		src := filepath.Join(staging, filepath.FromSlash(rel))
		dst := filepath.Join(dataDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.Rename(src, dst); err != nil {
			// A rename can fail across filesystems even within one directory
			// tree on some setups, so fall back to copying the bytes.
			body, readErr := os.ReadFile(src)
			if readErr != nil {
				return err
			}
			if writeErr := os.WriteFile(dst, body, 0o644); writeErr != nil {
				return writeErr
			}
		}
	}
	return nil
}

// List returns the bundles ENCLAVE has written for itself, newest first.
func List(dataDir string) []string {
	entries, err := os.ReadDir(filepath.Join(dataDir, BackupsDir))
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".zip") {
			out = append(out, e.Name())
		}
	}
	// The names carry a sortable timestamp, so reversing lexical order is
	// newest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// SuggestedFilename is what a downloaded bundle should be called.
func SuggestedFilename(now time.Time) string {
	return "enclave-backup-" + now.Format("20060102-150405") + ".zip"
}
