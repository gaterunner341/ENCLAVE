package web

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/backup"
	"github.com/gaterunner341/enclave/internal/store"
)

// handleData is the page people are sent to when they upgrade: take a backup
// from the old build, restore it into the new one.
func (s *Server) handleData(w http.ResponseWriter, r *http.Request) {
	dir := s.Store.Dir()
	stamp, stamped, err := store.ReadStamp(dir)
	var size int64
	if files, ferr := os.ReadDir(dir); ferr == nil {
		for _, f := range files {
			if info, ierr := f.Info(); ierr == nil {
				size += info.Size()
			}
		}
	}
	saved := []savedBundle{}
	for _, name := range backup.List(dir) {
		b := savedBundle{Name: name}
		if info, ierr := os.Stat(filepath.Join(dir, backup.BackupsDir, name)); ierr == nil {
			b.Size, b.Modified = info.Size(), info.ModTime()
		}
		saved = append(saved, b)
	}
	stampErr := ""
	if err != nil {
		stampErr = err.Error()
	}
	s.render(w, r, "data.html", page{
		Title: "Data and upgrades", Nav: "data",
		Data: map[string]any{
			"Dir": dir, "Stamp": stamp, "Stamped": stamped, "StampError": stampErr,
			"Schema": store.SchemaVersion, "Counts": s.Store.Counts(),
			"Size": size, "Saved": saved,
			"CatalogDir": s.Catalogs.Dir(),
		},
	})
}

type savedBundle struct {
	Name     string
	Size     int64
	Modified time.Time
}

// handleBackup streams the whole data set as one file. It is available in
// read-only mode, because taking a copy changes nothing.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	// The bundle is built in memory first so that a failure produces an error
	// page rather than a truncated download the browser has already saved.
	var buf bytes.Buffer
	if _, err := backup.Write(s.Store.Dir(), &buf, s.Version); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "The backup could not be made: "+err.Error())
		return
	}
	name := backup.SuggestedFilename(time.Now())
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", fmt.Sprint(buf.Len()))
	_, _ = w.Write(buf.Bytes())
}

// handleRestore replaces everything with the contents of an uploaded bundle.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		redirect(w, r, "/data", "", "The upload could not be read: "+err.Error())
		return
	}
	// Replacing every record is not something to do on a stray click.
	if !strings.EqualFold(strings.TrimSpace(r.FormValue("confirm")), "REPLACE") {
		redirect(w, r, "/data", "", "Type REPLACE to confirm that everything currently here should be replaced.")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		redirect(w, r, "/data", "", "Choose a backup file to restore.")
		return
	}
	defer file.Close()
	data, err := readCapped(file, s.MaxUpload)
	if err != nil {
		redirect(w, r, "/data", "", err.Error())
		return
	}
	res, err := backup.Restore(s.Store.Dir(), bytes.NewReader(data), int64(len(data)), s.Version)
	if err != nil {
		redirect(w, r, "/data", "", "Nothing was changed. "+err.Error())
		return
	}
	// The files on disk have been replaced; everything held in memory is now
	// stale and has to be read again before any page is served.
	if err := s.reloadAll(); err != nil {
		s.fail(w, r, http.StatusInternalServerError,
			"The data was restored but could not be loaded: "+err.Error()+
				". Restart ENCLAVE to pick it up.")
		return
	}
	msg := fmt.Sprintf("Restored %s from %s.", res.Manifest.Describe(), header.Filename)
	if res.Replaced != "" {
		msg += " What was here before was saved as " + filepath.Base(res.Replaced) + "."
	}
	redirect(w, r, "/data", msg, "")
}

// handleSnapshot writes a bundle into the data directory without downloading
// it, which is the thing to do before an upgrade or a risky import.
func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	path, err := backup.SaveCurrent(s.Store.Dir(), s.Version)
	if err != nil {
		redirect(w, r, "/data", "", err.Error())
		return
	}
	redirect(w, r, "/data", "Saved a copy as "+filepath.Base(path)+" in the backups folder.", "")
}

// handleSavedBundle serves one of the bundles ENCLAVE wrote for itself.
func (s *Server) handleSavedBundle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	// The name comes from a URL, so it is checked rather than trusted.
	if name == "" || name != filepath.Base(name) || !strings.HasSuffix(name, ".zip") ||
		strings.Contains(name, "..") {
		s.fail(w, r, http.StatusBadRequest, "That is not a backup file name.")
		return
	}
	path := filepath.Join(s.Store.Dir(), backup.BackupsDir, name)
	body, err := os.ReadFile(path)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "There is no saved backup called "+name+".")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(body)
}

// reloadAll re-reads the store and both registries from disk.
func (s *Server) reloadAll() error {
	if err := s.Store.Reload(); err != nil {
		return err
	}
	if err := s.Catalogs.Reload(); err != nil {
		return err
	}
	return s.Mappings.Reload()
}
