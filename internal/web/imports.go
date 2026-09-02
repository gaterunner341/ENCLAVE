package web

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/importer"
	"github.com/gaterunner341/enclave/internal/ingest"
	"github.com/gaterunner341/enclave/internal/mapping"
	"github.com/gaterunner341/enclave/internal/model"
)

// readCapped reads at most limit bytes and reports a clear error rather than
// silently truncating a file, which would import half a scan.
func readCapped(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading the upload: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("the file is larger than the %d MB upload limit; import it from the command line instead", limit>>20)
	}
	return data, nil
}

func (s *Server) handleImportForm(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	enclaves := s.Store.Enclaves()
	selected := r.URL.Query().Get("enclave")
	assetID := r.URL.Query().Get("asset")
	// Arriving from an asset page pins the import to that asset, and its
	// enclave is the only one that can apply.
	if a, ok := s.Store.Asset(assetID); ok {
		selected = a.EnclaveID
	}
	s.render(w, r, "import.html", page{
		Title: "Import scan results", Nav: "import",
		Data: map[string]any{
			"Enclaves":     enclaves,
			"Selected":     selected,
			"AssetID":      assetID,
			"Assets":       s.assetsByEnclave(),
			"EnclaveNames": enclaveNames(enclaves),
			"Formats": []ingest.Format{
				ingest.FormatCKL, ingest.FormatCKLB, ingest.FormatXCCDF,
				ingest.FormatNessus, ingest.FormatCSV,
			},
		},
	})
}

// handleImportUpload reads the file and decides whether it can be applied
// immediately or needs a column mapping confirmed first. A structured format
// carries its own meaning; a spreadsheet does not, and guessing without
// showing the guess is how bad data gets in.
func (s *Server) handleImportUpload(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		redirect(w, r, "/import", "", "The upload could not be read: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		redirect(w, r, "/import", "", "Choose a scan result file to upload.")
		return
	}
	defer file.Close()
	data, err := readCapped(file, s.MaxUpload)
	if err != nil {
		redirect(w, r, "/import", "", err.Error())
		return
	}
	opts := s.importOptions(r)
	if opts.EnclaveID == "" {
		redirect(w, r, "/import", "", "Choose which enclave these results belong to.")
		return
	}

	format := ingest.Detect(data, header.Filename)
	if format == ingest.FormatCSV {
		preview, err := ingest.PreviewCSV(data, 5)
		if err != nil {
			redirect(w, r, "/import", "", "That file could not be read as a spreadsheet: "+err.Error())
			return
		}
		e, _ := s.Store.Enclave(opts.EnclaveID)
		s.render(w, r, "import_map.html", page{
			Title: "Map columns", Nav: "import", Enclave: e,
			Data: map[string]any{
				"Preview": preview, "Filename": header.Filename,
				"Fields": ingest.Fields, "Options": opts,
				"Payload":  base64.StdEncoding.EncodeToString(data),
				"Enclaves": s.Store.Enclaves(),
			},
		})
		return
	}

	res, err := ingest.Parse(data, header.Filename, ingest.CSVOptions{})
	if err != nil {
		redirect(w, r, "/import", "", "That file could not be read as "+format.Label()+": "+err.Error())
		return
	}
	s.finishImport(w, r, res, opts)
}

// handleImportConfirm applies a CSV once its column mapping is confirmed.
func (s *Server) handleImportConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	f, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	data, err := base64.StdEncoding.DecodeString(f.str("payload"))
	if err != nil {
		redirect(w, r, "/import", "", "The uploaded file was lost between pages; upload it again.")
		return
	}
	csvOpts := ingest.CSVOptions{
		Mapping:          map[ingest.Field]string{},
		DefaultAssetName: f.str("default_asset_name"),
		DefaultAssetType: model.AssetType(f.str("default_asset_type")),
		Title:            f.str("title"),
		Kind:             f.str("kind"),
	}
	for _, field := range ingest.Fields {
		if v := f.str("map_" + string(field)); v != "" {
			csvOpts.Mapping[field] = v
		}
	}
	res, err := ingest.Parse(data, f.str("filename"), csvOpts)
	if err != nil {
		redirect(w, r, "/import", "", err.Error())
		return
	}
	s.finishImport(w, r, res, s.importOptions(r))
}

func (s *Server) importOptions(r *http.Request) importer.Options {
	get := func(k string) string { return strings.TrimSpace(r.FormValue(k)) }
	return importer.Options{
		EnclaveID:          get("enclave_id"),
		AssetID:            get("asset_id"),
		PlaceByAddress:     get("place_by_address") == "on",
		CreateAssets:       get("create_assets") != "off",
		ImportedBy:         get("imported_by"),
		Notes:              get("notes"),
		DefaultCriticality: model.Criticality(get("default_criticality")),
	}
}

func (s *Server) finishImport(w http.ResponseWriter, r *http.Request, res *ingest.Result, opts importer.Options) {
	if t := strings.TrimSpace(r.FormValue("title")); t != "" {
		res.Scan.Title = t
	}
	sum, err := s.Importer.Apply(res, opts)
	if err != nil {
		redirect(w, r, "/import", "", err.Error())
		return
	}
	e, _ := s.Store.Enclave(opts.EnclaveID)
	scan, _ := s.Store.Scan(sum.ScanID)
	s.render(w, r, "import_done.html", page{
		Title: "Import complete", Nav: "import", Enclave: e,
		Data: map[string]any{
			"Summary": sum, "Scan": scan, "Result": res,
			"Enclaves":     s.enclaveIndex(),
			"MappingCount": len(s.Mappings.Sets()),
		},
	})
}

// ---------- scans ----------

func (s *Server) handleScanList(w http.ResponseWriter, r *http.Request) {
	e, ok := s.Store.Enclave(r.PathValue("id"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
		return
	}
	s.render(w, r, "scans.html", page{
		Title: "Imports · " + e.Name, Nav: "enclaves", SubNav: "scans", Enclave: e,
		Data: map[string]any{"Scans": s.Store.Scans(e.ID)},
	})
}

func (s *Server) handleScanDetail(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.Store.Scan(r.PathValue("sid"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No import with that identifier.")
		return
	}
	e, _ := s.Store.Enclave(sc.EnclaveID)
	findings := s.Store.ScanFindings(sc.ID)
	counts := map[model.Severity]int{}
	unmapped := 0
	for _, f := range findings {
		if f.Live() {
			counts[f.Severity.Normalise()]++
			if len(f.ControlRefs) == 0 {
				unmapped++
			}
		}
	}
	assets := []*model.Asset{}
	for _, id := range sc.AssetIDs {
		if a, ok := s.Store.Asset(id); ok {
			assets = append(assets, a)
		}
	}
	s.render(w, r, "scan.html", page{
		Title: sc.Title, Nav: "enclaves", SubNav: "scans", Enclave: e,
		Data: map[string]any{
			"Scan": sc, "Findings": firstN(findings, 300), "Total": len(findings),
			"Counts": counts, "Unmapped": unmapped, "Assets": assets,
			"Severity":   donut(countsBySeverity(counts), severityOrder, severityClasses),
			"AssetIndex": s.assetIndex(),
		},
	})
}

func (s *Server) handleScanDelete(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	sc, ok := s.Store.Scan(r.PathValue("sid"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No import with that identifier.")
		return
	}
	enclaveID := sc.EnclaveID
	if err := s.Store.DeleteScan(sc.ID); err != nil {
		redirect(w, r, "/scans/"+sc.ID, "", err.Error())
		return
	}
	redirect(w, r, "/enclaves/"+enclaveID+"/scans", "Removed the import and every finding it produced.", "")
}

// ---------- mappings ----------

func (s *Server) handleMappingList(w http.ResponseWriter, r *http.Request) {
	unmapped := 0
	for _, f := range s.Store.Findings("") {
		if f.Live() && len(f.ControlRefs) == 0 {
			unmapped++
		}
	}
	s.render(w, r, "mappings.html", page{
		Title: "Control mappings", Nav: "mappings",
		Data: map[string]any{
			"Sets": s.Mappings.Sets(), "Schemes": mapping.Schemes,
			"Catalogs": s.Catalogs.All(), "Unmapped": unmapped,
		},
	})
}

func (s *Server) handleMappingDetail(w http.ResponseWriter, r *http.Request) {
	set, ok := s.Mappings.Get(r.PathValue("mid"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No mapping with that identifier.")
		return
	}
	keys := sortedKeys(set.Entries)
	shown := firstN(keys, 500)
	s.render(w, r, "mapping.html", page{
		Title: set.Name, Nav: "mappings",
		Data: map[string]any{
			"Set": set, "Keys": shown, "Total": len(keys),
			"Truncated": len(keys) > len(shown),
			"Catalog":   s.Catalogs.MustGet(set.Target),
		},
	})
}

func (s *Server) handleMappingImport(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		redirect(w, r, "/mappings", "", "The upload could not be read: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		redirect(w, r, "/mappings", "", "Choose a mapping file to upload.")
		return
	}
	defer file.Close()
	data, err := readCapped(file, s.MaxUpload)
	if err != nil {
		redirect(w, r, "/mappings", "", err.Error())
		return
	}
	var set *mapping.Set
	if strings.HasSuffix(strings.ToLower(header.Filename), ".xml") {
		set, err = mapping.ParseCCIList(strings.NewReader(string(data)))
	} else {
		set, err = mapping.ParseCSV(strings.NewReader(string(data)))
	}
	if err != nil {
		redirect(w, r, "/mappings", "", "That file could not be read as a mapping: "+err.Error())
		return
	}
	if v := strings.TrimSpace(r.FormValue("name")); v != "" {
		set.Name = v
	}
	if v := strings.TrimSpace(r.FormValue("scheme")); v != "" {
		set.Scheme = mapping.Scheme(v)
	}
	if v := strings.TrimSpace(r.FormValue("target")); v != "" {
		set.Target = v
	}
	if err := s.Mappings.Add(set); err != nil {
		redirect(w, r, "/mappings", "", err.Error())
		return
	}
	n, _ := s.Importer.Reannotate("")
	redirect(w, r, "/mappings/"+set.ID, fmt.Sprintf(
		"Loaded %s with %d entries. %d findings were re-checked against it.",
		set.Name, set.Size(), n), "")
}

func (s *Server) handleMappingDelete(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	if err := s.Mappings.Remove(r.PathValue("mid")); err != nil {
		redirect(w, r, "/mappings", "", err.Error())
		return
	}
	_, _ = s.Importer.Reannotate("")
	redirect(w, r, "/mappings", "Removed the mapping and re-checked existing findings.", "")
}

func (s *Server) handleReannotate(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	start := time.Now()
	n, err := s.Importer.Reannotate(r.FormValue("enclave_id"))
	if err != nil {
		redirect(w, r, "/mappings", "", err.Error())
		return
	}
	redirect(w, r, "/mappings", fmt.Sprintf(
		"Re-checked every finding against the current mappings in %s; %d changed.",
		time.Since(start).Round(time.Millisecond), n), "")
}

// enclaveNames labels the asset picker's groups.
func enclaveNames(enclaves []*model.Enclave) map[string]string {
	out := make(map[string]string, len(enclaves))
	for _, e := range enclaves {
		out[e.ID] = e.Name
	}
	return out
}

// assetsByEnclave groups the inventory for the import form's asset picker, so
// a person can attach results to a machine they already track rather than
// hoping the file's hostname matches it.
func (s *Server) assetsByEnclave() map[string][]*model.Asset {
	out := map[string][]*model.Asset{}
	for _, a := range s.Store.AllAssets() {
		out[a.EnclaveID] = append(out[a.EnclaveID], a)
	}
	return out
}
