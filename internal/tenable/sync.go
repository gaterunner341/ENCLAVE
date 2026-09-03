package tenable

import (
	"context"
	"fmt"
	"time"

	"github.com/gaterunner341/enclave/internal/importer"
	"github.com/gaterunner341/enclave/internal/ingest"
	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/store"
)

// SourceName is recorded on every import the connector makes, so a scan pulled
// from Security Center is distinguishable from a file somebody uploaded.
const SourceName = "tenable-sc"

// Syncer pulls scan results and hands them to the importer.
type Syncer struct {
	Store    *store.Store
	Importer *importer.Importer
	Client   *Client
	Config   *Connector
}

// Available lists what is on the Security Center, marking what has already been
// taken so nothing is imported twice by accident.
func (s *Syncer) Available(ctx context.Context, since time.Time) ([]ScanResult, error) {
	results, err := s.Client.ScanResults(ctx, since)
	if err != nil {
		return nil, err
	}
	for i := range results {
		if _, ok := s.Store.ScanBySourceRef(sourceRef(results[i].ID)); ok {
			results[i].Imported = true
		}
	}
	return results, nil
}

// Result reports what one import did.
type Result struct {
	ScanResult ScanResult
	Summary    *importer.Summary
	Skipped    string
}

// Import takes one scan result. A result already on file is skipped rather than
// imported again, unless the caller insists.
func (s *Syncer) Import(ctx context.Context, result ScanResult, force bool) (*Result, error) {
	out := &Result{ScanResult: result}
	if !result.Complete() {
		out.Skipped = "the scan is " + result.Status + ", so there is nothing finished to take"
		return out, nil
	}
	if !force {
		if existing, ok := s.Store.ScanBySourceRef(sourceRef(result.ID)); ok {
			out.Skipped = "already imported on " + existing.ImportedAt.Format("2 Jan 2006 15:04")
			return out, nil
		}
	}

	body, filename, err := s.Client.Download(ctx, result.ID)
	if err != nil {
		return nil, err
	}
	// The downloaded file goes through exactly the same reader as an uploaded
	// one, so there is one place where the Nessus format is understood.
	parsed, err := ingest.Parse(body, filename, ingest.CSVOptions{})
	if err != nil {
		return nil, fmt.Errorf("scan result %s (%s): %w", result.ID, result.Name, err)
	}
	parsed.Scan.SourceRef = sourceRef(result.ID)
	parsed.Scan.Tool = "Tenable Security Center"
	if result.Name != "" {
		parsed.Scan.Title = result.Name
	}
	if !result.Finished.IsZero() {
		parsed.Scan.ScanDate = result.Finished
	}
	note := "Pulled from " + s.Config.Host() + ", scan result " + result.ID
	if result.Repository != "" {
		note += ", repository " + result.Repository
	}
	parsed.Scan.Notes = note

	sum, err := s.Importer.Apply(parsed, importer.Options{
		EnclaveID:      s.Config.EnclaveID,
		PlaceByAddress: s.Config.PlaceByAddress,
		CreateAssets:   s.Config.CreateAssets,
		ImportedBy:     "Tenable Security Center connector",
		Notes:          note,
	})
	if err != nil {
		return nil, err
	}
	out.Summary = sum
	return out, nil
}

// SyncReport is what a run of everything outstanding did.
type SyncReport struct {
	Checked  int
	Imported int
	Skipped  int
	Findings int
	Assets   int
	Results  []*Result
	Errors   []string
}

// SyncAll imports every completed result that is not already on file.
func (s *Syncer) SyncAll(ctx context.Context, since time.Time, limit int) (*SyncReport, error) {
	results, err := s.Available(ctx, since)
	if err != nil {
		return nil, err
	}
	rep := &SyncReport{}
	for _, r := range results {
		if limit > 0 && rep.Imported >= limit {
			break
		}
		rep.Checked++
		if r.Imported || !r.Complete() {
			rep.Skipped++
			continue
		}
		// One bad result must not stop the rest: a console holds years of them
		// and any one can be corrupt.
		one, err := s.Import(ctx, r, false)
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s (%s): %v", r.Name, r.ID, err))
			continue
		}
		if one.Skipped != "" {
			rep.Skipped++
			continue
		}
		rep.Imported++
		rep.Findings += one.Summary.FindingsAdded + one.Summary.FindingsUpdated
		rep.Assets += one.Summary.AssetsCreated + one.Summary.AssetsMatched
		rep.Results = append(rep.Results, one)
	}
	return rep, nil
}

func sourceRef(id string) string { return SourceName + ":" + id }

// SourceRef is the exported form, for a page that wants to look one up.
func SourceRef(id string) string { return sourceRef(id) }

// FromScan reports whether an import came from this connector.
func FromScan(sc *model.Scan) bool {
	return sc != nil && len(sc.SourceRef) > len(SourceName) && sc.SourceRef[:len(SourceName)] == SourceName
}
