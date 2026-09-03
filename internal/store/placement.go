package store

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/gaterunner341/enclave/internal/model"
)

// PlacementProblem names what is wrong with where an asset is filed.
type PlacementProblem string

const (
	// NoEnclave: the record names no enclave at all. Every page lists assets by
	// enclave, so an asset in this state is invisible everywhere else.
	NoEnclave PlacementProblem = "no_enclave"
	// MissingEnclave: it names an enclave that is not on file, usually because
	// the identifier was renamed or the data came from somewhere else.
	MissingEnclave PlacementProblem = "missing_enclave"
	// OutsideRanges: it is in an enclave, but none of its addresses fall in any
	// range that enclave claims. Often it belongs somewhere else.
	OutsideRanges PlacementProblem = "outside_ranges"
)

// Label describes the problem for a page.
func (p PlacementProblem) Label() string {
	switch p {
	case NoEnclave:
		return "In no enclave"
	case MissingEnclave:
		return "Enclave no longer exists"
	case OutsideRanges:
		return "Address outside its enclave"
	}
	return string(p)
}

// Orphaned reports whether the asset is invisible to the rest of the
// application, as opposed to merely being somewhere questionable.
func (p PlacementProblem) Orphaned() bool {
	return p == NoEnclave || p == MissingEnclave
}

// Placement is one asset that does not sit cleanly in an enclave.
type Placement struct {
	Asset   *model.Asset
	Problem PlacementProblem
	// Claimed is the enclave the record names, when it names one that exists.
	Claimed *model.Enclave
	// Suggested is where the asset's addresses say it belongs, if any enclave's
	// ranges contain one. It is a suggestion, not a decision: nothing is moved
	// without somebody saying so.
	Suggested *model.Enclave
	// Matched is the address that put it there.
	Matched string
}

// UnplacedAssets finds every asset that is filed nowhere, filed under an
// enclave that no longer exists, or sitting in an enclave whose address ranges
// do not contain it.
//
// The first two matter most: assets in those states appear on no page in the
// application, because every list is drawn from an enclave. Without this they
// are lost rather than merely misfiled.
func (s *Store) UnplacedAssets() []Placement {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := []Placement{}
	for _, a := range s.assets {
		p := Placement{Asset: a}
		enclave, known := s.enclaves[a.EnclaveID]

		switch {
		case strings.TrimSpace(a.EnclaveID) == "":
			p.Problem = NoEnclave
		case !known:
			p.Problem = MissingEnclave
		default:
			p.Claimed = enclave
			// An enclave that declares no ranges cannot place anything, and an
			// asset with no address cannot be placed. Neither is a problem
			// with the asset, so neither is reported as one.
			if len(enclave.Prefixes()) == 0 || len(a.IPs) == 0 {
				continue
			}
			if s.withinLocked(enclave, a.IPs) {
				continue
			}
			p.Problem = OutsideRanges
		}

		p.Suggested, p.Matched = s.suggestLocked(a.IPs)
		if p.Suggested != nil && p.Claimed != nil && p.Suggested.ID == p.Claimed.ID {
			// The suggestion agrees with where it already is, so there is
			// nothing to report.
			continue
		}
		out = append(out, p)
	}

	sort.Slice(out, func(i, j int) bool {
		// The assets nobody can see come first, because they are the ones that
		// are actually lost.
		oi, oj := out[i].Problem.Orphaned(), out[j].Problem.Orphaned()
		if oi != oj {
			return oi
		}
		return strings.ToLower(out[i].Asset.DisplayName()) < strings.ToLower(out[j].Asset.DisplayName())
	})
	return out
}

func (s *Store) withinLocked(e *model.Enclave, ips []string) bool {
	prefixes := e.Prefixes()
	for _, raw := range ips {
		ip, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		for _, p := range prefixes {
			if p.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// suggestLocked finds the enclave whose ranges most specifically contain one of
// the addresses, which is the same rule the importer places assets by.
func (s *Store) suggestLocked(ips []string) (*model.Enclave, string) {
	var best *model.Enclave
	bestBits, bestAddr := -1, ""
	for _, raw := range ips {
		ip, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		for _, e := range s.enclaves {
			for _, p := range e.Prefixes() {
				if p.Contains(ip) && p.Bits() > bestBits {
					best, bestBits, bestAddr = e, p.Bits(), raw
				}
			}
		}
	}
	return best, bestAddr
}

// OrphanCount is the number of assets that no enclave page would show, which is
// what a warning banner needs to know.
func (s *Store) OrphanCount() int {
	n := 0
	for _, p := range s.UnplacedAssets() {
		if p.Problem.Orphaned() {
			n++
		}
	}
	return n
}

// MoveAssets reassigns assets to an enclave. It is the fix for everything
// UnplacedAssets reports.
func (s *Store) MoveAssets(assetIDs []string, enclaveID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.enclaves[enclaveID]; !ok {
		return 0, fmt.Errorf("no enclave %q to move them into", enclaveID)
	}
	moved := 0
	for _, id := range assetIDs {
		a, ok := s.assets[id]
		if !ok || a.EnclaveID == enclaveID {
			continue
		}
		from := a.EnclaveID
		a.EnclaveID = enclaveID
		if err := s.putAssetLocked(a); err != nil {
			a.EnclaveID = from
			return moved, err
		}
		// The findings recorded against it belong to the same enclave, or they
		// would go on counting towards the one it left.
		for _, f := range s.findings {
			if f.AssetID == id {
				f.EnclaveID = enclaveID
			}
		}
		moved++
	}
	if moved > 0 {
		s.dirty["findings"] = true
		s.reindexLocked()
		return moved, s.saveLocked()
	}
	return 0, nil
}
