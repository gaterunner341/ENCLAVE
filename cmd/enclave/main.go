// Command enclave runs the ENCLAVE interface, and the handful of operations
// that are better done from a shell than a browser.
//
//	enclave                              serve on 127.0.0.1:8080
//	enclave serve --addr 0.0.0.0:8080    serve on every interface
//	enclave import --enclave CORE f.ckl  import without the browser
//	enclave export findings              write CSV to stdout
//	enclave enclave add --id CORE ...    create an enclave
//	enclave version
package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/importer"
	"github.com/gaterunner341/enclave/internal/ingest"
	"github.com/gaterunner341/enclave/internal/mapping"
	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/store"
	"github.com/gaterunner341/enclave/internal/web"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

// stdout is where command output goes. It is a variable so that the tests can
// read what a command produced without spawning a process.
var stdout io.Writer = os.Stdout

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "enclave: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		return cmdServe(args)
	case "import":
		return cmdImport(args)
	case "export":
		return cmdExport(args)
	case "enclave":
		return cmdEnclave(args)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "ENCLAVE "+version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ENCLAVE — track risk and control baseline gaps across the systems you own.

  enclave                                     serve on 127.0.0.1:8080 and open a browser
  enclave serve [--addr HOST:PORT] [--data DIR] [--read-only] [--no-browser]
  enclave import --enclave ID [flags] FILE... load scan results without the browser
  enclave export KIND [--enclave ID]          write assets, findings, baseline or risks as CSV
  enclave enclave add --id ID --name NAME     create an enclave
  enclave enclave list                        list enclaves
  enclave version

The data directory defaults to "enclave-data" beside the executable. Copy that
folder to back everything up; delete it to start over.
`)
}

// dataDir resolves where records are kept. Beside the executable is the right
// default for a tool that is copied onto a system and run in place.
func dataDir(flagValue string) (string, error) {
	if flagValue != "" {
		return filepath.Abs(flagValue)
	}
	if env := os.Getenv("ENCLAVE_DATA"); env != "" {
		return filepath.Abs(env)
	}
	exe, err := os.Executable()
	if err != nil {
		return filepath.Abs("enclave-data")
	}
	return filepath.Join(filepath.Dir(exe), "enclave-data"), nil
}

// open loads the store and both registries from one data directory.
func open(dir string) (*store.Store, *catalog.Registry, *mapping.Registry, error) {
	st, err := store.Open(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	cats, err := catalog.NewRegistry(filepath.Join(dir, "catalogs"))
	if err != nil {
		return nil, nil, nil, err
	}
	maps, err := mapping.NewRegistry(filepath.Join(dir, "mappings"))
	if err != nil {
		return nil, nil, nil, err
	}
	return st, cats, maps, nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "address to listen on")
	dir := fs.String("data", "", "data directory")
	readOnly := fs.Bool("read-only", false, "serve without allowing any change")
	noBrowser := fs.Bool("no-browser", false, "do not open a browser on start")
	if err := fs.Parse(args); err != nil {
		return err
	}
	resolved, err := dataDir(*dir)
	if err != nil {
		return err
	}
	st, cats, maps, err := open(resolved)
	if err != nil {
		return err
	}
	srv, err := web.New(st, cats, maps, version)
	if err != nil {
		return err
	}
	srv.ReadOnly = *readOnly

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", *addr, err)
	}
	url := "http://" + displayAddr(ln.Addr().String())

	fmt.Printf("ENCLAVE %s\n", version)
	fmt.Printf("  data      %s\n", resolved)
	fmt.Printf("  catalogs  %d loaded\n", len(cats.All()))
	fmt.Printf("  listening %s\n", url)
	if *readOnly {
		fmt.Println("  mode      read only")
	}
	if !isLoopback(*addr) {
		fmt.Println()
		fmt.Println("  WARNING: this address is reachable from other machines and ENCLAVE has no")
		fmt.Println("  authentication of its own. Put it behind something that does, or bind to")
		fmt.Println("  127.0.0.1 and reach it over a tunnel.")
	}
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop.")

	if !*noBrowser && isLoopback(*addr) {
		go openBrowser(url)
	}

	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		// Uploads of a large scan export can legitimately take a while, so the
		// write timeout is generous rather than absent.
		WriteTimeout: 10 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-done:
		fmt.Println("\nStopping.")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		return st.Save()
	}
}

func displayAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return "127.0.0.1:" + port
	}
	return net.JoinHostPort(host, port)
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" || host == "" {
		return host == "localhost"
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func openBrowser(url string) {
	time.Sleep(300 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	dir := fs.String("data", "", "data directory")
	enclaveID := fs.String("enclave", "", "enclave the results belong to (required)")
	by := fs.String("by", "", "who is importing")
	notes := fs.String("notes", "", "note recorded against the import")
	place := fs.Bool("place-by-address", false, "route assets to the enclave whose range matches")
	noCreate := fs.Bool("no-create-assets", false, "skip results about assets not already in the inventory")
	crit := fs.String("criticality", "moderate", "criticality for assets the import creates")
	files, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if *enclaveID == "" {
		return fmt.Errorf("--enclave is required; run `enclave enclave list` to see them")
	}
	if len(files) == 0 {
		return fmt.Errorf("give at least one file to import")
	}
	resolved, err := dataDir(*dir)
	if err != nil {
		return err
	}
	st, cats, maps, err := open(resolved)
	if err != nil {
		return err
	}
	im := importer.New(st, cats, maps)
	opts := importer.Options{
		EnclaveID: *enclaveID, PlaceByAddress: *place,
		CreateAssets: !*noCreate, ImportedBy: *by, Notes: *notes,
		DefaultCriticality: model.Criticality(*crit),
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		res, err := ingest.Parse(data, filepath.Base(path), ingest.CSVOptions{})
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		sum, err := im.Apply(res, opts)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Fprintf(stdout, "%s: %d findings added, %d updated, %d assets created, %d matched",
			filepath.Base(path), sum.FindingsAdded, sum.FindingsUpdated,
			sum.AssetsCreated, sum.AssetsMatched)
		if sum.Unmapped > 0 {
			fmt.Fprintf(stdout, ", %d unmapped", sum.Unmapped)
		}
		fmt.Fprintln(stdout)
		for _, warn := range sum.Warnings {
			fmt.Fprintln(stdout, "  warning: "+warn)
		}
	}
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	dir := fs.String("data", "", "data directory")
	enclaveID := fs.String("enclave", "", "limit to one enclave")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	kind := "findings"
	switch len(rest) {
	case 0:
	case 1:
		kind = rest[0]
	default:
		return fmt.Errorf("export takes one kind, got %s", strings.Join(rest, " "))
	}
	resolved, err := dataDir(*dir)
	if err != nil {
		return err
	}
	st, cats, maps, err := open(resolved)
	if err != nil {
		return err
	}
	srv, err := web.New(st, cats, maps, version)
	if err != nil {
		return err
	}
	// The CSV writers live with the handlers, so the command borrows them
	// rather than keeping a second copy that could drift.
	req, _ := http.NewRequest("GET", "/export/"+kind+"?enclave="+url.QueryEscape(*enclaveID), nil)
	req.SetPathValue("kind", kind)
	rec := &stdoutRecorder{}
	srv.ExportCSV(rec, req)
	if rec.status >= 400 {
		return fmt.Errorf("nothing is exported under %q; use assets, findings, baseline or risks", kind)
	}
	return nil
}

// stdoutRecorder is an http.ResponseWriter that writes the body to stdout,
// which is what makes the export handler usable from the command line.
type stdoutRecorder struct {
	header http.Header
	status int
}

func (w *stdoutRecorder) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}
func (w *stdoutRecorder) Write(b []byte) (int, error) { return stdout.Write(b) }
func (w *stdoutRecorder) WriteHeader(code int)        { w.status = code }

func cmdEnclave(args []string) error {
	fs := flag.NewFlagSet("enclave", flag.ContinueOnError)
	dir := fs.String("data", "", "data directory")
	id := fs.String("id", "", "identifier")
	name := fs.String("name", "", "name")
	owner := fs.String("owner", "", "system owner")
	env := fs.String("environment", "Production", "environment")
	conf := fs.String("confidentiality", "moderate", "confidentiality impact")
	integ := fs.String("integrity", "moderate", "integrity impact")
	avail := fs.String("availability", "moderate", "availability impact")
	cidrs := fs.String("cidr", "", "comma separated address ranges")
	baseline := fs.String("baseline", "", "catalog id to assign, optionally catalog:profile")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("use `enclave enclave add` or `enclave enclave list`")
	}
	sub := rest[0]
	resolved, err := dataDir(*dir)
	if err != nil {
		return err
	}
	st, cats, _, err := open(resolved)
	if err != nil {
		return err
	}

	switch sub {
	case "list":
		w := csv.NewWriter(stdout)
		defer w.Flush()
		_ = w.Write([]string{"id", "name", "owner", "environment", "categorisation", "networks", "assets"})
		for _, e := range st.Enclaves() {
			ranges := []string{}
			for _, n := range e.Networks {
				ranges = append(ranges, n.CIDR)
			}
			_ = w.Write([]string{e.ID, e.Name, e.Owner, e.Environment,
				e.Categorization().Label(), strings.Join(ranges, " "),
				fmt.Sprint(len(st.Assets(e.ID)))})
		}
		return nil

	case "add":
		if *name == "" {
			return fmt.Errorf("--name is required")
		}
		slug := model.SlugID(*id)
		if slug == "" {
			slug = model.SlugID(*name)
		}
		e := &model.Enclave{
			ID: slug, Name: *name, Owner: *owner, Environment: *env, Status: "Active",
			Confidentiality: model.Impact(*conf).Normalise(),
			Integrity:       model.Impact(*integ).Normalise(),
			Availability:    model.Impact(*avail).Normalise(),
		}
		for _, c := range strings.Split(*cidrs, ",") {
			if c = strings.TrimSpace(c); c != "" {
				e.Networks = append(e.Networks, model.Network{CIDR: c})
			}
		}
		if *baseline != "" {
			catID, profile, _ := strings.Cut(*baseline, ":")
			if _, ok := cats.Get(catID); !ok {
				return fmt.Errorf("no catalog %q; loaded: %s", catID, catalogIDs(cats))
			}
			e.Baselines = append(e.Baselines, model.BaselineRef{
				CatalogID: catID, ProfileID: profile, AddedAt: time.Now().UTC(),
			})
		}
		if err := st.PutEnclave(e); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "created enclave %s (%s)\n", e.ID, e.Name)
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

// parseFlags parses args into fs and returns the positional arguments,
// wherever they appear among the flags.
//
// Go's flag package stops at the first positional argument, so
// `export findings --data DIR` would otherwise ignore --data entirely. Parsing
// repeatedly and collecting what is left each time gets the whole command line
// without having to guess which flags take a value: the flag set already knows.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
}

func catalogIDs(cats *catalog.Registry) string {
	ids := []string{}
	for _, c := range cats.All() {
		ids = append(ids, c.ID)
	}
	return strings.Join(ids, ", ")
}
