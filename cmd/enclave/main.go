// Command enclave runs the ENCLAVE interface, and the handful of operations
// that are better done from a shell than a browser.
//
//	enclave                              serve on 127.0.0.1:8080
//	enclave serve --addr 0.0.0.0:8080    serve on every interface
//	enclave import --enclave CORE f.ckl  import without the browser
//	enclave export findings              write CSV to stdout
//	enclave enclave add --id CORE ...    create an enclave
//	enclave healthcheck                  probe a running instance and exit 0 or 1
//	enclave version
//
// Every serve option can also come from the environment, because a container
// or a unit file configures a process that way rather than by rewriting its
// command line: ENCLAVE_ADDR, ENCLAVE_DATA, ENCLAVE_READ_ONLY,
// ENCLAVE_NO_BROWSER.
package main

import (
	"bytes"
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
	"strconv"
	"strings"
	"syscall"
	"time"

	// A container image built from scratch carries no zone database, so TZ
	// would be ignored and every timestamp would read as UTC without saying
	// so. Embedding the table costs about 450 KB and makes TZ work anywhere.
	_ "time/tzdata"

	"github.com/gaterunner341/enclave/internal/backup"
	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/importer"
	"github.com/gaterunner341/enclave/internal/ingest"
	"github.com/gaterunner341/enclave/internal/mapping"
	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/store"
	"github.com/gaterunner341/enclave/internal/tenable"
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
	// Stamps written into the data directory name the build that wrote them,
	// which is the first thing worth knowing when data will not open.
	store.BuildVersion = version
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
	case "backup":
		return cmdBackup(args)
	case "restore":
		return cmdRestore(args)
	case "tenable":
		return cmdTenable(args)
	case "healthcheck":
		return cmdHealthcheck(args)
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
  enclave import --enclave ID [--asset ID] FILE...
                                              load scan results without the browser
  enclave export KIND [--enclave ID]          write assets, findings, baseline or risks as CSV
  enclave enclave add --id ID --name NAME     create an enclave
  enclave enclave list                        list enclaves
  enclave backup [-o FILE]                    write everything to one file
  enclave restore FILE                        replace everything from one file
  enclave tenable test|list|import|sync       pull scans from a Security Center
  enclave healthcheck [--addr HOST:PORT]      probe a running instance; exit 0 if healthy
  enclave version

The data directory defaults to "enclave-data" beside the executable. Copy that
folder to back everything up, or use the backup and restore commands to move it
into a new version. Delete it to start over.

Serve options also read the environment, which is how a container or a unit
file is configured: ENCLAVE_ADDR, ENCLAVE_DATA, ENCLAVE_READ_ONLY and
ENCLAVE_NO_BROWSER. A command-line flag wins over the environment.
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
	// The defaults come from the environment so that a container or a unit
	// file can configure the process the way those things configure a process.
	// A flag still wins, because the flag package only applies a default when
	// the flag is absent.
	addr := fs.String("addr", envOr("ENCLAVE_ADDR", "127.0.0.1:8080"), "address to listen on")
	dir := fs.String("data", "", "data directory")
	readOnly := fs.Bool("read-only", envBool("ENCLAVE_READ_ONLY"), "serve without allowing any change")
	noBrowser := fs.Bool("no-browser", envBool("ENCLAVE_NO_BROWSER"), "do not open a browser on start")
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
	// Whether this instance talks to anything is the first thing somebody
	// reviewing it wants to know, so it is said at startup rather than being
	// discoverable only from a page.
	if on, live := tenable.AnyEnabled(resolved); on {
		for _, c := range live {
			fmt.Printf("  connector %s at %s (outbound)\n", c.Name, c.Host())
		}
	} else {
		fmt.Println("  network   no outbound connections")
	}
	if !isLoopback(*addr) {
		fmt.Println()
		fmt.Println("  WARNING: this address is reachable from other machines and ENCLAVE has no")
		fmt.Println("  authentication of its own. Put it behind something that does, or bind to")
		fmt.Println("  127.0.0.1 and reach it over a tunnel.")
		if inContainer() {
			// Binding every interface is the only thing that works inside a
			// container, so the warning would be noise without saying where
			// the authentication is supposed to come from in that case.
			fmt.Println("  In a container this binding is correct; the proxy in front of it is what")
			fmt.Println("  has to authenticate. See docs/deploying.md.")
		}
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

// envOr reads a setting from the environment, falling back to a default. It
// exists so that the same options can be given as flags on a command line or
// as variables in a compose file, without two code paths.
func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

// envBool reads a switch from the environment. An unrecognised value is not
// quietly taken as off: a misspelled ENCLAVE_READ_ONLY that leaves an instance
// writable is exactly the kind of thing nobody notices until it matters.
func envBool(name string) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	switch strings.ToLower(raw) {
	case "":
		return false
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	fmt.Fprintf(os.Stderr, "enclave: %s=%q is not a yes or a no, so it is being read as off\n", name, raw)
	return false
}

// inContainer reports whether this looks like a containerised process. It only
// changes the wording of a warning, so a wrong answer costs nothing.
func inContainer() bool {
	if envBool("ENCLAVE_IN_CONTAINER") {
		return true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		return strings.Contains(s, "docker") || strings.Contains(s, "containerd") ||
			strings.Contains(s, "kubepods")
	}
	return false
}

// cmdHealthcheck probes a running instance and exits 0 only if it answered.
// The container image carries no shell and no curl on purpose, so the health
// check has to be the binary itself.
func cmdHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	addr := fs.String("addr", envOr("ENCLAVE_ADDR", "127.0.0.1:8080"), "address the instance is serving on")
	timeout := fs.Duration("timeout", 5*time.Second, "how long to wait for an answer")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}
	target, err := probeAddr(*addr)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get("http://" + target + "/healthz")
	if err != nil {
		return fmt.Errorf("%s did not answer: %w", target, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", target, resp.Status)
	}
	fmt.Fprintln(stdout, "ok")
	return nil
}

// probeAddr turns a listen address into one that can be dialled. An instance
// told to bind every interface reports 0.0.0.0, which is not somewhere to
// connect to, so the port is kept and the host becomes the loopback.
func probeAddr(listen string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return "", fmt.Errorf("address %q is not host:port: %w", listen, err)
	}
	switch host {
	case "", "0.0.0.0", "::", "*":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
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
	assetID := fs.String("asset", "", "attach every result to this asset, whatever the file calls the target")
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
		EnclaveID: *enclaveID, AssetID: *assetID, PlaceByAddress: *place,
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

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	dir := fs.String("data", "", "data directory")
	out := fs.String("o", "", "write here instead of standard output")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) == 1 && *out == "" {
		*out = rest[0]
	} else if len(rest) > 0 {
		return fmt.Errorf("backup takes at most one output file")
	}
	resolved, err := dataDir(*dir)
	if err != nil {
		return err
	}
	var w io.Writer = stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	man, err := backup.Write(resolved, w, version)
	if err != nil {
		return err
	}
	if *out != "" {
		fmt.Fprintf(os.Stderr, "wrote %s: %s\n", *out, man.Describe())
	}
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	dir := fs.String("data", "", "data directory")
	yes := fs.Bool("yes", false, "do not ask before replacing what is there")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("give exactly one backup file to restore")
	}
	resolved, err := dataDir(*dir)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(rest[0])
	if err != nil {
		return err
	}
	man, err := backup.Inspect(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s contains: %s\n", rest[0], man.Describe())

	// Replacing somebody's records is not something to do because a command
	// was mistyped, so it is confirmed unless the caller said not to ask.
	if !*yes {
		existing, _ := store.Open(resolved)
		if existing != nil {
			if c := existing.Counts(); c.Enclaves > 0 || c.Findings > 0 {
				fmt.Fprintf(os.Stderr,
					"%s already holds %d enclaves and %d findings, and restoring replaces all of it.\n"+
						"Re-run with --yes to go ahead.\n", resolved, c.Enclaves, c.Findings)
				return fmt.Errorf("stopped without changing anything")
			}
		}
	}
	res, err := backup.Restore(resolved, bytes.NewReader(body), int64(len(body)), version)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "restored %s into %s\n", res.Manifest.Describe(), resolved)
	if res.Replaced != "" {
		fmt.Fprintf(stdout, "what was there was saved as %s\n", res.Replaced)
	}
	return nil
}

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
			_ = w.Write([]string{e.ID, e.Name, ownerName(st, e), e.Environment,
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
			ID: slug, Name: *name, Environment: *env, Status: "Active",
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
		// A name given here goes into the directory and is assigned as System
		// Owner, so that it is the same record every other enclave would use.
		if strings.TrimSpace(*owner) != "" {
			person, err := findOrAddPerson(st, *owner)
			if err != nil {
				return err
			}
			if err := st.SetContact(e.ID, "system-owner", person.ID); err != nil {
				return err
			}
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

// pickConnector resolves which console to talk to. Naming one is only necessary
// when more than one is switched on, so the common case of a single console
// needs no flag.
func pickConnector(dir, id string) (*tenable.Connector, error) {
	if id != "" {
		c, err := tenable.GetConnector(dir, id)
		if err != nil {
			return nil, err
		}
		if !c.Enabled {
			return nil, fmt.Errorf("%s is switched off", c.Name)
		}
		return c, nil
	}
	on, live := tenable.AnyEnabled(dir)
	if !on {
		return nil, fmt.Errorf(
			"no connector is switched on; add one on the Connectors page, or in %s",
			filepath.Join(dir, tenable.ConnectorsFile))
	}
	if len(live) > 1 {
		names := []string{}
		for _, c := range live {
			names = append(names, c.ID)
		}
		return nil, fmt.Errorf("more than one connector is on; choose with --connector: %s",
			strings.Join(names, ", "))
	}
	return live[0], nil
}

// cmdTenable drives the Security Center connector, which is what to put on a
// schedule if results should arrive without somebody pressing a button.
func cmdTenable(args []string) error {
	fs := flag.NewFlagSet("tenable", flag.ContinueOnError)
	dir := fs.String("data", "", "data directory")
	since := fs.String("since", "90d", "how far back to look, for example 30d or 12h")
	limit := fs.Int("limit", 0, "stop after this many results, 0 for no limit")
	force := fs.Bool("force", false, "take a result again even if it is already on file")
	connector := fs.String("connector", "", "which connector to use; needed only when there is more than one")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("use `enclave tenable test`, `list`, `import ID...` or `sync`")
	}
	sub, ids := rest[0], rest[1:]

	resolved, err := dataDir(*dir)
	if err != nil {
		return err
	}
	// The store is opened first because that is what brings a data directory up
	// to the current schema. Resolving a connector before it would look for the
	// list in a directory that still holds the shape it replaced.
	st, cats, maps, err := open(resolved)
	if err != nil {
		return err
	}
	cfg, err := pickConnector(resolved, *connector)
	if err != nil {
		return err
	}
	creds, err := tenable.LoadCredentials(resolved, cfg.ID)
	if err != nil {
		return err
	}
	client, err := tenable.New(cfg, creds)
	if err != nil {
		return err
	}
	window, err := parseSince(*since)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout()*8)
	defer cancel()

	switch sub {
	case "test":
		desc, err := client.Test(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, desc)
		return nil
	}

	sync := &tenable.Syncer{
		Store: st, Importer: importer.New(st, cats, maps), Client: client, Config: cfg,
	}

	switch sub {
	case "list":
		results, err := sync.Available(ctx, window)
		if err != nil {
			return err
		}
		w := csv.NewWriter(stdout)
		defer w.Flush()
		_ = w.Write([]string{"id", "name", "status", "repository", "finished", "hosts", "already imported"})
		for _, r := range results {
			_ = w.Write([]string{
				r.ID, r.Name, r.Status, r.Repository, fmtDate(r.Finished),
				fmt.Sprint(r.ScannedIPs), boolWord(r.Imported),
			})
		}
		return nil

	case "import":
		if len(ids) == 0 {
			return fmt.Errorf("give at least one scan result id; `enclave tenable list` shows them")
		}
		available, err := sync.Available(ctx, time.Time{})
		if err != nil {
			return err
		}
		byID := map[string]tenable.ScanResult{}
		for _, r := range available {
			byID[r.ID] = r
		}
		for _, id := range ids {
			result, ok := byID[id]
			if !ok {
				return fmt.Errorf("scan result %s is not on the console", id)
			}
			out, err := sync.Import(ctx, result, *force)
			if err != nil {
				return err
			}
			if out.Skipped != "" {
				fmt.Fprintf(stdout, "%s (%s): skipped, %s\n", result.Name, id, out.Skipped)
				continue
			}
			fmt.Fprintf(stdout, "%s (%s): %d findings added, %d updated, %d assets created, %d matched\n",
				result.Name, id, out.Summary.FindingsAdded, out.Summary.FindingsUpdated,
				out.Summary.AssetsCreated, out.Summary.AssetsMatched)
		}
		return nil

	case "sync":
		rep, err := sync.SyncAll(ctx, window, *limit)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "checked %d, took %d, skipped %d, covering %d assets and %d findings\n",
			rep.Checked, rep.Imported, rep.Skipped, rep.Assets, rep.Findings)
		for _, e := range rep.Errors {
			fmt.Fprintln(os.Stderr, "  could not take: "+e)
		}
		if len(rep.Errors) > 0 {
			// A scheduled run should fail loudly enough for the scheduler to
			// notice, while still having taken everything it could.
			return fmt.Errorf("%d of %d results could not be taken", len(rep.Errors), rep.Checked)
		}
		return nil
	}
	return fmt.Errorf("unknown subcommand %q; use test, list, import or sync", sub)
}

// parseSince reads a window like 30d, 12h or 90m. A scheduled sync wants to ask
// for what has happened since it last ran, in the units people think in.
func parseSince(v string) (time.Time, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" || v == "all" {
		return time.Time{}, nil
	}
	if strings.HasSuffix(v, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(v, "d"))
		if err != nil || days < 0 {
			return time.Time{}, fmt.Errorf("--since %q should look like 30d, 12h or all", v)
		}
		return time.Now().AddDate(0, 0, -days), nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return time.Time{}, fmt.Errorf("--since %q should look like 30d, 12h or all", v)
	}
	return time.Now().Add(-d), nil
}

func fmtDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ownerName resolves whoever holds the System Owner role over an enclave.
func ownerName(st *store.Store, e *model.Enclave) string {
	role, ok := st.Role("system-owner")
	if !ok {
		return ""
	}
	id, _ := e.Contact(role)
	if p, ok := st.Person(id); ok {
		return p.Name
	}
	return ""
}

// findOrAddPerson reuses a directory entry with the same name rather than
// creating a second record for somebody already on file.
func findOrAddPerson(st *store.Store, name string) (*model.Person, error) {
	name = strings.TrimSpace(name)
	for _, p := range st.People() {
		if strings.EqualFold(p.Name, name) {
			return p, nil
		}
	}
	p := &model.Person{Name: name}
	if err := st.PutPerson(p); err != nil {
		return nil, err
	}
	return p, nil
}

func catalogIDs(cats *catalog.Registry) string {
	ids := []string{}
	for _, c := range cats.All() {
		ids = append(ids, c.ID)
	}
	return strings.Join(ids, ", ")
}
