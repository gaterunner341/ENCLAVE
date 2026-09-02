// Command enclaved is the whole application: a local web server, a CSV
// importer and enough command line to script a collection.
//
// It listens on the loopback address only and never connects out.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pkittelson/enclave/internal/connector"
	"github.com/pkittelson/enclave/internal/coverage"
	"github.com/pkittelson/enclave/internal/model"
	"github.com/pkittelson/enclave/internal/resolve"
	"github.com/pkittelson/enclave/internal/store"
	"github.com/pkittelson/enclave/internal/web"
)

const usage = `ENCLAVE — asset inventory and assurance

  enclaved serve   [--data DIR] [--addr HOST:PORT]
  enclaved import  [--data DIR] --source ID --kind KIND --map FILE.json FILE.csv
  enclaved enclave [--data DIR] add --id ID --cidr CIDR [--name N] [--owner O] [--exposed]
  enclaved sources [--data DIR]

Source kinds drive field precedence:
  edr, endpoint_mgmt, vuln_scanner, config_scanner, cmdb, directory, ipam, netflow
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "enclaved:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// Double-clicked from a file manager there are no arguments, and serving
	// is the only thing anyone wants.
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		return serve(args)
	case "import":
		return importCSV(args)
	case "enclave":
		return enclaveCmd(args)
	case "sources":
		return sources(args)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Print(usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// defaultDataDir puts the data beside the executable, so copying that one
// folder is a complete backup and deleting it is a complete reset.
func defaultDataDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "enclave-data"
	}
	return filepath.Join(filepath.Dir(exe), "enclave-data")
}

func openStore(dir string) (*store.Store, error) {
	if dir == "" {
		dir = defaultDataDir()
	}
	return store.Open(dir)
}

func newEngine(st *store.Store) *web.Engine {
	return web.NewEngine(st, resolve.DefaultConfig(), coverage.DefaultControls())
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	data := fs.String("data", "", "data directory (default: enclave-data beside the executable)")
	addr := fs.String("addr", "127.0.0.1:8080", "address to listen on; loopback only by design")
	noBrowser := fs.Bool("no-browser", false, "do not open a browser window")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := openStore(*data)
	if err != nil {
		return err
	}
	engine := newEngine(st)
	if err := engine.Rebuild(); err != nil {
		return err
	}
	srv, err := web.NewServer(engine, st)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", *addr, err)
	}
	url := "http://" + ln.Addr().String()

	hosts, obs, _ := engine.Stats()
	fmt.Printf("\n  ENCLAVE is running at %s\n", url)
	fmt.Printf("  %d hosts from %d observations · data in %s\n\n", hosts, obs, st.Dir())
	fmt.Print("  Leave this window open. Close it to stop.\n\n")

	if !*noBrowser {
		openBrowser(url)
	}

	httpSrv := &http.Server{
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return httpSrv.Serve(ln)
}

// importCSV runs one import without the browser, for a scheduled collection.
func importCSV(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	data := fs.String("data", "", "data directory")
	source := fs.String("source", "", "source name, reused across collections from the same tool")
	kind := fs.String("kind", "", "source kind")
	mapFile := fs.String("map", "", "column mapping, as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || *kind == "" || *mapFile == "" || fs.NArg() != 1 {
		return fmt.Errorf("need --source, --kind, --map and exactly one CSV file")
	}
	if !validKind(*kind) {
		return fmt.Errorf("unknown source kind %q", *kind)
	}

	raw, err := os.ReadFile(*mapFile)
	if err != nil {
		return err
	}
	var cm connector.ColumnMap
	if err := json.Unmarshal(raw, &cm); err != nil {
		return fmt.Errorf("%s: %w", *mapFile, err)
	}
	if len(cm.Identifiers) == 0 {
		return fmt.Errorf("%s maps no identifiers; there would be nothing to merge on", *mapFile)
	}

	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()

	feed := &connector.CSV{SourceID: *source, SourceKind: *kind, Map: cm}
	obs, err := feed.Parse(f)
	if err != nil {
		return err
	}
	if len(obs) == 0 {
		return fmt.Errorf("that mapping produced no rows")
	}

	st, err := openStore(*data)
	if err != nil {
		return err
	}
	if err := st.Append(obs); err != nil {
		return err
	}
	if err := st.RecordImport(store.ImportRecord{
		At:           time.Now(),
		Filename:     filepath.Base(fs.Arg(0)),
		SourceID:     *source,
		SourceKind:   *kind,
		Observations: len(obs),
	}); err != nil {
		return err
	}

	engine := newEngine(st)
	if err := engine.Rebuild(); err != nil {
		return err
	}
	hosts, _, built := engine.Stats()
	fmt.Printf("ok hosts=%d built=%s\n", hosts, built.Format(time.RFC3339))
	return nil
}

func enclaveCmd(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return fmt.Errorf("usage: enclaved enclave add --id ID --cidr CIDR [...]")
	}
	fs := flag.NewFlagSet("enclave add", flag.ContinueOnError)
	data := fs.String("data", "", "data directory")
	id := fs.String("id", "", "identifier, for example CORP-CORE")
	cidr := fs.String("cidr", "", "address ranges, comma separated")
	name := fs.String("name", "", "human readable name")
	owner := fs.String("owner", "", "accountable owner")
	impact := fs.String("impact", "Moderate", "Low, Moderate or High")
	framework := fs.String("framework", "cis", "cis, csf, iso or nist")
	exposed := fs.Bool("exposed", false, "reachable from an untrusted network")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *id == "" || *cidr == "" {
		return fmt.Errorf("usage: enclaved enclave add --id ID --cidr CIDR [...]")
	}

	var cidrs []string
	for _, c := range strings.Split(*cidr, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		cidrs = append(cidrs, c)
	}

	st, err := openStore(*data)
	if err != nil {
		return err
	}
	err = st.PutEnclave(&model.Enclave{
		ID:        strings.ToUpper(*id),
		Name:      *name,
		CIDRs:     cidrs,
		Owner:     *owner,
		Impact:    *impact,
		Framework: *framework,
		Exposed:   *exposed,
		CreatedAt: time.Now(),
	})
	if err != nil {
		return err
	}
	fmt.Printf("ok %s %s\n", strings.ToUpper(*id), strings.Join(cidrs, ", "))
	return nil
}

// sources lists what has been imported, so a scheduled collection can be
// checked without opening a browser.
func sources(args []string) error {
	fs := flag.NewFlagSet("sources", flag.ContinueOnError)
	data := fs.String("data", "", "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	records := st.Imports()
	if len(records) == 0 {
		fmt.Println("nothing imported yet")
		return nil
	}
	for _, rec := range records {
		fmt.Printf("%-24s %s\n", rec.SourceID,
			fmt.Sprintf("%s  %s  %d rows  %s",
				rec.At.Format("2006-01-02 15:04"), rec.SourceKind, rec.Observations, rec.Filename))
	}
	return nil
}

func validKind(kind string) bool {
	for _, k := range resolve.Kinds() {
		if string(k.ID) == kind {
			return true
		}
	}
	return false
}

// openBrowser is best effort. If it fails the address is already on screen.
func openBrowser(url string) {
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
