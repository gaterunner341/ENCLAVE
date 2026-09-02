# ENCLAVE

Asset inventory and assurance for a network you are accountable for.

ENCLAVE takes the CSV exports you already have — endpoint agent, vulnerability
scanner, endpoint management, asset database, directory, address management —
and reconciles them into one record per machine. It then answers the question
those tools individually cannot: **of the machines somebody owns, how many are
actually covered by the controls that are supposed to cover them.**

It is a single executable. No installer, no database, no service account, no
outbound connection. It listens on the loopback address and stores everything
in a folder next to itself.

## Getting it

A current Windows build sits at `ENCLAVE.exe` in the root of this repository.
Download it, put it wherever you like, and double-click. Nothing to install.

Every push also builds one under the CI workflow's artifacts, and the Release
workflow can be run on demand from the Actions tab to publish a zip with a
checksum.

## Running it

```
enclaved                      # serve on 127.0.0.1:8080 and open a browser
enclaved serve --addr 127.0.0.1:9000 --no-browser
enclaved enclave add --id CORP-CORE --cidr 10.12.0.0/16 --owner "D. Rennick"
enclaved import --source falcon-prod --kind edr --map mapping.json export.csv
enclaved sources
```

`--data DIR` overrides the data directory, which defaults to `enclave-data`
beside the executable. Copy that folder to back it up; delete it to start over.

## How it works

Four ideas, and nothing else:

**Observations are append-only.** An import writes rows to a log and never
edits anything. The host view is rebuilt by replaying that log, so a wrong
import can be explained rather than merely corrected.

**Machines are merged on identifiers, transitively.** Serial numbers, hardware
UUIDs, MAC addresses and names are normalised, then any two records sharing one
are the same machine. Placeholder values that tools write for "unknown" are
rejected, because merging on those collapses an estate into one host.

**Disagreements are decided by the kind of tool, not its name.** An agent on
the box wins about the operating system; the address management system wins
about addresses; the asset database wins about who owns it. The losing value is
kept and shown on the Conflicts page, so a wrong record can be proven wrong.
Adding a second EDR needs no new configuration.

**Hosts are placed by address, longest prefix first, and a person overrides
that.** A machine whose address matches no enclave has no owner, no impact
rating and no control framework, so it appears in a claim queue rather than
quietly counting as covered.

## Controls

Four are measured out of the box, per enclave:

| Control | Met when | Target |
|---|---|---|
| EDR | An endpoint agent is installed and reporting healthy | 98% |
| Encrypted | The system disk is encrypted at rest | 95% |
| Vuln scan | Scanned for vulnerabilities within 30 days | 90% |
| Benchmark | Checked against its hardening baseline within 90 days | 85% |

Eligibility is kept separate from compliance. Network gear is not counted as
failing an endpoint agent control it could never meet, because coverage numbers
that punish the wrong hosts stop being believed.

## Layout

```
cmd/enclaved        the executable: serve, import, enclave, sources
internal/model      observations, hosts, enclaves, identifier normalisation
internal/connector  CSV in, observations out; the only place file formats live
internal/resolve    merge policy: what joins, and who wins a disagreement
internal/store      the append-only log and the small state file
internal/coverage   controls, measurement, and placement by address range
internal/web        one HTML template, a dozen routes, no client framework
```

## Building

Go 1.24 or later, no dependencies outside the standard library.

```
go test ./...
go build ./cmd/enclaved

# the shipped Windows build
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w" -o ENCLAVE.exe ./cmd/enclaved
```

## Known limits

- There is no authentication. It binds to loopback for that reason; do not put
  it on a shared host.
- Uploads are capped at 10 MB. A larger export belongs in the `import`
  subcommand on a schedule.
- Retirement is modelled but not yet exposed in the interface.
