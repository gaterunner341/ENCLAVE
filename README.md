# ENCLAVE

Track risk and control baseline gaps across the systems you are accountable for.

ENCLAVE inventories your enclaves, the hosts and network devices inside them,
and the scan results you already produce. It reconciles those results against a
control baseline and answers the question the scanners cannot: **of the controls
you are supposed to be meeting, which ones are you actually meeting, and how do
you know?**

It is a single executable with no dependencies outside the Go standard library.
No installer, no database engine, no service account, and no outbound connection
unless you configure one.

## Get it

A current Windows build sits at **[`ENCLAVE.exe`](ENCLAVE.exe)** in the root of
this repository. Download it, put it anywhere, and double-click. Nothing to
install.

Every push also builds one under the CI workflow's artifacts, and the Release
workflow publishes builds for Windows, macOS and Linux with checksums.

## Run it

No installer, no database, no admin rights.

```
ENCLAVE.exe                   # on Windows, or just double-click it
./enclave                     # a built binary on macOS or Linux
go run ./cmd/enclave          # from source
```

It serves on <http://127.0.0.1:8080> and opens a browser. Press Ctrl+C to stop.
Your data lands in `enclave-data` next to the executable.

**[RUN.md](RUN.md) has the full walkthrough**: installing, the first five
minutes, every command line flag, where the data lives, and what to do before
putting it on a shared machine.

## What it does

**Enclaves.** A bounded system: whatever your organisation calls an
authorisation boundary, a site, or a mission network. Each carries its owner,
its impact categorisation, the address ranges it owns, and the control baselines
it is held to.

**Assets.** Hosts and network devices in one record, because they share almost
every field that matters to risk. The asset type is what stops a switch being
measured against a control only a workstation could ever meet.

**Scan results.** STIG checklists (`.ckl` and `.cklb`), SCAP results (XCCDF and
ARF), Nessus and ACAS exports including compliance audits, and any spreadsheet
you can map columns for. A finding is identified by its rule and the asset it is
about, so re-importing next month's scan updates the rows rather than duplicating
them: the first-seen date stays, finding age stays meaningful, and any decision
you recorded is left alone.

Uploading a checklist for a machine ENCLAVE has never seen adds it. Uploading one
for a machine you already track attaches the compliance to it: results are matched
on serial number, then hostname, then address, and when the file records a name
your inventory does not use you can pin the import to the host you mean, from a
button on that host's own page.

**Control baselines.** NIST SP 800-53 Rev 5 with its low, moderate and high
baselines; the CIS Critical Security Controls v8 with its three Implementation
Groups; and NIST CSF 2.0. All three are built in. Your own framework loads from
OSCAL, a CSV, or a short plain-text format, and an import that reuses a built-in
identifier replaces it.

**Gap analysis.** For every control in the selected baseline, ENCLAVE reconciles
what somebody claimed with what the scans found:

| State | Means |
|---|---|
| Contradicted by scans | Claimed implemented, and scan results against it are failing |
| Failing | Not claimed, and scan results are failing |
| Not implemented | Assessed as not implemented |
| Not assessed | Nobody has said anything about it |
| Partial or planned | Acknowledged as incomplete |
| Claimed, no evidence | Claimed implemented, nothing here confirms or refutes it |
| Satisfied | Claimed implemented, and scan results pass |

**Contradicted** is the state the tool exists to produce. No document review
finds it, because on paper the control is fine.

**People.** A directory of who holds which post, recorded once. Enclaves point at
those records rather than carrying typed-in names, so a change of post is one
edit. Roles are yours to define: rename them, reorder them, add your own. A role
held once for the organisation, such as the Chief Information Officer, is
assigned there and inherited by every enclave; one held per system, such as the
System Owner, is chosen on each. Exports carry the resolved names, not
identifiers.

**Assets in bulk.** The estate-wide asset list crosses enclaves, so moving a set
of hosts from one to another is one job rather than one per enclave. Selections
survive the filters, findings move with the assets, and anything that ended up
in no enclave at all is found on its own page rather than being lost.

**Vulnerabilities.** Findings are recorded per host, which is right for fixing
them. The Vulnerabilities page turns that round: one row per CVE, every host it
is on, the worst severity and CVSS seen, the age of the oldest instance and how
many are past their remediation target. Scanner exports, plain CVE spreadsheets
and a form for typing one in by hand all feed it, and an unpatched CVE counts as
evidence against the flaw remediation controls rather than only as a patch.

**Risk.** A finding's weight comes from its severity, the criticality of the
asset it is on, the enclave's impact categorisation, whether a decision has been
recorded about it, and how far past its remediation target it is. Enclave scores
normalise by asset count so a twelve-host enclave and a four-hundred-host one
can sit in the same table. Alongside that is a risk register for the things that
need a plan rather than a patch.

## Running it

```
enclave                                    serve on 127.0.0.1:8080, open a browser
enclave serve --addr 127.0.0.1:9000 --no-browser
enclave serve --read-only                  publish results without allowing changes
enclave enclave add --id CORE --name "Core Operations" \
    --cidr 10.20.0.0/16 --baseline nist-800-53r5:moderate
enclave import --enclave CORE scan.ckl results.nessus
enclave export findings --enclave CORE > findings.csv
```

`--data DIR` overrides the data directory, which defaults to `enclave-data`
beside the executable and can also be set with `ENCLAVE_DATA`. Copy that folder
to back everything up; delete it to start over.

## Getting started

1. **Create an enclave** and give it the address ranges it owns. Ranges may
   nest; an imported asset lands in the enclave whose range matches it most
   specifically, so a management VLAN carved out of a site range wins over the
   site.
2. **Assign a baseline.** Pick a framework and a profile. Findings already
   imported are mapped against it immediately, so the gap page is populated
   without re-importing anything.
3. **Import a scan.** Structured formats apply straight away. A spreadsheet
   stops at a mapping screen showing what was detected from your column
   headings, so you can see the guess before anything is written.
4. **Load the CCI list.** For STIG and SCAP results this is the step that
   matters. See below.
5. **Assess controls** as you go. The gap page shows where the assessment and
   the scans disagree.

## Mapping findings to controls

A STIG rule cites Control Correlation Identifiers. A Nessus plugin cites CVEs.
A benchmark item cites a section number. None of those is a control identifier,
so ENCLAVE keeps translation tables and does not invent entries: anything a
table cannot translate is reported as unmapped rather than attributed to a
control it might not belong to.

Four small tables ship with the binary, including a starter subset of the CCI
list covering the identifiers common to operating system and network STIGs. It
is **not** the authoritative list. Download DISA's `U_CCI_List.xml` and load it
on the Mappings page; it replaces the subset and re-checks every finding already
imported.

A **crosswalk** table is what carries evidence between frameworks. Give it a
`control` scheme and it takes a finding that already resolved to a control in
one framework and carries it into another, which is how a STIG result reaches a
CIS safeguard, or your own build standard, without a per-rule table nobody could
maintain.

## Your own control framework

The plain-text catalogue format reviews as a readable diff rather than a wall of
braces:

```
@id       acme-secure-build
@name     ACME Secure Build Standard
@version  2026.1
@profile  core = Core requirements
@profile  ext  = Extended requirements
@family   HD   = Hardening

HD-1    | Approved base image only    | core,ext
HD-1(1) | Base image rebuilt monthly  | ext
HD-2    | Unused services removed     | core,ext
```

A CSV with `id` and `title` columns works too, as does an OSCAL catalog in JSON.

## Connectors

ENCLAVE makes no outbound connection unless you configure one, which is the
state it ships in and what the startup banner reports. A Tenable Security Center
connector can fetch completed scan results over the REST API instead of somebody
exporting files: it authenticates with an API key, downloads the same `v2`
export you would have taken by hand, and hands it to the same reader an uploaded
file goes through. It records which result it took so nothing is imported twice,
and credentials are kept out of backups.

See [docs/connectors.md](docs/connectors.md).

## Upgrading

Open **Data**, click **Download a backup**, start the new build, and restore the
file on its Data page. That carries the enclaves, assets, findings, imports,
control assessments and risk entries, along with any catalogues and mapping
tables you loaded. On a terminal it is `enclave backup -o file.zip` and then
`enclave restore file.zip`.

The data folder records which layout wrote it. A newer build reads older data
and upgrades it; an older build handed newer data refuses and says which version
wrote it, rather than reading half of it. The same check runs on a backup file
before anything is written, and whatever a restore replaces is saved to
`enclave-data/backups/` first.

## Documentation

- **[RUN.md](RUN.md)** — how to run it, the first five minutes, every command
- [docs/importing.md](docs/importing.md) — what is read from each file format, and the asset and finding identity rules
- [docs/mappings.md](docs/mappings.md) — how findings reach controls, the CCI list, crosswalks between frameworks
- [docs/risk-scoring.md](docs/risk-scoring.md) — exactly how the numbers are produced, and what they are not
- [docs/data.md](docs/data.md) — the data folder, backups, restores and schema versions
- [docs/connectors.md](docs/connectors.md) — pulling scans from Tenable Security Center, and what that changes

## Layout

```
cmd/enclave         the executable: serve, import, export, enclave
internal/model      the domain: enclaves, assets, findings, assessments, risk
internal/catalog    control frameworks, their profiles, and how they load
internal/store      persistence: JSON files, in-memory indexes, atomic writes
internal/ingest     file formats in, findings out; the only place they live
internal/mapping    findings to control identifiers, and nothing invented
internal/importer   applying a parsed result: asset matching, control mapping
internal/risk       scoring and the gap analysis
internal/web        the interface: handlers, templates, one stylesheet
```

## Building

Go 1.24 or later. No dependencies outside the standard library.

```
go test ./...
go build ./cmd/enclave

# a Windows build to hand to somebody
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o ENCLAVE.exe ./cmd/enclave
```

## Known limits

- **There is no authentication.** It binds to loopback for that reason. Binding
  it anywhere else prints a warning and is only safe behind something that does
  authenticate. `--read-only` disables every write but is not an access control.
- Uploads through the browser are capped at 128 MB. A larger export belongs in
  the `import` subcommand.
- Records are held in memory and written as JSON. That is comfortable into the
  low hundreds of thousands of findings and is not the right shape for millions.
- The built-in 800-53 catalogue covers every base control and the enhancements
  the baselines select. It is a working copy, not the authoritative one; import
  the OSCAL release for an authorisation package.
