# Importing scan results

ENCLAVE reads the files your tools already produce. This is what it takes from
each of them, and what it does with the result.

## The identity rules

Two decisions are made on every import, and both are worth understanding before
loading anything important.

**Which asset is this result about?** A scan record is matched against the
existing inventory on serial number first, then hostname, then IP address, in
that order, because that is the order of how reliably each one identifies a
machine across tools. Hostname matching ignores case and the domain suffix, so
`APP-SRV-01` and `app-srv-01.example.org` are the same machine. Values that
tools write when they do not know an answer — `Unknown`, `Default string`,
`To be filled by O.E.M.` and the rest — are rejected as serial numbers, because
merging on one of those collapses an estate into a single asset.

**Which finding is this?** A finding is identified by its rule and the asset it
is about. Loading the same scan again updates that row rather than adding
another: the first-seen date stays where it was, so finding age stays
meaningful, and any decision recorded against it is left alone. A finding the
scanner stops reporting closes itself, unless somebody has recorded a different
decision about it.

Nothing a person has set on an asset record is overwritten by an import. A scan
fills in blank fields and contributes addresses and a last-seen date; it does
not change the owner, the criticality or the role.

**Pinning an import to one host.** Matching is a heuristic, and it fails when a
file records a name the inventory does not use — a checklist that says
`WIN-A4F2K9` for a machine you track as `PAY-APP-PROD-01`, say. Left alone, that
creates a second record for a machine you already have.

The **Attach to one host** field on the import form, and `--asset` on the command
line, pin every result in the file to a machine you name instead. Pinning
overrides both the matching heuristic and placement by address, so a file cannot
scatter results across the inventory; a file describing several targets that is
pinned to one host says so in the import summary rather than doing it quietly. A
pinned import never renames the host it is attached to.

The quickest route is the **Import results for this host** button on a host's own
page, or the **Import** link on its row in the assets list. Both open the import
form already pinned to that machine.

## STIG checklists

Both checklist formats are read: `.ckl` from STIG Viewer 2, and `.cklb` JSON
from STIG Viewer 3.

Taken from each rule: the group and rule identifiers, the severity (including a
severity override, which wins), the status, the discussion, check and fix text,
every CCI reference, and the reviewer's own finding details and comments. A
checklist describes one target, so one import produces one asset.

CAT I maps to **high** rather than critical, so that a remote code execution
scoring 9.8 and a CAT I configuration item are not scored identically. CAT II
maps to medium and CAT III to low.

## SCAP results

XCCDF and ARF are both read. Rule definitions are collected as the document is
walked and joined to the results afterwards, so a finding carries its title,
description, check and fix text rather than a bare identifier. The `xccdf_...`
prefix chain is stripped, leaving the `SV-` identifier a person would recognise.
CCI and CVE identifiers are taken from either the rule or the result.

A file containing rules but no `TestResult` is a benchmark definition rather
than a scan, and says so rather than importing nothing silently.

## Nessus and ACAS

Results can also be pulled from a Tenable Security Center over its API rather
than exported by hand; see [connectors.md](connectors.md). What arrives that way
goes through the reader described here, unchanged.


`.nessus` exports are read as a token stream, so a several-hundred-megabyte
export from a large estate is never held in memory as a tree.

Each `ReportHost` becomes an asset. The NetBIOS name replaces a bare address
where one is present. CVEs, the CVSS score and vector are taken from the newest
scoring system the plugin carries, because that is the one your remediation
deadlines are written against.

Two kinds of result are distinguished:

- A **vulnerability** plugin becomes an open finding. Its severity comes from
  the STIG severity if the plugin carries one, then the CVSS band, then the risk
  factor. A plugin whose risk factor is `None` is informational: it is kept,
  because it is often the best inventory evidence available, but it never counts
  as open.
- A **compliance audit** result is a configuration check, not a vulnerability.
  Its own pass/fail and its own severity are authoritative, and the observed
  value is kept as the finding detail.

## Vulnerability scans and CVE lists

Three routes, depending on what you have.

**A scanner export.** Upload the `.nessus` file. Plugins become findings with
their CVEs, CVSS score and vector; compliance audit results in the same file are
read as configuration checks instead.

**A spreadsheet of hosts and CVEs.** The commonest export there is, and it
usually has no column that could be called a title:

```
Host,IP Address,CVE,Severity,CVSS,Solution,First Detected
DB-SRV-04,10.20.4.40,CVE-2024-1086,Critical,7.8,Update the kernel,2025-05-11
```

That imports as it stands. A finding needs either a title or a CVE, not both:
where there is no title the identifier becomes one, because a CVE is a complete
finding on its own. The CVE also stands in as the finding's identity, so
re-importing next month's list merges rather than duplicating.

**One CVE somebody found without a scanner.** Use **Record a finding** on the
host's page. Give it the identifier and a CVSS score and it carries the same
weight as an imported one: it reaches the same controls, ages against the same
remediation target, and appears in the same views. It is filed under an import
called "Recorded by hand", so it stays as traceable as everything else.

However it arrives, an unpatched CVE is treated as evidence about flaw
remediation and vulnerability monitoring, so it counts against the control
baseline and not only as a patch. The **Vulnerabilities** page turns the
per-host findings round the other way: one row per CVE, with every host it is
on, the worst severity and CVSS seen, how long the oldest instance has been
open, and how many are past their remediation target.

## Spreadsheets

Any file with a header row. Column headings from the common exporters — Tenable,
Qualys, Rapid7 and the usual eMASS shapes — are recognised automatically, and
the detected mapping is shown for confirmation before anything is written.
Comma, tab, semicolon and pipe delimiters are all sniffed, and Excel's UTF-8
byte order mark is stripped so it does not turn the first column name into
something nothing matches.

Either a finding title or a CVE column is required; rows are grouped by asset
name, so several rows about one machine become one asset with several findings.

With no status column, every row is read as open, because a row in a
vulnerability export exists precisely because the condition was found.

A `control` column is treated as a direct citation and is filed under every
loaded framework that actually contains that identifier — a spreadsheet saying
"AC-2" does not say which framework it means, and the answer is "whichever ones
have an AC-2".

## Assets that end up nowhere

Every list in ENCLAVE is drawn from an enclave, so an asset that is not in one
appears on no page at all. That happens when an enclave identifier is renamed
underneath its assets, when data is restored from somewhere else, or when the
files are edited by hand.

The **Unplaced assets** page, linked from the Enclaves page and from a warning on
the overview when there are any, finds three things:

- assets naming no enclave at all;
- assets naming an enclave that is not on file;
- assets whose addresses fall in none of the ranges their enclave claims, which
  usually means either the asset or the enclave's ranges are wrong.

Each one is shown with the enclave its addresses point to, if any, and can be
moved there in a click. Findings move with the asset, so they stop counting
towards the enclave it left.

An asset in a nested range is not reported. A host at 10.20.9.5 filed under an
enclave claiming 10.20.0.0/16 is inside a range that enclave claims, even if a
second enclave claims 10.20.9.0/24 as well, and either is a defensible home.

An asset with no address recorded cannot be checked either way, so it is not
reported as misplaced. The page says how many of those there are rather than
implying everything else has been verified.

## Placing assets across enclaves

By default every asset in a file lands in the enclave you chose. Turning on
**place by address range** routes each target to the enclave whose network range
contains its address, longest prefix first, falling back to the one you chose.
That lets a single estate-wide scan populate several enclaves in one go.

## Undoing an import

Deleting an import removes every finding it produced and leaves the assets
alone. It is the correct way to undo a mistaken load.
