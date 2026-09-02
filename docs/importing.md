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

## Spreadsheets

Any file with a header row. Column headings from the common exporters — Tenable,
Qualys, Rapid7 and the usual eMASS shapes — are recognised automatically, and
the detected mapping is shown for confirmation before anything is written.
Comma, tab, semicolon and pipe delimiters are all sniffed, and Excel's UTF-8
byte order mark is stripped so it does not turn the first column name into
something nothing matches.

A finding title is the only required column. Rows are grouped by asset name, so
several rows about one machine become one asset with several findings.

With no status column, every row is read as open, because a row in a
vulnerability export exists precisely because the condition was found.

A `control` column is treated as a direct citation and is filed under every
loaded framework that actually contains that identifier — a spreadsheet saying
"AC-2" does not say which framework it means, and the answer is "whichever ones
have an AC-2".

## Placing assets across enclaves

By default every asset in a file lands in the enclave you chose. Turning on
**place by address range** routes each target to the enclave whose network range
contains its address, longest prefix first, falling back to the one you chose.
That lets a single estate-wide scan populate several enclaves in one go.

## Undoing an import

Deleting an import removes every finding it produced and leaves the assets
alone. It is the correct way to undo a mistaken load.
