# Mapping findings to controls

A STIG rule cites Control Correlation Identifiers. A Nessus plugin cites CVEs.
A CIS benchmark item cites a section number. None of those is a control
identifier, so something has to translate them before a scan result can say
anything about a control baseline.

ENCLAVE keeps that translation in tables you can read, edit and replace. It does
not invent entries. A finding whose identifiers no table recognises is reported
as unmapped, and the count is shown on the gap page, the import summary and the
Mappings page — because a large unmapped count means the tables need work, not
that the estate is clean.

## What ships with the binary

Four small tables, all visible and removable on the Mappings page:

| Table | Reads | Targets |
|---|---|---|
| CCI starter subset | CCI identifiers | NIST SP 800-53 Rev 5 |
| Unpatched vulnerabilities | any CVE | NIST SP 800-53 Rev 5 |
| Unpatched vulnerabilities | any CVE | CIS Controls v8 |
| Unpatched vulnerabilities | any CVE | NIST CSF 2.0 |

The CCI table covers the identifiers common to operating system and network
STIGs. It is **not** the authoritative list and is not meant to be.

The vulnerability tables use a `*` key, meaning "any finding that names a CVE at
all". That is how a vulnerability result reaches the flaw remediation and
vulnerability monitoring controls without a per-CVE table nobody could maintain.

## The step that matters: the real CCI list

DISA publishes the authoritative Control Correlation Identifier list as
`U_CCI_List.xml`. Load it on the Mappings page and it replaces the starter
subset, then re-checks every finding already imported, so evidence appears
without re-importing anything.

Each CCI in that file carries references into one or more revisions of
SP 800-53; ENCLAVE takes the highest revision present, because that is the one a
current STIG is written against. A reference like `AC-2 (1) (a)` becomes
`AC-2(1)`: the enhancement identifies a separately assessable control, the
statement item does not.

## Crosswalks

A crosswalk carries evidence between frameworks. Give a table the `control`
scheme and it takes a finding that already resolved to a control in one
framework and carries it into another.

This is how a STIG result reaches a CIS safeguard, or your own build standard,
without anyone maintaining a per-rule table for every framework:

```
#name,NIST 800-53 to the ACME Secure Build Standard
#scheme,control
#target,acme-secure-build

key,controls
AC-6(10),AM-1
CM-6,HD-1
CM-7,HD-2
SI-2,"HD-1,HD-4"
```

Crosswalks run after the direct tables, so the source framework has already been
resolved by the time one is consulted.

## The CSV format

Two columns: a key and the controls it maps to, comma separated within the cell.
Rows beginning with a hash set the table's metadata.

```
#name,Local decisions
#id,local-decisions
#scheme,cci
#target,nist-800-53r5
#note,Agreed with the assessor in the March review.

key,controls
CCI-001234,"AC-17(1),SC-8"
```

`scheme` is one of `cci`, `cve`, `rule`, `group`, `benchmark`, `keyword` or
`control`. A header row is optional: every key ENCLAVE maps on carries a digit
somewhere, and a column heading does not, so the first row is recognised for
what it is either way.

## How a finding is resolved

Tables are tried in order of how specific the evidence is:

1. An explicit CCI reference on the finding.
2. A control the scan itself cited.
3. A crosswalk from a framework the finding already resolved into.
4. The rule, group, benchmark section or CVE tables.
5. Title keywords, if any such table is loaded.

A finding that cites an enhancement the selected profile does not include is
recorded against that enhancement's base control rather than discarded, so the
evidence is kept.

Every control a finding reaches is shown on the finding page, with the reason it
was reached.
