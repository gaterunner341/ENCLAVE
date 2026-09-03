# Pulling scans from Tenable Security Center

ENCLAVE can fetch scan results from a Security Center over its REST API rather
than somebody exporting a `.nessus` file and uploading it.

This is the only part of the tool that reaches the network. Read the section on
what it changes before turning it on.

## What it changes

With no connector configured, ENCLAVE opens no outbound socket at all. That is
most of why it is straightforward to run on a network that does not permit them,
and it is the state it ships in. The startup banner says so:

```
  network   no outbound connections
```

With the connector on, it connects to the console you name, when you press one
of the buttons on the Connectors page or run one of the commands below. It does
not poll, it does not run on a timer of its own, and it sends nothing anywhere
else. The banner changes to name the host it will reach.

## Setting it up

**On the Security Center**, create an API key for a user with access to the
repositories you want. Keys are the documented way to authenticate and need no
session.

**In ENCLAVE**, click **Import** in the top navigation and choose the connector,
or go to **Connectors** from the footer of any page. Fill in:

- the console's address, which must be `https`
- which enclave imported results belong to
- optionally, which repositories to offer, and whether to place hosts by
  address range

**Credentials.** The way that writes no secret to disk is to set them in the
environment ENCLAVE runs in:

```
ENCLAVE_TENABLE_ACCESS_KEY=...
ENCLAVE_TENABLE_SECRET_KEY=...
```

These always win over anything stored. If setting environment variables is not
practical, the page can store them in `tenable-credentials.json` in the data
directory. That file is written readable only by the account ENCLAVE runs as,
and it is deliberately excluded from backups: a bundle gets emailed, and a key
inside one is a key everybody who receives it now holds.

For a console too old for API keys, a username and password work through the
`/rest/token` endpoint instead.

**Certificates.** These appliances commonly present a certificate signed by an
internal authority. Point the connector at that authority's PEM bundle. There is
also a switch to skip verification entirely, named so that nobody turns it on by
accident: it accepts whatever certificate the console presents, including one an
attacker substituted.

## Using it

**Test the connection** makes one call and reports what it found, so a wrong
address or an untrusted certificate is caught there rather than halfway through
a download.

**List what is on the console** shows completed scans from the last ninety days,
marking the ones already taken. Tick any and take them.

**Take everything outstanding** imports every completed result that is not
already on file, up to twenty-five at a time.

From a terminal, which is what to put on a schedule:

```
enclave tenable test
enclave tenable list
enclave tenable import 101 102
enclave tenable sync --since 30d
enclave tenable sync --since 30d --limit 10
```

`sync` exits non-zero if any result could not be taken, having still taken
everything it could, so a scheduler notices.

## What it actually does

The connector fetches; it does not interpret. It asks for the same `v2` export
you would have downloaded by hand, opens the archive Security Center returns,
and hands the `.nessus` file inside to exactly the same reader an uploaded file
goes through. There is one place where the Nessus format is understood and one
set of rules about what a finding means.

Each import records where it came from: the console's host, the scan result
identifier and the repository. That identifier is how a second run knows what it
has already taken, so nothing is imported twice. Taking one again on purpose
merges with what is there rather than duplicating it, as any re-import does.

A scan that has not finished is never downloaded. A result that fails to import
does not stop the rest of the run.

## The API this uses

Four endpoints, all under `/rest`:

| Call | Purpose |
|---|---|
| `GET /system` | Test the connection and read the version |
| `POST /token` | Log in, only when using a username and password |
| `GET /scanResult` | List completed scans |
| `POST /scanResult/{id}/download` | Fetch one, as a zip holding the `.nessus` |

Authentication is the `X-APIKey` header in the form
`accessKey=<key>; secretKey=<secret>`, or the `X-SecurityCenter` token and
`TNS_SESSIONID` cookie from a password login.
