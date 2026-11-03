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
or go to **Connectors** from the footer of any page, then **Add a connector**.
Connectors are a list: add as many as you have consoles, switch each on or off
independently, and remove one when it is no longer wanted. Fill in:

- a name, so a list of them reads sensibly
- the console's address, which must be `https`
- which enclave imported results belong to
- optionally, which repositories to offer, and whether to place hosts by
  address range

**Credentials.** These are per connector. The way that writes no secret to disk
is to set them in the environment ENCLAVE runs in:

```
ENCLAVE_TENABLE_ACCESS_KEY=...
ENCLAVE_TENABLE_SECRET_KEY=...
```

With more than one console, name the connector in the variable so each has its
own, for example `ENCLAVE_TENABLE_PROD_ACCESS_KEY` for a connector whose
identifier is `prod`. The connector's own variable wins over the plain one, and
either wins over anything stored.

Anything typed into the form is stored when you save the connector, in
`connector-credentials.json`, keyed by that connector. There is no separate box
to tick: typing a key in is the intent to store it. That file is written
readable only by the account ENCLAVE runs as, and it is excluded from backups,
because a bundle gets emailed and a key inside one is a key everybody who
receives it now holds. Removing a connector removes its credentials with it.

For a console too old for API keys, a username and password work through the
`/rest/token` endpoint instead.

**Certificates.** These appliances commonly present a certificate signed by an
internal authority. Point the connector at that authority's PEM bundle. There is
also a switch to skip verification entirely, named so that nobody turns it on by
accident: it accepts whatever certificate the console presents, including one an
attacker substituted.

In a container deployment, put the bundle in `deploy/certs/` beside the compose
file. It is mounted read-only at `/certs`, so a file named
`securitycenter-ca.pem` is referenced on the connector as
`/certs/securitycenter-ca.pem`. For keeping API keys out of the data volume in
that deployment, see [docs/deploying.md](deploying.md).

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
enclave tenable sync --connector prod --since 30d
```

`--connector` is needed only when more than one is switched on.

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
