# How to run ENCLAVE

Nothing to install. No database, no web server, no admin rights.

---

## Where to get it

A current Windows build is committed at **`ENCLAVE.exe`** in the root of this
repository. Open it on GitHub and use the download button.

Every push to the repository also builds one, available under that run's
artifacts on the Actions tab. Tagged releases carry builds for Windows, macOS
and Linux with a `SHA256SUMS.txt`.

Building it yourself takes one command and is covered further down. To run it
on a server for a team rather than on your own machine, skip to *Hosting it
for a team* near the end, or go straight to
[docs/deploying.md](docs/deploying.md).

## Running the executable

**Windows**

1. Put `ENCLAVE.exe` anywhere you like. The Desktop is fine.
2. Double-click it.
3. A black window appears and your browser opens at <http://127.0.0.1:8080>.

Leave the black window open. Closing it stops the app.

Windows may warn that it is from an unknown publisher: **More info → Run
anyway**. That warning is because the build is unsigned, not because anything is
wrong with it.

**macOS or Linux**

```
chmod +x enclave
./enclave
```

Then open <http://127.0.0.1:8080> if it does not open by itself.

On macOS, Gatekeeper may block an unsigned binary the first time. Right-click
the file, choose **Open**, then confirm; or run
`xattr -d com.apple.quarantine ./enclave` once.

---

## If you have the source

You need Go 1.24 or later, and nothing else.

```
git clone https://github.com/gaterunner341/enclave.git
cd enclave

go run ./cmd/enclave              # start it straight away
```

or build a binary you can copy elsewhere:

```
go build -o enclave ./cmd/enclave
./enclave
```

Run the tests while you are here:

```
go test ./...
```

---

## First five minutes

The app opens on an empty overview. Do these in order.

**1. Add the people who hold posts.** Click **People**. Put in your CIO, CISO,
system owners, data owners and security officers once. Enclaves then pick from
this list rather than having names typed into them, so a name is spelled the
same everywhere and a change of post is one edit.

The roles table on the same page is yours to change. Rename them, reorder them,
add your own, remove what you do not use. A role held once for the whole
organisation, such as the CIO, is assigned there and every enclave inherits it;
one held per system, such as the System Owner, is chosen on each enclave.

**2. Create an enclave.** Click **Enclaves → New enclave**.

- Name: whatever you call the system, for example `Core Operations`
- Address ranges: one CIDR per line, optionally with a label

  ```
  10.20.0.0/16 Core
  10.20.9.0/24 Management VLAN
  ```
- Set the confidentiality, integrity and availability ratings. The overall
  categorisation is the highest of the three and it scales the risk score.

**3. Assign a baseline.** On the enclave page, pick a framework and profile from
the dropdown and click **Apply**. Start with NIST SP 800-53 Rev 5 moderate, or
CIS Controls v8 Implementation Group 2, whichever your organisation uses.

**4. Import a scan.** Click **Import**, choose your enclave, and upload whatever
you have:

- a vulnerability scan: a Nessus or ACAS export (`.nessus`)
- a spreadsheet of hosts and CVEs saved as CSV, from Tenable, Qualys, Rapid7 or
  anywhere else
- a STIG checklist (`.ckl` from STIG Viewer 2, or `.cklb` from STIG Viewer 3)
- SCAP results (`.xml`, XCCDF or ARF)

Structured files import immediately. A CSV stops at a mapping screen showing
which columns it recognised, so you can correct the guess before anything is
written.

**Adding a host, or adding compliance to one you already track.** Both are the
same upload. By default each target in the file is matched against the inventory
on serial number, then hostname, then address, and added if it is new — so
uploading a checklist for a machine ENCLAVE has never seen creates it.

When the file records a name your inventory does not use, matching fails and you
would get a duplicate. Use **Attach to one host** on the import form to pin every
result in the file to a machine you choose. The quickest way there is the
**Import results for this host** button on the host's own page, or the **Import**
link on its row in the assets list: both open the form already pinned to it. A
pinned import contributes the platform detail and the dates, and never renames
the host or touches its owner, criticality or role.

**5. Load the real CCI list.** If you imported STIG or SCAP results, this is the
step that makes the gap analysis useful. Download DISA's `U_CCI_List.xml` and
load it under **Mappings**. It replaces the small starter table that ships with
the app and re-checks every finding you have already imported.

**6. Look at the vulnerabilities.** The **Vulnerabilities** page lists every CVE
across the estate, worst first, with the hosts each one is on and how long it
has been open. To record a single CVE nobody scanned for, use **Record a
finding** on the host's own page.

**7. Look at the gap analysis.** Enclave → **Baseline**. Start with the controls
marked **Contradicted by scans**: somebody recorded those as implemented while
the scans against them are failing.

---

## Command line

The same binary does the parts that are better scripted than clicked.

```
enclave                                     serve on 127.0.0.1:8080, open a browser
enclave serve --addr 127.0.0.1:9000         a different port
enclave serve --no-browser                  do not open a browser
enclave serve --read-only                   publish results, allow no changes
enclave serve --data /path/to/dir           use a different data directory

enclave enclave list
enclave enclave add --id CORE --name "Core Operations" \
    --cidr 10.20.0.0/16 --baseline nist-800-53r5:moderate

enclave import --enclave CORE scan.ckl results.nessus
enclave import --enclave CORE --asset asset-2026...-0001 scan.ckl
enclave import --enclave CORE --place-by-address estate-wide.nessus

enclave backup -o enclave-backup.zip        write everything to one file
enclave restore enclave-backup.zip --yes   replace everything from one file

enclave export enclaves  > systems.csv        with every point of contact resolved
enclave export people    > directory.csv
enclave export findings  --enclave CORE > findings.csv
enclave export baseline  --enclave CORE > baseline.csv
enclave export assets    > assets.csv
enclave export risks     > poam.csv

enclave healthcheck                         exit 0 if a running instance answers
enclave version
```

Every serve option can come from the environment instead, which is how a
container or a systemd unit configures a process: `ENCLAVE_ADDR`,
`ENCLAVE_DATA`, `ENCLAVE_READ_ONLY`, `ENCLAVE_NO_BROWSER`. A flag on the
command line wins over the environment. A value for `ENCLAVE_READ_ONLY` that
is neither a yes nor a no is reported on stderr rather than guessed at.

There is also a read-only JSON API on the running server, at `/api/enclaves`,
`/api/assets`, `/api/findings`, `/api/risks`, `/api/scans`, `/api/catalogs` and
`/api/summary`, each accepting `?enclave=ID`.

---

## Pulling scans from Tenable Security Center

By default ENCLAVE makes no outbound connection at all, and scan results arrive
by upload. If you would rather it fetched them, click **Import** in the top
navigation: that page offers both ways in, and the connector is the second of
them. It is also linked from the footer of every page.

Add a connector, give it a name, and fill in the console's `https` address, an
API key from it, and which enclave results belong to. Add as many as you have
consoles; each can be switched on or off, and removed, on its own. Put the key
in the environment rather than on disk:

```
ENCLAVE_TENABLE_ACCESS_KEY=...
ENCLAVE_TENABLE_SECRET_KEY=...
```

Then **Test the connection**, **List what is on the console**, and take what you
want. On a schedule:

```
enclave tenable sync --since 30d
```

[docs/connectors.md](docs/connectors.md) covers certificates, credential
handling and exactly what turning it on changes.

## Moving assets between enclaves

The **Assets** page lists every host and network device on file, whichever
enclave it is in. Tick any number of them, choose a destination at the bottom,
and move them in one go. Their findings move with them, so nothing is left
counting towards the enclave they came from.

The same works from a single enclave's asset list, and the filters apply to the
selection: narrow to network devices, or to a search term, tick the header
checkbox to take everything shown, and move the lot. Shift-clicking selects a
run of rows.

Assets that ended up in no enclave at all are on **Unplaced assets**, linked from
the Enclaves page and from a warning on the overview when there are any.

## Appearance

The footer of every page has an appearance control: **Light**, **Dark**, or
**System**. System is the default and follows whatever your operating system is
set to. The choice is remembered per browser and applied on the server, so pages
render in the right colours from the first paint rather than flashing the wrong
ones first.

## Where your data lives

In a folder called `enclave-data` next to the executable.

- Back it up from the **Data** page, or by copying the folder.
- Start over by deleting it.
- Put it somewhere else with `--data DIR` or by setting `ENCLAVE_DATA`.

Inside are plain JSON files, plus `catalogs/` and `mappings/` for anything you
imported. You can read them, diff them, and put them in version control.

---

## Upgrading to a new version

Three steps, and none of them involve finding a folder.

1. In the version you are running now, open **Data** and click
   **Download a backup**. One file, everything in it.
2. Put the new build wherever you want it and start it.
3. Open its **Data** page, upload the file, type `REPLACE`, and restore.

That carries your enclaves, assets, findings, imports, control assessments and
risk entries, along with any control catalogues and mapping tables you loaded.

From a terminal it is the same two steps:

```
old-enclave backup -o enclave-backup.zip
new-enclave restore enclave-backup.zip
```

Restoring over an install that already has data asks first; add `--yes` when
you mean it. Whatever was there is written to `enclave-data/backups/` before
anything is replaced, so a restore into the wrong instance can be undone.

**Copying the whole `enclave-data` folder to the new location works too**, and
always has. The backup file exists so you do not have to know that.

### What the version stamp does

The data folder records which layout wrote it, in `schema.json`. A newer build
reads older data directly and upgrades it if the layout has changed. An older
build handed newer data refuses to open it and says which version wrote it,
rather than reading half of it and writing back something neither version can
use. The same check runs on a backup file before a single byte is written.

If you see that message, the fix is to run the newer build, or to restore a
backup taken with the version you are running.

---

## Stopping it

Close the black window, or press **Ctrl+C** in the terminal.

---

## Before you put it on a shared machine

**ENCLAVE has no login of its own.** It binds to `127.0.0.1` for that reason, so
by default only the machine it runs on can reach it.

If you bind it to anything else it prints a warning, and it is only safe behind
something that authenticates on its behalf — a reverse proxy your organisation
already runs, or an SSH tunnel:

```
ssh -L 8080:127.0.0.1:8080 you@the-server
```

`--read-only` stops every change through the interface. It is a safety catch for
publishing results, not an access control.

---

## Hosting it for a team

Everything above is one person running a binary. For an instance several people
use, there is a Docker setup in the repository:

```
cp env.example .env           # optional; every default works
docker compose up -d --build
```

It publishes on the server's own `127.0.0.1:8080` and nowhere else, so you
reach it over a tunnel until you have decided what goes in front of it. The
same problem applies as above and more sharply, because now it is a service
rather than something on your desk: ENCLAVE has no login, so a reverse proxy
has to do that job. The compose file bundles one — TLS and a password, started
with `docker compose --profile tls up -d` — for teams that would rather not
wait on infrastructure.

Useful afterwards:

```
docker compose logs -f enclave                  what it is doing
docker compose ps                               including whether it is healthy
docker compose exec enclave /usr/local/bin/enclave backup -o /data/backup.zip
docker compose cp enclave:/data/backup.zip .
docker compose down                             stop; the data volume survives
```

**[docs/deploying.md](docs/deploying.md)** is the whole guide: the three ways
to front it, every setting, backups and restores, upgrades, where connector
API keys should live, how to run a read-only instance for an auditor beside a
writable one, and what the compose file already does about hardening.
