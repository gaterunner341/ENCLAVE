# How to run ENCLAVE

ENCLAVE is a container. There is nothing to install, nothing to download and
no admin rights to ask for: you paste a YAML file into whatever runs your
containers, and open a browser at it.

---

## Start it

```yaml
services:
  enclave:
    image: ghcr.io/gaterunner341/enclave:latest
    restart: unless-stopped
    environment:
      PUID: "568"          # the user it runs as; 568 is "apps" on TrueNAS
      PGID: "568"
    ports:
      - "8080:8080"
    volumes:
      - /mnt/tank/apps/enclave:/data    # CHANGE THIS
```

Change the directory on the left of `:/data` and start it. Nothing has to be
created or chowned first — the container takes ownership of that directory
itself and then drops to `PUID:PGID`, so the server never runs as root.

- **TrueNAS**: Apps, Discover Apps, the three-dot menu, Install via YAML.
- **Portainer**: Stacks, Add stack, Web editor.
- **Unraid**: Docker, Compose, Add stack.
- **Anywhere else**: save it as `docker-compose.yml` and `docker compose up -d`.

Then open `http://your-host:8080`.

Do not use port 80 or 443 on a NAS — its own web interface is there, and the
app will fail to start with a port conflict.

The fuller file, with the hardening settings and an optional CA certificate
mount, is [`deploy/truenas/enclave.yaml`](deploy/truenas/enclave.yaml).
[docs/truenas.md](docs/truenas.md) explains each part, and
[docs/deploying.md](docs/deploying.md) covers backups, upgrades, connector
credentials and what has to sit in front of it.

---

## Before anyone else uses it

**ENCLAVE has no accounts and no sign-in.** Anyone who can reach that port can
read every finding and change every risk decision, and nothing records who did
it. On a management VLAN that may be your answer. Reachable from a user
network it is not. [docs/deploying.md](docs/deploying.md) sets out the three
ways to put something in front of it, and the repository ships one.

`ENCLAVE_READ_ONLY=on` serves the interface but refuses every change. It is a
safety catch for publishing results, not an access control.

---

## If you have the source

Go 1.24 or later, and nothing else.

```
git clone https://github.com/gaterunner341/ENCLAVE.git
cd ENCLAVE

docker compose up -d --build      # build the image and run it
go test ./...                     # the test suite
go run ./cmd/enclave              # on 127.0.0.1:8080, for development
```

`go run` is for working on ENCLAVE, not for running it: it keeps its data in
`enclave-data` in the working directory and has none of the deployment around
it.

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

The same program does the parts that are better scripted than clicked. Reach
them with `docker compose exec` — or on TrueNAS, the app's shell button.

```
docker compose exec enclave enclave enclave list
docker compose exec enclave enclave enclave add --id CORE --name "Core Operations" \
    --cidr 10.20.0.0/16 --baseline nist-800-53r5:moderate

docker compose exec enclave enclave import --enclave CORE /data/scan.ckl
docker compose exec enclave enclave import --enclave CORE --asset asset-2026...-0001 /data/scan.ckl
docker compose exec enclave enclave import --enclave CORE --place-by-address /data/estate.nessus

docker compose exec enclave enclave backup -o /data/enclave-backup.zip
docker compose exec enclave enclave restore /data/enclave-backup.zip --yes

docker compose exec enclave enclave export findings --enclave CORE > findings.csv
docker compose exec enclave enclave export enclaves > systems.csv
docker compose exec enclave enclave export people   > directory.csv
docker compose exec enclave enclave export baseline --enclave CORE > baseline.csv
docker compose exec enclave enclave export assets   > assets.csv
docker compose exec enclave enclave export risks    > poam.csv

docker compose exec enclave enclave healthcheck
docker compose exec enclave enclave version
```

The repetition is not a typo: the first `enclave` is the service, the second
is the program, and for `enclave add` the third is the subcommand.

A file to import has to be somewhere the container can see, which means the
data directory — drop it in the directory you mounted at `/data` and refer to
it as `/data/<name>`. An export goes to the terminal, so the redirection above
writes the CSV on whichever machine you ran the command from.

Serving is configured by the environment, because that is how a container is
configured: `ENCLAVE_ADDR`, `ENCLAVE_DATA`, `ENCLAVE_READ_ONLY`, and `PUID`
and `PGID` for the user it runs as. A value for `ENCLAVE_READ_ONLY` that is
neither a yes nor a no is reported on stderr rather than guessed at.

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

In the directory you mounted at `/data` — the one on the left of `:/data` in
the YAML.

- Back it up from the **Data** page, by snapshotting that directory, or with
  `enclave backup`.
- Start over by emptying it.
- Move it by pointing the YAML somewhere else.

Inside are plain JSON files, plus `catalogs/` and `mappings/` for anything you
imported. You can read them, diff them, and put them in version control.

---

## Upgrading to a new version

Pull the new image and recreate the app. The data directory stays where it is.

```
docker compose pull
docker compose up -d --force-recreate
```

On TrueNAS or Portainer that is the app's update or re-pull button.

Take a backup first — **Data**, **Download a backup**, or
`enclave backup -o /data/enclave-backup.zip` — because it costs one command
and a snapshot of the directory is not atomic while the app is running.

Moving to a different machine is the same backup file: restore it on the new
instance from its **Data** page, or with
`enclave restore /data/enclave-backup.zip`. Restoring over an instance that
already has data asks first; add `--yes` when you mean it, and whatever was
there is written to `backups/` inside the data directory first, so a restore
into the wrong instance can be undone.

**Copying the whole data directory works too**, and always has. The backup
file exists so you do not have to know that.

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

```
docker compose down
```

The data directory survives; it is outside the container. On TrueNAS or
Portainer, the app's stop button does the same thing.

---

## Running it for a team

Everything about putting it where several people can reach it —  what has to
sit in front of it, TLS and a password, settings, backups, connector
credentials, hardening — is in **[docs/deploying.md](docs/deploying.md)**.
**[docs/truenas.md](docs/truenas.md)** is the shorter one for an appliance
that takes a pasted YAML file.

Day to day:

```
docker compose logs -f enclave                  what it is doing
docker compose ps                               including whether it is healthy
docker compose exec enclave enclave backup -o /data/backup.zip
docker compose cp enclave:/data/backup.zip .
```
