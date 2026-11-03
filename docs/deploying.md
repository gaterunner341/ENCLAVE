# Running ENCLAVE on a server

Everything here is in three files at the top of the repository: `Dockerfile`,
`docker-compose.yml`, and `env.example`. The supporting pieces are in
`deploy/`.

**For an appliance that takes a pasted YAML file** — TrueNAS, Portainer,
Unraid — use [`deploy/truenas/enclave.yaml`](../deploy/truenas/enclave.yaml)
and read [truenas.md](truenas.md) instead. It is the same deployment with the
values written out and a published image rather than a build. Everything below
about settings, backups, upgrades and credentials still applies.

---

## Read this part first

**ENCLAVE has no accounts and no sign-in of its own.** Anybody who can reach
the port can read every finding and change every risk decision, and nothing
in the record will say who did it. That is a deliberate limit of a tool meant
to be copied onto a machine and run by one person, and it is the single thing
that changes when you move it to a server.

So the question a server deployment has to answer is not "how do I start it"
— that is one command — but "what sits in front of it". There are three
answers, and the compose file supports all three:

| | What it is | When it fits |
|---|---|---|
| **Loopback and a tunnel** | The default. The port is published only on the server's own `127.0.0.1`; you reach it over `ssh -L`. | One or two people, nothing new to run or maintain. The safest starting point. |
| **Your own reverse proxy** | ENCLAVE publishes on the host, your existing proxy or load balancer authenticates in front of it. | An organisation that already runs one and already has SSO, PKI, and logging there. Most federal shops are here. |
| **The bundled proxy** | A Caddy container in the compose file, opted into with `--profile tls`. TLS plus a password. | A team that wants something working this afternoon without filing a ticket. |

The default is the first one. Nothing is reachable from the network until you
change `ENCLAVE_BIND`, and the server prints a warning at startup whenever it
is bound to something other than the loopback.

---

## Quick start

```bash
git clone https://github.com/gaterunner341/enclave.git
cd enclave

cp env.example .env          # optional; every default works
docker compose up -d --build
```

Then, from your own machine:

```bash
ssh -L 8080:127.0.0.1:8080 you@server
```

and open <http://127.0.0.1:8080>.

Useful afterwards:

```bash
docker compose logs -f enclave      # what it is doing
docker compose ps                   # including whether it is healthy
docker compose restart enclave
docker compose down                 # stop; the data volume survives
```

---

## What the files are

| File | What it is for |
|---|---|
| `Dockerfile` | Builds the image. Multi-stage: compiles a static binary, then copies it onto Alpine with the certificate bundle and nothing else. There is a `test` stage too — `docker build --target test .` runs gofmt, vet and the test suite. |
| `docker-compose.yml` | The deployment. One service by default; a second under the `tls` profile. |
| `env.example` | Every setting, with the default and what it means. Copy to `.env`. |
| `deploy/Caddyfile` | The bundled proxy's configuration. Read it before you rely on it — everything that decides who gets in is in there. |
| `deploy/auth/users.conf.example` | Who may log in through that proxy. Copy to `users.conf`. |
| `deploy/certs/` | Somewhere to put a CA certificate or a server certificate from your own PKI. |
| `.dockerignore` | Keeps data, credentials and certificates out of image layers. Image layers are not secret. |

---

## Settings

All of them are optional, and all of them live in `.env` beside the compose
file. `env.example` is the full list; these are the ones that matter.

| Variable | Default | What it does |
|---|---|---|
| `ENCLAVE_BIND` | `127.0.0.1` | The host address the port is published on. `0.0.0.0` makes it reachable from the network — only do that once something authenticates in front of it. |
| `ENCLAVE_PORT` | `8080` | The host port. |
| `ENCLAVE_READ_ONLY` | `off` | `on` serves the interface but refuses every change. |
| `TZ` | `UTC` | The zone timestamps are written in. |
| `ENCLAVE_VERSION` | `docker` | Stamped into the binary and shown in the footer, so a screenshot in a report says which build produced it. Pass a git SHA or a release tag. |
| `ENCLAVE_HOSTNAME` | `localhost` | `tls` profile only: the name people type, which has to match the certificate. |

The same variables work outside Docker — the binary reads `ENCLAVE_ADDR`,
`ENCLAVE_DATA`, `ENCLAVE_READ_ONLY` and `ENCLAVE_NO_BROWSER` from the
environment, so a systemd unit configures it the same way. A command-line
flag still wins over the environment.

A note on `ENCLAVE_READ_ONLY`: a value that is neither a yes nor a no is
reported on stderr and read as off, rather than being guessed at. A
misspelled `ENCLAVE_READ_ONLY` that silently leaves an instance writable is
not a failure anyone notices until it matters.

### A read-only instance for people who only need to look

Run a second instance against a *copy* of the data for an auditor or a
programme office, so that reading a risk register cannot change one. Take the
copy first:

```bash
docker run --rm -v enclave_enclave-data:/from -v enclave-readonly:/to alpine \
  sh -c 'cp -a /from/. /to/ && chown -R 65532:65532 /to'
```

then serve it:

```bash
docker run -d --name enclave-readonly --restart unless-stopped \
  -e ENCLAVE_READ_ONLY=on \
  -v enclave-readonly:/data \
  -p 127.0.0.1:8081:8080 \
  enclave:latest
```

Every mutating route answers 403 and the interface stops offering the
controls that would use them.

Point it at a copy rather than at the live volume. Two instances sharing one
data directory is not something ENCLAVE supports: each holds its indexes in
memory, so the second one would show a stale picture and could overwrite the
first one's work on shutdown. Re-run the copy command when you want the
read-only instance refreshed.

---

## Where the data lives

Everything ENCLAVE knows — enclaves, assets, findings, scans, catalogues,
mappings, the people directory and connector credentials — is in the
`enclave_enclave-data` volume, mounted at `/data`.

**Back it up.** The tidiest way is to have ENCLAVE write a single file into
its own volume and copy that out:

```bash
docker compose exec enclave /usr/local/bin/enclave backup -o /data/enclave-backup.zip
docker compose cp enclave:/data/enclave-backup.zip ./enclave-backup-$(date +%F).zip
```

The backup deliberately leaves connector API keys out, so a bundle can be
handed to somebody without handing them a credential. The consequence is that
a restored instance has no keys until somebody enters them again.

To put one back:

```bash
docker compose cp ./enclave-backup-2026-11-03.zip enclave:/data/restore.zip
docker compose exec enclave /usr/local/bin/enclave restore /data/restore.zip
docker compose restart enclave
```

Copying the whole volume works too, and is the right thing for a
point-in-time snapshot:

```bash
docker run --rm -v enclave_enclave-data:/data -v "$PWD":/out alpine \
  tar czf /out/enclave-data.tgz -C /data .
```

### Upgrading

```bash
git pull
docker compose up -d --build
```

The data directory carries a schema version. A newer build upgrades older
data in place on the first start and says what it did in the log; an older
build refuses to open newer data rather than quietly damaging it. Take a
backup first anyway — it costs one command.

---

## Connector credentials

ENCLAVE can pull scan results from a Tenable Security Center. There are three
places those API keys can live, and the right one depends on who administers
the box.

**1. Typed into the connector page (the default).** They are written to
`/data/connector-credentials.json` at mode 0600, inside the data volume. This
is the simplest thing and it is what most people should do. The file is
excluded from backup bundles.

**2. In `enclave.env`, outside the volume.** Create that file beside the
compose file — it is read automatically if it exists, and both `.gitignore`
and `.dockerignore` already exclude it:

```
ENCLAVE_TENABLE_PROD_ACCESS_KEY=...
ENCLAVE_TENABLE_PROD_SECRET_KEY=...
```

`PROD` is the connector's id, upper-cased. The environment wins over the
stored file, and a variable named for a connector wins over the unnamed
`ENCLAVE_TENABLE_ACCESS_KEY`, so two consoles can hold different keys.

Be aware of the trade: an environment variable is visible in
`docker inspect` and in the container's `/proc`, to anybody who can reach the
Docker socket. On a box where that is a wider group than the people who
should see the key, option 1 is better, not worse.

**3. Docker secrets**, if this is on a Swarm or you are already using them.
Mount the secret and point `ENCLAVE_TENABLE_<ID>_ACCESS_KEY` at its contents
with your own entrypoint; nothing in ENCLAVE needs to change.

### A Security Center behind your own CA

Put the CA certificate in `deploy/certs/`. It is mounted read-only at
`/certs` inside the container, so a file named `securitycenter-ca.pem` is
referenced on the connector's edit page as:

```
/certs/securitycenter-ca.pem
```

Use that rather than the "skip verification" switch. Skipping verification on
a connection that carries vulnerability data about your own estate is a
finding waiting to be written about you.

---

## TLS and a password, using the bundled proxy

Two steps, then one command.

**1. Decide who may log in.** Generate a hash per person:

```bash
docker run --rm caddy:2-alpine caddy hash-password --plaintext 'the password'
```

Copy the example file and paste each result in:

```bash
cp deploy/auth/users.conf.example deploy/auth/users.conf
$EDITOR deploy/auth/users.conf
```

```
basic_auth {
	phillip   $2a$14$...
	jordan    $2a$14$...
}
```

The hashes are in a file rather than in `.env` for two reasons: a bcrypt hash
is full of dollar signs, which a compose file would try to expand into other
variables, and an environment variable would show up in `docker inspect`. The
proxy refuses to start if the file is missing, which is deliberate — there is
no accidental path to an unauthenticated instance.

**2. Name the host** in `.env`, so it matches the certificate:

```
ENCLAVE_HOSTNAME=enclave.internal.example.gov
ENCLAVE_BIND=127.0.0.1
```

Leave `ENCLAVE_BIND` on the loopback: the proxy reaches ENCLAVE over the
compose network, and the published port does not need to be open as well.

**3. Start it:**

```bash
docker compose --profile tls up -d
```

### Which certificate it uses

By default, one from Caddy's own local authority. That needs no internet
access, which is the point — it works on a closed network on the first try.
Browsers will warn until the root is trusted; export it with:

```bash
docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt .
```

For your own PKI, which is what most organisations will want: put the
certificate and key in `deploy/certs/`, then in `deploy/Caddyfile` delete the
`tls internal` line and uncomment

```
tls /etc/caddy/certs/enclave.crt /etc/caddy/certs/enclave.key
```

For a publicly resolvable name and a publicly trusted certificate, uncomment
the `email` line in the global block instead and delete `tls internal`. Caddy
will get one from Let's Encrypt, which needs inbound 80 and outbound 443.

---

## Using the reverse proxy you already have

Publish ENCLAVE on the host (`ENCLAVE_BIND=127.0.0.1` is still right if the
proxy is on the same machine) and point your proxy at it. Four things matter:

- **Authenticate.** This is the whole reason the proxy is there.
- **Raise the request body limit.** Scan exports are large; ENCLAVE accepts
  up to 128 MB per file. nginx defaults to 1 MB and will reject an import
  with a 413 that looks like an ENCLAVE bug. Set `client_max_body_size 256m;`.
- **Raise the read timeout.** A large import can take minutes.
- **Pass the host through.** ENCLAVE generates only relative links, so it
  does not need to know its own external name, but logs on your side are
  worth more with it.

nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 256m;
    proxy_read_timeout 600s;
}
```

ENCLAVE does not serve from a sub-path. Give it a hostname or a port of its
own, not `https://intranet/enclave/`.

---

## What the compose file already does about hardening

Worth knowing, because some of it will show up on a container scan and some
of it is what a reviewer will ask about.

| | Why |
|---|---|
| Runs as uid 65532, never root | Nothing in ENCLAVE needs privilege. |
| `read_only: true` on the root filesystem | The only writable places are the data volume and a 512 MB tmpfs at `/tmp`, which is where a large upload spills while it is being parsed. |
| `cap_drop: [ALL]` | It binds 8080, not a privileged port, so it needs no capabilities at all. |
| `no-new-privileges:true` | No setuid path out of the container. |
| Log rotation at 10 MB × 5 | An instance that logs steadily should not be able to fill the disk and take the records down with it. |
| Health check is the binary itself | `enclave healthcheck` probes `/healthz`, so there is no curl or wget in the image, and the check works the same if the image is ever rebased onto scratch. |
| `.dockerignore` excludes data, `.env`, credentials and certificates | An image layer is not secret. Anything copied in can be read back out by anyone who can pull the image. |

Two things it deliberately does **not** do: there is no authentication (see
the top of this file), and the container talks outbound only if you configure
a connector. The startup log says which, every time:

```
  network   no outbound connections
```

or

```
  connector Production SC at sc.example.gov (outbound)
```

### Running commands inside the container

The image has a shell, so either of these works:

```bash
docker compose exec enclave /usr/local/bin/enclave enclave list
docker compose exec enclave sh
```

`docker compose exec` runs the binary directly, so it keeps working if you
rebase the image onto something with no shell.

---

## Troubleshooting

**`docker compose ps` says the container is unhealthy.** The health check is
`enclave healthcheck`, which asks `/healthz` on the port the container is
listening on. Run it by hand to see the actual error:

```bash
docker compose exec enclave /usr/local/bin/enclave healthcheck
```

**Permission denied writing to `/data`.** The volume was created before the
image, by something that made it root-owned. Fix the ownership rather than
running as root:

```bash
docker compose down
docker run --rm -v enclave_enclave-data:/data alpine chown -R 65532:65532 /data
docker compose up -d
```

**An import returns 413, or dies partway through.** The limit is in the proxy,
not in ENCLAVE. See the body-size notes above.

**The proxy will not start.** Almost always `deploy/auth/users.conf` is
missing or has no accounts in it. `docker compose logs proxy` will say so.

**`refusing to open data written by a newer version`.** The image is older
than the data. Rebuild it (`docker compose up -d --build`) rather than
deleting anything.

**Nothing is listening on the port you expected.** `ENCLAVE_BIND` defaults to
`127.0.0.1`, so from another machine there is nothing to connect to. That is
the intended default; see the top of this file before changing it.
