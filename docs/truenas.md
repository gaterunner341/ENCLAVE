# ENCLAVE as a YAML app

The paste-ready file is [`deploy/truenas/enclave.yaml`](../deploy/truenas/enclave.yaml).
It is ordinary Docker Compose, so it works anywhere that takes a compose file:
TrueNAS, Portainer, Unraid, Synology, or `docker compose up -d` on a plain box.

It differs from the [`docker-compose.yml`](../docker-compose.yml) at the root
of the repository in three ways, all of them because an appliance pastes YAML
into a box rather than cloning a repository:

- it pulls a published image instead of building one,
- every value is written out, because there is no `.env` to read,
- the data directory is a path you choose rather than a Docker volume, so it
  can be snapshotted and replicated with everything else on the machine.

---

## Before you paste it

**Make the directory and give it to the right user.** This is the one step
that, skipped, stops the app. It exits, and with `restart: unless-stopped` it
does that on a loop, which from the outside looks like an app that will not
start. It now says so in the log in as many words — `cannot write to the data
directory`, and the `chown` to run — so if the app is stopping, read the log
before anything else.

```bash
mkdir -p /mnt/tank/apps/enclave
chown -R 568:568 /mnt/tank/apps/enclave
```

`568` is the `apps` user on TrueNAS, and `user: "568:568"` in the YAML is what
makes ENCLAVE run as it. Delete that line and it runs as `65532`, the user
built into the image, and the directory has to be owned by that instead.
Either works. They have to agree.

**Pick a port that is free.** The YAML uses `8080`. Do not use `80` or `443` on
a NAS — its own web interface is there, and the app will fail to start.

**Change the two marked lines**: the path on the left of `:/data`, and the
user, if you are not using `568`.

---

## The image

```
ghcr.io/gaterunner341/enclave:latest
```

Published from `main` by the [Container image](../.github/workflows/image.yml)
workflow, which smoke-tests the image before pushing it, so a broken build
cannot become the `latest` something pulls overnight. `:sha-xxxxxxxx` pins an
exact build and `:vN.N.N` a release.

It is public, so nothing has to be logged in to pull it.

If a package of your own ever does need its visibility changed, that setting
is on your profile rather than on the repository — a package only appears in
the repository sidebar once it has been linked to one:

```
https://github.com/users/YOUR_GITHUB_USERNAME/packages/container/PACKAGE/settings
```

### Or build it yourself

Nothing has to be published at all. On a machine with Docker and a checkout:

```bash
git clone https://github.com/gaterunner341/ENCLAVE.git
cd ENCLAVE
docker build -t enclave:local .
```

then use `image: enclave:local` in the YAML. To move it to a machine that
cannot build:

```bash
docker save enclave:local | gzip > enclave.tar.gz
# copy it across, then on the other machine:
gunzip -c enclave.tar.gz | docker load
```

---

## Afterwards

Open `http://your-host:8080`.

**If the browser says `ERR_SSL_PROTOCOL_ERROR` or "can't provide a secure
connection", the app is running** — something answered, or you would have got
a refused connection. The browser is speaking TLS to a server that speaks
plain HTTP.

It is usually HSTS, and the trap is that **HSTS applies to a whole host, not
to one port**. A NAS web interface on 443 sends that header, so after visiting
it the browser forces HTTPS on every port of that address, 8080 included.
Typing `http://` does not get around it. In Chrome, clear it at
`chrome://net-internals/#hsts` under *Delete domain security policies*, with
just the host (`192.168.1.120`, no port). Firefox: forget the site from
history.

It will keep happening to everyone who has visited the appliance's own
interface, which is the practical argument for putting the TLS proxy in front
of ENCLAVE rather than fighting browsers one at a time.

**Back it up.** The data directory is plain files, so a snapshot of the dataset
is a complete backup. For something you can hand to somebody, have ENCLAVE
write one file:

```bash
docker exec enclave /usr/local/bin/enclave backup -o /data/enclave-backup.zip
```

It lands in the data directory, where the host can see it directly. Connector
API keys are deliberately left out, so a bundle can be shared without sharing a
credential.

**Upgrade** by pulling the image again and recreating the app. The data
directory carries a schema version: a newer build upgrades older data in place
on the first start and says what it did in the log, and an older build refuses
to open newer data rather than quietly damaging it.

**A Security Center behind your own CA**: make a second directory, put the CA
certificate in it, and uncomment the `/certs` mount in the YAML. The connector
then references it as `/certs/<filename>`.

---

## The part that is not solved by a YAML file

ENCLAVE has no accounts and no sign-in. Anyone who can reach port 8080 can read
every finding and change every risk decision, and nothing in the record will say
who did it. On a management VLAN that may be an acceptable answer. Reachable
from a user network it is not.

[deploying.md](deploying.md) sets out the three ways to put something in front
of it. On an appliance the two that fit are: your existing reverse proxy, or
the bundled one, which needs two files on disk and so is a clone-the-repository
deployment rather than a paste-one-file deployment.

Whichever you pick, the port ENCLAVE itself is on should not be reachable from
anywhere but the proxy once you have one.
