# The data folder, backups and upgrades

Everything ENCLAVE knows sits in one folder of plain files. There is no database
engine, no service and no hidden state, which is what makes moving it between
versions a matter of copying rather than migrating.

## What is in it

```
enclave-data/
  schema.json        which layout wrote this folder, and with which build
  enclaves.json      the systems being tracked
  assets.json        hosts and network devices
  scans.json         one record per imported result file
  findings.json      every scan result, with its history and decisions
  assessments.json   control implementation statements
  risks.json         the risk register
  connectors.json    links to outside systems results can be pulled from
  people.json        the directory of who holds which post
  roles.json         the posts themselves, and who holds the organisation-wide ones
  catalogs/          control frameworks you imported
  mappings/          translation tables you imported
  backups/           bundles ENCLAVE wrote for itself
```

All of it is JSON you can read, diff and put in version control. `catalogs/`
holds the frameworks in whatever format you loaded them in. `backups/` is
excluded from backups, so bundles never nest.

The folder defaults to `enclave-data` beside the executable. `--data DIR` and
the `ENCLAVE_DATA` environment variable override it.

## Backups

A backup is a single zip containing the whole folder plus a manifest:

```json
{
  "format": "enclave-backup",
  "schema": 1,
  "created": "2026-09-02T23:32:20Z",
  "created_by": "v1.2.0",
  "counts": { "enclaves": 2, "assets": 3, "findings": 9 }
}
```

Take one from the **Data** page, or with `enclave backup -o file.zip`. It is an
ordinary zip: open it and the files inside are the same readable JSON that sits
in the folder. Nothing is encrypted, so treat a bundle with the same care as the
data folder itself.

## Restoring

A restore **replaces** everything in the target folder. It is not a merge:
records that are not in the bundle are gone afterwards. Merging two data sets
means deciding what happens when both sides changed the same enclave, and
guessing at that quietly would be worse than not offering it.

Four things happen in order, and the first three can all abort without touching
anything:

1. The manifest is read. A zip that is not an ENCLAVE bundle, or one written
   against a newer schema than this build understands, is refused here.
2. The contents are unpacked into a staging folder inside the data directory.
   Archive entries that would write outside it are rejected.
3. The staged data is opened as a store. A bundle whose files do not parse is
   refused at this point, with the live data still untouched.
4. Whatever is currently there is written to `backups/` as
   `before-restore-<timestamp>.zip`, the old files are removed, and the staged
   files are moved into place.

Only then does the running server re-read the store and both registries, so a
restore takes effect without a restart.

Through the interface the restore needs the word `REPLACE` typed. On the command
line, restoring over an install that already holds records stops and asks;
`--yes` goes ahead.

## Schema versions

`schema.json` records the layout version and the build that wrote it.

| Situation | What happens |
|---|---|
| Folder is new | Stamped with the current version |
| Folder has data but no stamp | Adopted as version 1 and stamped |
| Stamp matches this build | Opened directly |
| Stamp is older than this build | Upgraded in place, then re-stamped |
| Stamp is newer than this build | Refused, naming the version that wrote it |

### The migrations so far

**2 to 3, connector settings become a list.** The first connector release stored
one console's settings as though there could only ever be one, with no name and
no way to remove it. Those settings become an entry in `connectors.json`, named
after the console it reaches, and any stored key moves with it into
`connector-credentials.json` keyed by that connector. The shapes it replaced are
deleted, the credentials file included: a secret left on disk for something
nothing reads outlives the reason anybody had it.

**1 to 2, points of contact become a directory.** Enclaves used to carry a
system owner and a security contact as free text. Those names are moved into
`people.json` and the enclaves point at them by role, so the same person named
on five systems becomes one record used five times.

Two people typed the same way become one record. Two typed differently stay
separate: guessing that "D. Rennick" and "Dave Rennick" are the same person is
not a guess a tool should make on an authorisation record. Merge them by hand on
the People page if they are.

The last row is the one that matters. Reading a layout from the future means
guessing, and a wrong guess writes back something neither version can use. So it
stops instead, and the message says to upgrade or to use a backup taken with the
version that wrote the data.

The same check runs against a bundle's manifest before a restore begins.

There are no migrations yet, because schema 1 is the first. The machinery for
them exists so that the first change to the layout is a matter of adding one
step, rather than of working out afterwards how to rescue everybody's data.

## Getting data out, rather than moving it

A backup is for moving ENCLAVE between installs. To get the contents into
something else, use the exports: `assets`, `findings`, `baseline` and `risks`
are all plain CSV from the interface or from `enclave export`, and the same
collections are available as JSON under `/api/`.
