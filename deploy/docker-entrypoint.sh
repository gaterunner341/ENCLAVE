#!/bin/sh
# ENCLAVE's container entry point.
#
# Its only job is that nobody has to prepare anything before starting the
# container. A directory bind-mounted from a NAS arrives owned by root, or by
# whoever created the dataset, and a server running as an unprivileged user
# cannot write to it. Asking for a chown first is a deployment that fails on
# the paste, so instead: take ownership here, then drop to that user before
# serving. The process that handles requests is never root.
#
# PUID and PGID name the user to run as, the convention every NAS uses. They
# default to 65532, which is the user the image is built around.

DATA="${ENCLAVE_DATA:-/data}"
PUID="${PUID:-65532}"
PGID="${PGID:-65532}"

if [ "$(id -u)" = "0" ]; then
	mkdir -p "$DATA" 2>/dev/null || true

	# Only when it is not already right. A recursive chown over a large
	# estate on every restart would be a slow start in exchange for nothing.
	owner="$(stat -c '%u:%g' "$DATA" 2>/dev/null || echo unknown)"
	if [ "$owner" != "${PUID}:${PGID}" ]; then
		echo "enclave: taking ownership of $DATA for ${PUID}:${PGID} (was $owner)"
		# A failure here is not fatal: the directory may already be usable
		# through an ACL, and if it is not, the server says so in terms that
		# name the fix. Dying here with chown's own wording would be worse.
		chown -R "${PUID}:${PGID}" "$DATA" 2>/dev/null ||
			echo "enclave: could not change the owner of $DATA; carrying on"
	fi

	exec su-exec "${PUID}:${PGID}" /usr/local/bin/enclave "$@"
fi

# Already unprivileged, because the deployment named a user. There is nothing
# to take ownership with; if the directory cannot be written the server will
# say which chown would fix it and stop.
exec /usr/local/bin/enclave "$@"
