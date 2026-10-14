# RAWGRAVEL Docker deployment

Host: `root@server.example.com`
Compose project: `/opt/various/rawgravel`
Website: https://wallet.example.com
Container: `rawgravel`

The Node server runs on port 3000 inside the existing external Docker network `public24`. There is no published host port. Traefik terminates HTTPS on `websecure` and requests the certificate using the existing `lealpn` resolver.

Signing settings are stored in `/opt/various/rawgravel/secrets/wallet.json`, owned by root with group 1000 and mode 0640. The secrets directory has mode 0700. Compose mounts this file read-only at `/run/secrets/wallet.json`. The Node process runs as UID/GID 1000. The private key is not part of the image or source tree.

The generator is publicly accessible at the user's request (`PUBLIC_ACCESS=true`). It signs freely entered membership details; it does not validate eligibility against a membership database. No application-level membership data storage or automatic pass updates are implemented.

## Operations

From `/opt/various/rawgravel`:

```sh
docker compose ps
docker compose logs --tail 50 rawgravel
docker compose up -d --build
```

`/healthz` reports process health; `/api/status` reports whether signing settings are present. Verify a pass download after changing signing certificates.

## Updates

Build the worker bundle locally with `npm run build`; transfer `Dockerfile`, `.dockerignore`, `compose.yaml`, `worker/index.js`, and `scripts/server.mjs`. Preserve the server's `secrets/` directory. Rebuild the image and recreate this Compose service. Certificate renewals for HTTPS are managed by the existing Traefik resolver. Renew the separate Apple signing certificate before its expiration and replace `secrets/wallet.json` securely.
