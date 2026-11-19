# Public demo on Cloudflare Containers

This folder deploys a read-only Kavlotryx demo to [Cloudflare Containers](https://developers.cloudflare.com/containers/). A small Worker sends every request to one container that runs the image from `deploy/Dockerfile.demo`.

What visitors get:

- The full console, signed in automatically as a **viewer**. Every change is blocked: pipeline runs, overrides, triage, notes, uploads, settings and connector syncs. A banner says it's a demo.
- Sample data seeded when the image is built: the three-day Prowler, Trivy and Wiz story from DefectDojo's public test files, a made-up DefectDojo export, the Microsoft Graph, LeanIX and ServiceNow CMDB snapshots, CISA KEV and FIRST EPSS entries for the sample CVEs, and a few triage decisions.
- A fresh copy of that data whenever the container wakes up. After 10 minutes without requests the container sleeps, and the next visitor starts it again, which takes about 10–15 seconds.

The REST API stays closed to anonymous callers.

## What you need

- A Cloudflare account on the **Workers Paid** plan. Containers aren't available on the free plan.
- **Node.js 22.12 or newer.** Wrangler 4 refuses to run on older versions. Check with `node --version`, and upgrade with `brew upgrade node` or a version manager such as nvm.
- **Docker with Buildx**, because Wrangler builds the image locally before it uploads it. With colima on macOS:

  ```bash
  brew install docker-buildx
  mkdir -p ~/.docker && echo '{"cliPluginsExtraDirs": ["/usr/local/lib/docker/cli-plugins"]}' > ~/.docker/config.json
  colima start
  docker buildx version
  ```

  On Apple silicon, Homebrew installs into `/opt/homebrew`, so use `/opt/homebrew/lib/docker/cli-plugins` instead. If `~/.docker/config.json` already exists, add the `cliPluginsExtraDirs` key to it rather than replacing the file.

## Deploy

```bash
cd deploy/cloudflare
npm install
npx wrangler login       # opens the browser once
npm run check            # type-checks the Worker
npm run deploy           # builds the image (~330 MB), pushes it, deploys the Worker
```

The first deploy takes a few minutes, mostly for the image build and upload. Wrangler prints a `https://kavlotryx-demo.<your-subdomain>.workers.dev` address. The first request after a deploy, or after the demo has slept, waits while the container starts.

To refresh the sample data, for example so due dates and ages look current again, run `npm run deploy`. Each deploy rebuilds and reseeds the image.

## Use your own domain

The domain's DNS has to be on Cloudflare. In `wrangler.jsonc`:

1. Uncomment the `routes` entry and set the host name, for example `kavlotryx-demo.example.com`.
2. Set `PUBLIC_URL` to the same address with `https://`.

Then run `npm run deploy` again. `PUBLIC_URL` tells Kavlotryx the address people use, so its secure cookies, form checks and the copy-paste snippets on the Scanners page match. If you leave it empty, the demo uses the address of the request that woke it.

## Optional: sign in as admin during a walkthrough

Visitors stay read-only. If you want to show the write features yourself, such as triage, overrides and pipeline runs, add a private admin token:

```bash
npx wrangler secret put KAVLO_API_TOKENS        # value: me:admin:<at least 16 random characters>
npx wrangler secret put KAVLO_SESSION_SECRET    # value: output of `openssl rand -hex 32`
npm run deploy
```

Then use **Sign in** on the console with that token. Anything you change lasts until the container next sleeps. Keep the token to yourself: anyone who has it can change the demo until it resets.

## Cost and limits

- The container uses the `basic` instance type (¼ vCPU, 1 GiB memory, 4 GB disk); Kavlotryx needs about 90 MiB. `max_instances` is 1, so there's only ever one demo running, and that also caps the cost.
- The Workers Paid plan includes 25 GiB-hours of memory, 375 vCPU-minutes and 200 GB-hours of disk per month. With a 10-minute sleep timer, that covers roughly 25 hours of demo time a month; beyond that, usage is billed by the second. To change the sleep time, edit `INACTIVITY_TIMEOUT_MS` in `src/index.ts`.
- The container has no outbound Internet access (`enableInternet: false`). The demo doesn't need it, because the tracker is a local fake and the connectors, KEV and EPSS included, read snapshots.
- The Worker only passes `GET`, `HEAD` and `POST` requests through to the container.

## Keeping it private instead

To limit the demo to people you invite, put the host name behind [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/): in Zero Trust, add a self-hosted application for the demo's host name with a policy that allows specific email addresses. Access is free for up to 50 users, and visitors confirm a one-time code sent to their email.

## Third-party data

The image contains scanner sample files from the [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) test suite (BSD-3-Clause), downloaded at a pinned commit and checked by SHA-256 during the build. Their notice is in the image at `/opt/kavlotryx/THIRD-PARTY-SAMPLES.md`. The KEV entries come from CISA's public catalog and the EPSS scores from FIRST's public API, copied once into `examples/samples/config/`. Everything else in the demo is made-up data.
