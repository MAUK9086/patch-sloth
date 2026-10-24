# App Platform deploy (Option B): morning steps

Goal: the API and web page live on DigitalOcean App Platform, with no GPU. One service, `apps-s-1vcpu-2gb`
($25/month, billed per second). Spec: `deploy/do-app.yaml`. Image: `deploy/Dockerfile`.

What the image contains, so start-up never depends on the GitHub API:
- the feed release `feed-2026-10-23` (parquet, CSV, meta, HGB fallback model);
- the GHSA advisory index, built during the image build from the latest GitHub Advisory DB;
- osv-scanner 2.7.0 and its npm/PyPI offline DB.

The deployed app scans with the in-process GHSA index (`PATCHSLOTH_SCAN_ENGINE=fallback`). Measured on the laptop,
an offline osv-scanner run takes 26–39 s and ~0.6 GB per lockfile, because it reloads its database on every call.
The fallback matcher agreed with osv-scanner on both fixture lockfiles (DECISIONS.md, 2026-10-21).

The DigitalOcean console labels below are written from the docs and may differ slightly on screen. The field
values are exact.

## 0. Before you start (laptop, 1 min)

```bash
cd ~/Downloads/TECH_PROJECTS/hacktoberFestweek3/patch-sloth
git pull && git log -1 --oneline     # the commit that added deploy/DEPLOY_STEPS.md, or newer
date -u +%FT%TZ                      # note this: app creation time, for the cost table
```

## 1. Create the app (console, ~5 min)

1. Go to <https://cloud.digitalocean.com>, click **Create** (top right), then **App Platform**.
2. Source: choose **GitHub**. If asked, click **Authorize / Install** the DigitalOcean GitHub app. Choose
   **Only select repositories** → `MAUK9086/patch-sloth` → **Install**.
3. Repository `MAUK9086/patch-sloth`, branch `master`, **Source directory** `patch-sloth`, **Autodeploy** on.
   Click **Next**.
4. DigitalOcean looks for a Dockerfile in the source directory, but ours is in `deploy/`. Pick one of these:
   - On the resources screen, edit the component: set **Build strategy / Resource type** to **Dockerfile**, and
     **Dockerfile path** to `patch-sloth/deploy/Dockerfile`. Set **HTTP port** to `8080`.
   - Or, simplest: continue with whatever it detects. After step 9, open **Settings → App Spec → Edit**, paste
     the whole of `deploy/do-app.yaml`, click **Save**, and it redeploys with the right settings.
5. **Size:** Basic / shared CPU, **1 vCPU, 2 GB** (`apps-s-1vcpu-2gb`, $25/mo), 1 container.
   Do not pick 1 GB: the app uses ~0.6 GB with the feed loaded.
6. **Environment variables** (component level). Add the plain ones exactly as in `deploy/do-app.yaml`:
   | Key | Value |
   |---|---|
   | `PATCHSLOTH_FEED_REPO` | `MAUK9086/patch-sloth` |
   | `PATCHSLOTH_FEED_DOWNLOAD` | `1` |
   | `PATCHSLOTH_SCAN_ENGINE` | `fallback` |
   | `PATCHSLOTH_LLM_BACKEND` | `null` |

   Then add `PAPERINSTRUMENTS_API_KEY` = your key, with the **Encrypt** box ticked. Without it, reports use the
   template writer, which is fine but has no Ultramarine.
7. **Health check:** HTTP, path `/health`, initial delay 30 s, period 10 s, timeout 10 s, failure threshold 12.
   This is already in the spec if you used the paste route.
8. **Region:** New York (`nyc`). **App name:** `patch-sloth`.
9. Click **Create Resources** / **Create App**.

## 2. Watch the build (~10–15 min)

Open the app → **Activity** → the running deployment → **Build logs**. Expected milestones, in order:
- `git clone ... advisory-database` and then `ls -la /out` showing `advisory_index.json.gz` (a few MB);
- `pip install` of `requirements-app.txt`;
- `osv-scanner ... --download-offline-databases`, then `du -sh /opt/osv-db` printing about 245M;
- 4 `curl` downloads of the feed into `/app/feed` and `/app/data/models`;
- `Successfully built`, then the deploy phase, with health checks on `/health`.

## 3. Check it works (laptop, 2 min)

```bash
APP=https://patch-sloth-xxxxx.ondigitalocean.app     # <- paste the app URL from the console
curl -s "$APP/health"; echo
# expected: "status":"ok", "model":"stack", "feed_rows":240071, "scan_engine":"fallback",
#           "feed_release":"feed-2026-10-23" (or "feed-2026-10-23 (local copy)" if GitHub was unreachable)
curl -s -F "file=@patch-sloth/tests/fixtures/package-lock.json" -F "no_llm=true" "$APP/scan" | head -c 600; echo
curl -s -F "file=@patch-sloth/tests/fixtures/requirements.txt" "$APP/scan" | python -c "import json,sys; j=json.load(sys.stdin); print(j['engine'], len(j['rows']), j['costs'])"
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" "$APP/feed/latest.csv"
```
Then open `$APP` in a browser, paste a lockfile, and take the screenshot for the post.

## 4. If something fails

| Symptom | Likely cause | Fix |
|---|---|---|
| Build log: "Dockerfile not found" or a buildpack build | Dockerfile path not set | Step 1.4: Settings → App Spec → paste `deploy/do-app.yaml` |
| Build fails at `osv-scanner ... warm-up failed` | network hiccup while downloading the OSV DB | **Actions → Force rebuild and deploy** |
| Build fails at `git clone advisory-database` | GitHub hiccup | Force rebuild |
| Deploy: health check failed, runtime log shows `Killed` / OOM | memory | Settings → component → size **2 vCPU / 4 GB** (`apps-s-2vcpu-4gb`, $50/mo) |
| Health check failed, no OOM | slow cold start | raise `initial_delay_seconds` to 90 in the spec |
| `/health` shows `"feed_release": "... (local copy)"` | GitHub API rate limit at boot | harmless: the baked feed is served |
| `/scan` returns 503 "scanner unavailable" | the advisory index is missing from the image | check the build log for the `/out` listing; force rebuild |

## 5. Costs to record (for the post's cost table)

- App creation time (step 0) and, if you delete it later, the deletion time.
- The plan: `apps-s-1vcpu-2gb`, $25/month ≈ $0.034/hour, billed per second, 1-minute minimum
  (docs.digitalocean.com/products/app-platform/details/pricing, checked 2026-10-24).
