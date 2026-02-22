# DetectFlow real-time dashboard in ASM

The ASM frontend can embed the **real-time Dashboard** from [DetectFlow UI](https://github.com/socprime/detectflow-ui) (SOC Prime DetectFlow OSS) so you get pipeline topology and runtime state in one place.

## What is DetectFlow UI?

DetectFlow UI is a separate React (Vite) app for:

- Viewing pipeline topology and runtime state
- Managing pipelines and configuration
- Configuring repositories, topics, filters, log sources, and runtime settings

It uses React Flow, SSE for real-time updates, and talks to a DetectFlow backend (see [detectflow-main](https://github.com/socprime/detectflow-main)).

## How it’s integrated in ASM

- **Route:** **DetectFlow** in the sidebar → `/detectflow`.
- **Behavior:** The page embeds DetectFlow UI in an **iframe** when `NEXT_PUBLIC_DETECTFLOW_UI_URL` is set. If not set, the page shows setup instructions and a link to the DetectFlow UI repo.

## Setup

### 1. Run DetectFlow UI

Clone and run the UI (and its backend) as per the [DetectFlow UI README](https://github.com/socprime/detectflow-ui):

```bash
git clone https://github.com/socprime/detectflow-ui.git
cd detectflow-ui
yarn install
yarn watch
```

By default the app runs at `http://localhost:5173`. For production, build and serve it (e.g. behind nginx or in Docker) and note its public URL.

### 2. Point ASM at DetectFlow UI

Set the URL in the ASM frontend environment so it’s available at build time:

**Local (.env in project root):**

```bash
NEXT_PUBLIC_DETECTFLOW_UI_URL=http://localhost:5173
```

**Docker Compose:** add to `.env` and rebuild the frontend:

```bash
NEXT_PUBLIC_DETECTFLOW_UI_URL=http://localhost:5173
# Or, if DetectFlow UI runs in another container on the same Docker network:
# NEXT_PUBLIC_DETECTFLOW_UI_URL=http://detectflow-ui:5173
```

Then rebuild so the variable is inlined:

```bash
docker compose up -d --build frontend
```

**AWS / production:** set `NEXT_PUBLIC_DETECTFLOW_UI_URL` to the public URL of your deployed DetectFlow UI (e.g. `https://detectflow-ui.yourdomain.com`), then rebuild the ASM frontend.

### 3. Open the dashboard in ASM

Log in to ASM → **DetectFlow** in the sidebar. The real-time dashboard will load in the iframe (or you’ll see the setup message if the URL isn’t set).

## Limitations

- **Separate app:** DetectFlow UI is a different codebase and product; we only embed it. Auth and session are not shared: users may need to log in to DetectFlow UI inside the iframe if it uses its own auth.
- **CORS / cookies:** If DetectFlow UI and ASM are on different origins, cookies/auth don’t automatically cross. Running both behind the same domain (e.g. reverse proxy with `/detectflow-app` for the UI) can simplify this.
- **Build-time URL:** `NEXT_PUBLIC_DETECTFLOW_UI_URL` is baked in at frontend build time. Changing it requires rebuilding the frontend.

## Optional: run DetectFlow UI in Docker next to ASM

To run DetectFlow UI as another service and embed it:

1. Clone detectflow-ui, add a `Dockerfile` (or use their image if provided).
2. Add a `detectflow-ui` service to `docker-compose.yml` (or a separate compose file) exposing port 5173.
3. Set `NEXT_PUBLIC_DETECTFLOW_UI_URL=http://detectflow-ui:5173` only if the browser can reach that URL (usually not for `http://detectflow-ui:5173` from the user’s machine). For same-machine Docker, use `http://localhost:5173` and map the container port to the host. For production, use the public URL of the DetectFlow UI deployment.

## References

- [DetectFlow UI](https://github.com/socprime/detectflow-ui)
- [DetectFlow main](https://github.com/socprime/detectflow-main)
