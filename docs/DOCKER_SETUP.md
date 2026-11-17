# Docker setup

Docker is optional; Windows PowerShell `setup.ps1` and `start.ps1` still run the native Python application.

```powershell
docker compose up --build -d
docker compose --profile scanners up --build -d
docker compose ps
docker compose down
```

The app is published only on `127.0.0.1:8000`. SQLite data, reports and logs have persistent volumes/mounts. ZAP is a separate, optional service on the internal `weppentest` network and is activated by profile `scanners`; the API key must be changed for shared environments. Do not publish ZAP's API port. The app has a `/health` health check and ZAP checks its local API. Compose's `depends_on` condition is optional for the default profile.

Set `APP_PORT`, `API_KEY`, `API_KEY_REQUIRED`, and `ZAP_API_KEY` in an untracked `.env` file. Keep secrets out of source control. Docker Desktop with Linux containers is recommended on Windows 11. The app image contains only the Python platform and its core requirements; it does not bundle every scanner. Add dedicated scanner services/images as explicitly configured, instead of bloating the core image. Paths and mounted artifact permissions differ between Windows and Linux containers.

Build without ZAP: `docker compose up --build -d app`.
