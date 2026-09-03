# M365 Admin PowerShell Container

Ephemeral, dockerized PowerShell 7 environment pre-loaded with Microsoft 365 / Entra ID admin modules. Each run is a fresh container — no persisted state, no cached tokens, reauthenticate every time.

## What's included

- **PowerShell 7** (via `mcr.microsoft.com/dotnet/sdk:9.0`)
- **Microsoft.Graph** / **Microsoft.Graph.Beta** — Entra ID, users, groups, Conditional Access
- **ExchangeOnlineManagement** — Exchange Online + Security & Compliance Center
- **PnP.PowerShell** — SharePoint Online, Teams, M365 Groups
- **MicrosoftTeams** — Teams-specific admin
- **Microsoft.PowerApps.*** — Power Platform admin
- **Az** — Azure resource management
- **Microsoft365DSC** — configuration auditing / drift detection
- A stub `xdg-open` that prints the sign-in URL to the terminal instead of trying to launch a browser, since the container has none

## Requirements

- Docker + Docker Compose
- A host browser to complete interactive sign-in (URL is copy-pasted manually)

## Build

```bash
docker compose build
```

Rebuild whenever you want to refresh module versions:

```bash
docker compose build --no-cache
```

## Run

```bash
docker compose run --rm m365-admin
```

Drops you into an interactive `pwsh` shell. `--rm` deletes the container on exit — nothing persists between runs.

## Authenticating

Browser-based interactive auth is used. When you connect to a service, the stub `xdg-open` prints a URL instead of opening a browser:

```powershell
Connect-MgGraph -Scopes "User.Read.All" -TenantId "yourtenant.onmicrosoft.com"
Connect-ExchangeOnline
```

Copy the printed URL into your host browser, sign in, and the OAuth redirect will complete back into the container (requires `network_mode: host` — see below).

## Networking note

The compose file uses `network_mode: host` so the container shares your host's `localhost`, letting the OAuth loopback redirect (`http://localhost:PORT/...`) reach the container's local auth listener without port-mapping guesswork. This removes the container's normal network isolation — acceptable for this single-purpose, ephemeral admin tool, but worth knowing if you repurpose the container for anything else.

## Files

| File | Purpose |
|---|---|
| `Dockerfile` | Builds the image: PowerShell + modules + `xdg-open` stub |
| `docker-compose.yml` | Runs the container interactively with host networking |

## Notes

- Modules are baked into the **image**, not the container — rebuilding refreshes them; running (`docker compose run`) does not re-download anything.
- No credentials, tokens, or module state persist across runs by design.
