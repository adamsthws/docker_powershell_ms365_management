# AGENTS.md

Guidance for AI coding agents (and people) working anywhere in this repository. This is the only agent instruction file at the root: there is no CLAUDE.md. Folders with their own tooling have an AGENTS.md of their own with the detail for that folder; read it before working there. Where the two differ, the folder's file wins for that folder.

## What is here

- `Dockerfile`, `docker-compose.yml`: the `m365-admin` PowerShell container (Graph, Exchange Online, PnP, Teams, Power Platform, Az, Microsoft365DSC). See [README.md](README.md).
- [`business-email-compromise/`](business-email-compromise/AGENTS.md): runbook and helpers for recovering a compromised Microsoft 365 mailbox.

## Rules for every folder

- **Read-only during live work unless the operator says otherwise.** When helping with a live case or a client environment, an agent reads files and output, runs only read-only commands, and recommends changes rather than making them. That covers the client's tenant or machine, the case or evidence files, and the code in this repository. Before any change, say exactly what it is and wait for the operator to approve it explicitly. One approval covers only the change it was given for, not later ones.
- **Client data stays out of git.** Case folders, evidence and anything client-specific live in `.scratch_area/`, which `.gitignore` excludes. Never weaken that or move client data anywhere tracked.
- **Keep the repository client-generic.** Docs and examples use placeholders: `contoso.com`, `user@contoso.com`, IPs from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32. Never real client names, addresses or IPs.
- **Work in a worktree while a case is running.** The case containers mount a folder's code from the main checkout, so changing it there changes the tools under a live session. Make tooling changes on a branch in a separate worktree (for example under `.scratch_area/worktrees/`).
- **Run the folder's tests before committing** (for example `business-email-compromise/scripts/test.sh`). They must pass.
