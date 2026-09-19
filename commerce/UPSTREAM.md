# Vendored upstream

- Repository: https://github.com/medusajs/dtc-starter
- Commit: `bd2441acc18359533758fbf4db5bc80129055d2e`
- License: MIT, retained in `LICENSE`.
- Medusa packages: 2.21.0, as pinned by upstream.
- Next.js: 15.5.24, as pinned by upstream.
- Package manager: pnpm 10.11.1, existing lockfile retained.

Local integration changes: server-only SDK routed through Sentinel; per-request signed visitor context and routing epoch; request-time rendering; no shared region/API cache; browser option picker uses a server action; storefront cookies work with the configured HTTP/HTTPS scheme; separate Docker images; export-key and admin initialization scripts.

The real and sandbox services run the same backend and frontend build against different databases and signing secrets. Static catalog content starts from the same synthetic seed; generated IDs can differ between databases. No production database is copied into the sandbox. Reconcile upstream updates explicitly; do not replace this directory without preserving and reviewing integration changes.
