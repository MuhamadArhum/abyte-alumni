# FrameFlow - Aluminum & Glass Quotation System

A real, locally hosted, single-business web application with a Python HTTP server, persistent SQLite database, hashed passwords, server-checked roles, quote snapshots, and audit events. It uses only the Python standard library.

## Run on Windows

1. Install Python 3.10 or newer if needed.
2. Double-click `Start-FrameFlow.cmd` (or run `python server.py` in this folder).
3. On first launch, enter the administrator name, email, and a password of at least 12 characters in the terminal.
4. Open [http://127.0.0.1:8765](http://127.0.0.1:8765) in your browser and sign in.
5. Create staff accounts in **Users & audit**.

Keep the terminal open while using the system. Press Ctrl+C in that window to stop it. Database file: `data/frameflow.sqlite3`. You can choose another data directory with `FRAMEFLOW_DATA_DIR`.

## Mobile PWA installation

- Deploy FrameFlow to an HTTPS host (for example, its existing Render URL), then open that URL on the phone. A local `127.0.0.1` address only points back to the phone itself.
- In Chrome or Edge on Android, tap **Install app** in the header or use the browser menu and choose **Install app** / **Add to Home screen**.
- On iPhone or iPad, open the HTTPS URL in Safari, tap **Share**, then **Add to Home Screen**.
- The service worker keeps the app shell available for launch while offline. Sign-in, quotations, sales, and reports need the server and an internet connection; authenticated business data is not saved in the offline cache.

## Working features

- Server-managed login sessions; passwords are PBKDF2-HMAC-SHA256 hashes, never stored in plaintext.
- Administrator, Estimator, Sales, and Viewer roles with server-side checks on edits, rate changes, user management, and settings.
- Client directory, search, editing, archiving, and historical quotation references.
- Catalog and selling rates for aluminum, glass, mirrors, accessories, and services; changes are recorded in rate history and audit log.
- Multi-line quotation drafts, decimal-safe `quantity × rate` calculations, discount, terms, validity, revisions, and status workflow.
- Issuing a quotation saves an immutable snapshot of the customer details, item descriptions, rates, totals, and terms.
- Browser print layout for saving customer quotations as PDF; CSV quotation export; administrator JSON database export.
- Company details, currency, default terms, user administration, and recent audit events.
- SQLite foreign keys, transaction-backed writes, parameterized SQL, input bounds, same-origin write checks, and sign-in attempt throttling.

## Pricing rules awaiting business approval

The supplied SRS states that aluminum cutting/deductions, stock lengths, glass billing area, wastage, accessories, labor, tax, margin/markup, and rounding policies are pending validation. This system therefore calculates the entered line quantity times its unit rate, less a fixed discount. Put dimensions and workshop specifications in the line description for now. Do not treat it as an automatic dimensions-to-material estimator until the owner provides approved formulas and sample quotations.

## Deploy on Render

`render.yaml` configures a Render web service on the paid Starter plan with a persistent disk mounted at `/var/data`. The SQLite database is stored on that disk and the app binds to Render's assigned port. HTTPS session cookies are enabled by the deployment configuration. The browser's print dialog generates PDFs locally.

1. Create a **private** GitHub repository for this app and push the contents of this folder to its `main` branch. Keep `data/` out of Git; `.gitignore` excludes the SQLite database and local runtime files.
2. In Render, choose **New → Blueprint**, connect the GitHub repository, and apply `render.yaml`. The service needs a paid plan because persistent disks are not available on free web services.
3. Open the deployed URL. On first visit, create the administrator with a unique email and a strong password of at least 12 characters. Add other staff through **Users & audit**.
4. Export a JSON backup regularly from the administrator area and keep a separate copy. The app does not yet include a backup import/restore workflow.

This deployment uses one web instance and SQLite on persistent storage. For larger teams or multiple instances, migrate to managed PostgreSQL before scaling. Do not put customer records, passwords, or the SQLite database into a public GitHub repository.

