# TPP Report Builder

Web app for making Tenant Protection Plan inspection reports. Sign-in required.

**Open:** https://sankalp2930.github.io/tpp-report-builder/

## How access works
The app itself is stored encrypted in `vault.json`. Nothing readable is in this repo except the sign-in page.

- App content: AES-256-GCM with a random key
- Each user has a 3072-bit RSA-OAEP key pair; the private key is locked with their password (PBKDF2-SHA256, 600,000 rounds)
- Every save from the Users panel generates a new app key, so removed users cannot open the new version

## Managing users (admins)
1. Sign in, click **Users**.
2. Add, remove or reset users. Click **Save and download vault.json**.
3. Upload that `vault.json` here (Add file > Upload files) and commit. The site updates in about a minute.

## Install as an app
Chrome or Edge: install icon in the address bar. iPhone: Share > Add to Home Screen. Android: menu > Install app.
