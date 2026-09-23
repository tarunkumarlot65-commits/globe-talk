# GlobeTalk

Random text/video chat with strangers — AI nudity detection, live voice translation,
country-based matching, Google/Facebook/email login, and a text profanity filter.

## What's in this folder

```
server.js        - main server (matching, chat, video signaling, bans)
auth.js          - login: Google Sign-In, Facebook Login, email OTP
moderation.js    - AI nudity detection (video)
profanity.js     - vulgar/sexual language filter (text)
security.js      - VPN/proxy detection
translate.js     - live translation (Google Translate / LibreTranslate / mock)
package.json     - dependencies
.env             - your settings (already has a random JWT_SECRET filled in)
public/
  index.html     - the app itself (home screen, chat, video)
  terms.html     - Terms of Service (fill in your details before launch)
  privacy.html   - Privacy Policy (fill in your details before launch)
```

## Run it (3 commands)

```
npm install
npm start
```

Then open the link it prints (usually `http://localhost:3000`).

That's it — `.env` already has a working `JWT_SECRET`, so logins will work right away
(email OTP codes print in the console since no email service is configured yet).

## To turn on optional features, edit `.env`:

- `GOOGLE_CLIENT_ID` — Google Sign-In (get free from console.cloud.google.com)
- `FACEBOOK_APP_ID` / `FACEBOOK_APP_SECRET` — Facebook Login (developers.facebook.com)
- `SMTP_HOST` / `SMTP_USER` / `SMTP_PASS` — real emails instead of console-only OTP codes
- `GOOGLE_TRANSLATE_KEY` or `LIBRETRANSLATE_URL` — real translation instead of test/mock mode
- `PROXYCHECK_API_KEY` — higher VPN-detection limits (works without a key too, at a lower rate)

None of these are required to test the app locally.

## Deploying so it's live on the internet

Easiest free path: push this folder to a GitHub repo, then connect that repo on
render.com as a "Web Service" (Build command: `npm install`, Start command: `npm start`).
Add the same `.env` values under Render's "Environment" tab.

## Before opening this to the public

- Fill in the real name/email/address in `public/terms.html` and `public/privacy.html`
  (search for `[...]` placeholders)
- Get a local lawyer to glance over the Terms/Privacy once, especially for the countries
  you're targeting
- Turn on Google/Facebook login and real translation for the best experience
