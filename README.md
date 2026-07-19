# ProtOSINT
ProtOSINT is a Python script that helps you investigate Proton Mail accounts.

<img width="800" height="832" alt="protosint (1)" src="https://github.com/user-attachments/assets/4c08389a-0525-40e3-99d3-392561752425" />

## Version
This is **ProtOSINT v2**. The first version has been around for a few years, but Proton's API changed and the old checks stopped working, so this is a rewrite that brings the tool back to life. Big thanks to [NeutrOSINT](https://github.com/Kr0wZ/NeutrOSINT) for keeping this kind of research going in the meantime.

## Description
This tool is meant for OSINT work on Proton Mail (educational and authorised use only). You give it an email address, a username or a domain, and it tells you what it can find: whether the address really exists, when the account's encryption key was created, which algorithm it uses, and whether a custom domain is hosted on Proton.

It has four modules:
- **[1]** Check one Proton email: does it exist, and what's the key creation date and type.
- **[2]** Enumerate a username across every Proton domain (protonmail.com, protonmail.ch, pm.me, proton.me).
- **[3]** Check whether a domain uses Proton Mail (via its MX records, cross-checked with the key server).
- **[4]** Batch-verify a list of addresses through a real logged-in Proton session.


## How it works (and why)

Proton makes account enumeration deliberately hard, so a naive check will lie to you. ProtOSINT works around this by combining three sources and trusting the right one for the job.

**The key server lies about non-existent addresses.** Proton's public key server (`pks/lookup`) returns a fake "decoy" key - with a made-up creation date - for *any* address on a Proton domain, whether it exists or not. So a "valid key + nice date" is not proof the address exists. The key server is still useful, but only for reading the *real* key date of an address you've already confirmed exists.

**The account API is better, but not perfect.** Proton's account API (`/users/available`) tells you whether a username is free. It's right most of the time, but it checks the *username*, not the specific address, so it can be wrong on edge cases - `test@protonmail.ch` can look "taken" even though that `.ch` address was never created.

**The only fully reliable check is Proton's own compose window.** When you type an address into the "To" field, Proton validates it and flags it in red if the mailbox doesn't exist. ProtOSINT can drive that with Selenium: it logs into your Proton account, opens a new message, types the address, and reads whether Proton accepts it or rejects it. That's the authoritative answer, and it's what modules 1, 2 and 4 use when Selenium is turned on (which it is by default).

**Custom domains are checked by DNS.** For a domain like `example.com`, the real question is where its mail is routed. If the MX record points to Proton (`mail.protonmail.ch` / `mailsec.protonmail.ch`), the domain is on Proton Mail. Module 3 reads the MX records and cross-checks them against the key server.


## Requirements

- [Python 3](https://www.python.org/downloads/) (3.7 or newer)
- The Python packages in `requirements.txt` (`requests`, `selenium`)
- A browser (Chrome/Chromium or Firefox) for the Selenium check
## Install

Clone the repo and install the Python dependencies:

```bash
git clone https://github.com/pixelbubble/ProtOSINT.git
cd ProtOSINT
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

You also need a browser installed for the Selenium check. Selenium downloads the matching driver by itself, so you don't need to install a separate chromedriver/geckodriver.

Debian / Ubuntu / Kali:

```bash
wget -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt update
sudo apt install -y /tmp/chrome.deb
# alternatives: sudo apt install -y chromium   (or: firefox-esr)
```

macOS (Homebrew):

```bash
brew install --cask google-chrome  # or: brew install --cask firefox
```

Windows: install Chrome or Firefox normally from their website.

> Running as root (common on Kali)? Chrome needs the `--no-sandbox` flag or it crashes on launch. ProtOSINT already sets it for you, so there's nothing to do.

## Configuration

The first time you run the script it creates a `config.json` file next to it:

```json
{
  "proton": {
    "username": "",
    "password": ""
  },
  "settings": {
    "use_selenium": true,
    "headless": true
  }
}
```

- `use_selenium` (`true`/`false`) uses the Selenium compose check for modules 1, 2 and 4 (the reliable method). Set it to `false` to fall back to the faster account API.
- `headless` (`true`/`false`) runs the browser in the background so no window pops up. Only set it to `true` on an account **without** 2FA or CAPTCHA, since you can't solve those when the window is hidden. Set it to `false` if you need to see the browser.
- `username` / `password` are your Proton login. You can fill them in, or leave them empty and the script will ask when it starts. Leaving the password empty is safer - it's never written to disk. If you do put credentials in the file, don't commit it (it's already in `.gitignore`).

If you close the browser mid-session, the next check that needs it will reopen and log back in on its own.

## Usage

```bash
python3 protosint.py
```

Pick a module from the menu and follow the prompts. `q` quits (and closes the browser if one was open).

## Tips for Proton Mail investigation

### Proton Mail is case-insensitive

The account name is case-insensitive, and Proton treats `.`, `_` and `-` as transparent. Anything after a `+` is ignored too. So all of these are the same account as `mikemike@protonmail.com`:

- `mike.mike@protonmail.com`
- `mike_mike@protonmail.com`
- `mike-mike@protonmail.com`
- `mike.mike+paypal@protonmail.com`

They all share the same key and timestamp.

### The timestamp is the key date, not always the account date

The date ProtOSINT shows is when the account's *primary PGP key* was created - which is not always the same as when the account was created.

**Example 1 - the target never touched their keys.** Here the key date is the real account creation date.

- 2021-01-12: account `example@protonmail.com` is created
- 2021-01-15: ProtOSINT reports 2021-01-12

**Example 2 - the target regenerated their key.** Now the date reflects the newer key, not the account.

- 2021-01-12: account `example@protonmail.com` is created
- 2021-01-13: target generates a new key in Settings → Encryption keys
- 2021-01-15: ProtOSINT reports 2021-01-13, not 2021-01-12

### Encryption keys

ProtOSINT shows which key type the account uses. What the key server reports for the primary key is one of:

- Curve25519 - modern ECC (an Ed25519 signing key); this is the default on newer accounts and the fastest and most secure
- RSA 2048 - the old default on accounts created before 2021
- RSA 4096 - stronger but slower, usually seen when someone imported a key for legacy compatibility

You may also see X25519, Ed25519 or RSA 3072 on some keys - they're all read straight from the key's OpenPGP algorithm ID.

### Custom domains

A paid Proton plan lets you attach your own domain. If `alias@yourdomain.com` resolves to Proton (module 1 or 3), the target is on a paid Proton plan. Module 3 confirms this from the domain's MX records, which is the most reliable signal.

## Rate limits

Proton rate-limits both the key server (error 2028) and the account API (HTTP 429). The exact limits aren't documented and seem to move around, so if you get blocked, wait a while or run again from a different IP. The Selenium method uses your normal logged-in session, so it isn't affected by these limits.

## Contributing

Feel free to clone the project. For anything major, open an issue first to talk it through.

The Selenium module reads Proton's web app, so if Proton changes its page the selectors in `selenium_login()` and `selenium_check_emails()` may need a small update. That's the first place to look if the browser check stops working.

## License

[MIT](https://choosealicense.com/licenses/mit/)

