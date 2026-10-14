# nochain-hunter

A single bash script that finds, quarantines and (if you insist) deletes the
files left behind by the **EtherHiding / "nochain" WordPress compromise**, plus
a small set of must-use plugins and `.htaccess` rules that stop the known
reinfection paths from coming back.

It needs nothing but `bash`, `find` and `grep`. WordPress doesn't have to be
running, installed correctly, or even reachable. That matters when the host
has suspended the site or the dashboard is redirecting visitors to a scam page.
One pass covers every site under an account.

## Background

"EtherHiding" is a family of WordPress compromises that keeps its payload
**on a public blockchain** rather than on an attacker's server. Injected
JavaScript calls a smart contract through a public RPC endpoint (Base,
publicnode, drpc and others), reads the current payload, and runs it in the
visitor's browser. Because the payload lives in a contract, the attacker can
swap it without touching the site, and there's no command-and-control domain
to take down.

The variant this tool targets (named after its `nochain` markers) adds several
persistence tricks on top:

- **Service workers** (`nochain-sw.js`, `nc-sw.js`, `/nochain/sw.js`)
  registered at the site root, so the payload keeps firing from the visitor's
  browser cache after the server-side files are gone.
- **Must-use plugins** that load on every request and never appear in the
  Plugins list.
- **Disposable plugin/theme directories** named with a Unix timestamp
  (`something-1789001503`) or a word plus a hex tail (`site-helper-3f9a1c`,
  shown in the dashboard as "Query Monitor Companion" or a similar name).
- A **self-repair routine**: ZIP archives disguised as images in `uploads/`
  that get unpacked back into `plugins/` when anything is removed, with a
  `.state.json` integrity file to detect tampering.
- **PHP backdoors** (`eval(base64_decode(...))` and friends), often in
  timestamp-named files.

A second, unrelated family turned up during the same cleanup: a fake
"WP Security Helper" plugin that **hides a rogue administrator account** from
the Users list and itself from the Plugins list. The scanner detects that too.

## What it detects

| Check | Severity |
|---|---|
| Plugin/theme directories named with a plausible Unix timestamp (2023 to one year ahead) | HIGH |
| `nochain` directories; service-worker files at a site root | HIGH |
| Any `.php` file under `uploads/` | HIGH |
| Images over 20 KB in `uploads/` whose bytes are actually a ZIP or PHP | HIGH |
| Unrecognised must-use plugins (`nc-dropin*` is HIGH, anything else MEDIUM) | HIGH / MEDIUM |
| PHP files under `wp-content/` whose name ends in a Unix timestamp | HIGH |
| `.state.json` self-repair integrity files inside `plugins/` | MEDIUM |
| `<word>-<hex>` plugin/theme directories; known drop directories (`webtoffee_export`, `nc-dropin`) | HIGH |
| Code signatures: nochain loader/evasion markers, the known payload contract address, blockchain RPC hostnames, the `getActiveScripts` contract ABI, archive-unpacking self-repair, `eval` of encoded payloads | HIGH |
| A bundled Ethereum client library (`JsonRpcProvider`) inside site code | MEDIUM |
| Admin-concealment markers: `_pre_user_id`, `wsh_*` hidden-user options, plugins that hide themselves while filtering the Users list, forged "WordPress Security Team" authorship | HIGH |
| Any 40-hex contract address in a file that also references an RPC endpoint (EtherHiding with a contract we haven't seen) | HIGH |

The must-use plugin check has an allowlist of the drop-ins that common managed
WordPress hosts install (WP Engine, SiteGround, GoDaddy, Liquid Web, Pressable,
Cloudways and others), so a clean managed site shouldn't light up. If yours
does, check the file before you remove it.

Findings inside a directory that is already flagged are collapsed into that
directory, so the report lists what to remove, not every file underneath it.

## Usage

Upload `nochain-scan.sh` to the account (SSH/SFTP), then:

```sh
chmod +x nochain-scan.sh

./nochain-scan.sh                       # scan ~/www, report only (the default)
./nochain-scan.sh --root /var/www       # scan somewhere else
./nochain-scan.sh --quarantine          # scan, then move HIGH findings out of the web root
./nochain-scan.sh --list                # list quarantine batches
./nochain-scan.sh --restore 20260911-142233   # put a batch back
./nochain-scan.sh --delete              # scan, then permanently remove HIGH findings
./nochain-scan.sh --delete --no-archive # ... without keeping a tar.gz copy
./nochain-scan.sh --sw                  # neutralise the service-worker files
./nochain-scan.sh --help
```

Every run writes a plain-text report to `~/nochain-report-<timestamp>.txt`.

### Recommended order

1. **Scan** and read the report. Review the MEDIUM findings by hand.
2. **`--sw`** first. Don't just delete the service worker: browsers that
   already installed it will keep running the cached payload. `--sw` replaces
   each file with a worker that clears its caches, unregisters itself and
   reloads the page. Leave those files in place for 30 days, then delete them.
3. **`--quarantine`** the HIGH findings. Must-use plugins move first, because
   they load earliest and rebuild everything else.
4. **Scan again.** Anything that reappears means a live backdoor (or a
   compromised credential) is still active.
5. Only once the site is stable, `--delete` (or just delete the quarantine
   directory).

### Safety

- **Report-only by default.** Nothing moves without a flag *and* a prompt.
- **Quarantine is reversible.** Files go to `~/nochain-quarantine/<batch>/`,
  keeping their original layout, with a `manifest.tsv` that `--restore` reads.
- **Delete is guarded.** It shows the full list and requires you to type
  `DELETE`. Unless you pass `--no-archive` it writes
  `~/nochain-removed-<batch>.tar.gz` first and refuses to continue if the
  archive fails. It also refuses to remove anything outside the scan root,
  any path containing `..`, WordPress's structural directories (`wp-content`,
  `plugins`, `uploads`, …), anything that looks like a WordPress install root,
  or a site's top-level directory.
- Only **HIGH** findings are ever moved or deleted. MEDIUM is for you to judge.

## Hardening files (`wp-hardening/`)

| File | Install to | What it does |
|---|---|---|
| `000-nochain-guard.php` | `wp-content/mu-plugins/` | Removes dropper-shaped plugins from the active list before WordPress loads them, refuses to activate them through the dashboard or the REST API, and blocks WordPress HTTP API calls to the blockchain RPC hosts. Reports blocks in an admin notice and the PHP error log (at most once an hour). |
| `001-block-user-enumeration.php` | `wp-content/mu-plugins/` | Stops anonymous visitors listing usernames through `/wp-json/wp/v2/users`, `?author=N` redirects and oEmbed author data. Administrators are unaffected. |
| `no-php.htaccess` | `wp-content/uploads/.htaccess` and `wp-content/upgrade/.htaccess` | Refuses to execute PHP from those folders over the web. WordPress updates still work. |
| `root.htaccess` | The **top** of the site's root `.htaccess`, above `# BEGIN WordPress` | Refuses any PHP file whose name ends in a 10-digit timestamp, the dropper's naming pattern. |

The `.htaccess` rules use Apache 2.4 syntax (`Require all denied`). On nginx,
add equivalent `location` blocks instead.

The guard plugin carries the signatures it blocks, so the scanner exempts it
by name. Install it as exactly `000-nochain-guard.php`.

**These are tripwires, not walls.** Anything already running on the site, or
anyone holding your SFTP/SSH/hosting credentials, can edit or delete them.
They stop the known reinstall shapes from loading and tell you when one comes
back. The RPC block only covers requests made through the WordPress HTTP
API; a backdoor using raw `curl` will bypass it.

## Limitations

This is a triage and cleanup tool for one known campaign, not a malware
scanner and not a substitute for a full incident response. In particular:

- **It does not look in the database.** Injected `<script>` tags in posts,
  options or widgets, and rogue administrator accounts, have to be found and
  removed separately (for example with `wp db search` and `wp user list`).
- **Signatures go stale.** The operators rename things. A clean scan means
  "none of these patterns", not "the site is clean".
- **Cleanup doesn't fix how they got in.** Rotate every credential: WordPress
  admins, SFTP/SSH, hosting panel, database password, and the salts in
  `wp-config.php`. Update or remove whatever plugin was exploited, then
  reinstall WordPress core and your plugins from clean sources.
- Built and tested on Linux (GNU `find`/`date`). On macOS/BSD it runs, but
  timestamps in the report show as raw epoch values.
- Review every finding before deleting. Quarantine exists so you don't have
  to trust the script blindly.

## Origin

Written while cleaning up a live nochain infection
across several WordPress sites looked after by
Henry Holsters. The signatures come from files
recovered during that cleanup. Issues and pull requests with new indicators
are welcome.

## License

Copyright (C) 2026 Ben Crum.

Licensed under the [GNU Affero General Public License v3.0](LICENSE). You may use, modify and redistribute this software, but if you distribute it or run a modified version as a network service, you must make your source code available under the same license.
