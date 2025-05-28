# 403X

<p align="center">
  <img src="403x.png" width="100%" alt="403X Banner">
</p>

**403X**
An all-in-one 401/403 bypass arsenal that chains 20 + evasion modules, runs them concurrently, and lets you fine-tune every test from headers to hex-encoded path tricks. Built for pentesters, bug-bounty hunters, red-teamers, and anyone who refuses to take “Forbidden” for an answer.

---

## Features

* **Module buffet** – 22 specialised bypass engines:

  * HTTP-method fuzzing, header spoofing, path-traversal, double encoding, case smashing, dot-slash & null-byte tricks, … *(full list below)*
* **Smart defaults** – Ships with carefully-curated fallback wordlists for paths, headers, payloads, UA strings and suffixes → works out-of-the-box even if you don’t supply your own files.
* **External wordlists** – Point any module at `paths.txt`, `headers.txt`, `payloads.txt`, `user_agents.txt`, or `endpaths.txt` to extend the attack surface instantly.
* **Threaded speed** – Global thread-pool (default **5**, configurable with `-T`) keeps requests flying without melting your target.
* **Fast mode** – `--fast` slices each wordlist to the essentials for quick recon passes.
* **Proxy & timeout support** – Pipe traffic through Burp/ZAP (`--proxy http://127.0.0.1:8080`) and tweak `--timeout` as needed.
* **Baseline probe** – Detects if a page is already 200 OK and politely exits unless you tell it to continue.
* **Repro-ready output** – Every hit comes with an auto-generated `curl` one-liner.
* **Report file** – `-o results.txt` dumps a timestamped summary of winners.

---

## Installation

1. **Clone**

   ```bash
   git clone https://github.com/YourUserName/403x.git
   cd 403x
   ```
2. **Install Python 3.7+ dependencies**

   ```bash
   pip install -r requirements.txt
   ```

   *Minimal stack:* `requests`, `colorama`, `urllib3`

---

## Quick-Start

### Full auto (all modules, default 5 threads)

```bash
python 403x.py -u https://target.com/secret
```

### 2× faster recon

```bash
python 403x.py -u https://target.com/secret --fast -T 10
```

### Headers only

```bash
python 403x.py -u https://target.com/secret -H
```

### Path traversal **only** with a custom list

```bash
python 403x.py -u https://target.com/secret -t \
               --fast \
               --paths-file my_sneaky_paths.txt \
               -T 20 -o path_hits.txt
```

*(See **Advanced Usage** below for the `--paths-file` helper.)*

---

## Full Syntax

```bash
python 403x.py -u <URL> [module flags] [options]
```

### Module flags

| Flag                  | Module                                     | What it does             |
| --------------------- | ------------------------------------------ | ------------------------ |
| `-a, --all`           | **All modules**                            | (default if none picked) |
| `-m, --methods`       | HTTP method fuzz                           |                          |
| `-H, --headers`       | Header spoof / IP forwarding               |                          |
| `-P, --protocols`     | Switch HTTP↔HTTPS & `X-Forwarded-Scheme`   |                          |
| `--protocol-version`  | Force HTTP/1.0                             |                          |
| `-p, --ports`         | Port overrides / `X-Forwarded-Port`        |                          |
| `-t, --paths`         | Path-traversal wordlist                    |                          |
| `--advanced-path`     | Encoded slashes, semicolons, wildcard etc. |                          |
| `--exhaustive-case`   | Case-permutation brute                     |                          |
| `--double-encoding`   | %25 double-encode sweep                    |                          |
| `-e, --encoding`      | Mixed URL-encoding tricks                  |                          |
| `-c, --case`          | Simple upper/lower/mixed path tests        |                          |
| `-x, --extensions`    | Add / swap file-extensions                 |                          |
| `-q, --params`        | Parameter pollution (& special chars)      |                          |
| `-U, --user-agents`   | UA rotation (bots / curl / etc.)           |                          |
| `-A, --auth`          | Empty / fake Auth headers & API keys       |                          |
| `-d, --dot-slash`     | `./`, `%2e/`, dot-slash chaos              |                          |
| `-s, --special-chars` | Wild prefix/suffix chars `# ; * …`         |                          |
| `-n, --null-byte`     | `%00`, `%0a` mid-path injections           |                          |
| `-i, --injection`     | Custom payloads in query/path/header/Auth  |                          |
| `-C, --cache`         | Cache-buster headers                       |                          |
| `-f, --fuzzing`       | Random mutation / repetition fuzz          |                          |
| `-y, --content-type`  | Content-Type flips                         |                          |
| `-E, --endpaths`      | Classic suffixes (`/.`, `?debug=1`, etc.)  |                          |

### General options

| Option                 | Default | Description                       |
| ---------------------- | ------- | --------------------------------- |
| `-T, --threads`        | **5**   | Global thread-pool size           |
| `--fast`               | off     | Trim each list for quicker scans  |
| `--proxy <url>`        | –       | Send all traffic via HTTP/S proxy |
| `--timeout <sec>`      | **10**  | Per-request timeout               |
| `-o, --output <file>`  | –       | Save winning bypasses             |
| `-k, --continue-if-ok` | off     | Continue even if baseline is 200  |
| `-v, --verbose`        | off     | Log every request & error         |

---

## Examples

### 1 . Full brute with report

```bash
python 403x.py -u https://api.corp.local/admin -a -T 15 -o corp_admin_hits.txt
```

### 2. Only header & UA spoofing through Burp

```bash
python 403x.py -u https://10.10.10.10/private -H -U \
               --proxy http://127.0.0.1:8080 --timeout 5
```

### 3. Force HTTP/1.0 + port tricks

```bash
python 403x.py -u https://172.20.0.5/secure \
               --protocol-version -p --fast
```

### 4. Target-specific path list

```bash
python 403x.py -u https://example.com/ \
               -t --paths-file spring_tomcat_paths.txt
```

### Sample hit (console)

```
[*] Baseline 403 detected – launching bypass engines…
[+] BYPASS FOUND [HTTP-HEADER] Status: 200, Length: 844 - https://target.com/secret
    Payload: X-Forwarded-For: 127.0.0.1
    Reproduce: curl -k -s 'https://target.com/secret' -H 'X-Forwarded-For: 127.0.0.1'
```

---

## Wordlist Integration

| File              | Used by              | How                                   |
| ----------------- | -------------------- | ------------------------------------- |
| `paths.txt`       | `-t / --paths`       | Custom traversal strings              |
| `headers.txt`     | `-H / --headers`     | Extra spoof headers (`Header: value`) |
| `payloads.txt`    | `-i / --injection`   | Custom payload snippets               |
| `user_agents.txt` | `-U / --user-agents` | One UA string per line                |
| `endpaths.txt`    | `-E / --endpaths`    | Suffixes appended after the resource  |

If a file is **missing**, 403X automatically falls back to its built-in mini list, so it *never* crashes.

---

## Modules in Depth

<details>
<summary>Click to expand the full 22-module list …</summary>

1. **HTTP Method**  `-m`
2. **Protocol Version**  `--protocol-version`
3. **Header Spoof**  `-H`
4. **Advanced Path**  `--advanced-path`
5. **Exhaustive Case**  `--exhaustive-case`
6. **Double Encoding**  `--double-encoding`
7. **Protocol Scheme Switch**  `-P`
8. **Port Override**  `-p`
9. **Path Traversal**  `-t`
10. **End-Path Suffix**  `-E`
11. **URL Encoding**  `-e`
12. **Case Sensitivity**  `-c`
13. **File Extension**  `-x`
14. **Param Pollution**  `-q`
15. **User-Agent Rotation**  `-U`
16. **Auth Header Tricks**  `-A`
17. **Dot-Slash**  `-d`
18. **Special Characters**  `-s`
19. **Null-Byte Injection**  `-n`
20. **Payload Injection**  `-i`
21. **Cache Bypass**  `-C`
22. **Fuzzing Mutations**  `-f`

</details>

---

## Requirements

* **Python ≥ 3.7**
* **Requests** ≥ 2.20
* **Colorama** (pretty colours)

*All other libs come with the standard library.*

---

## Contributing

1. **Fork** → **Branch** → **Code** → **Pull Request**
2. Keep code `black`-formatted, add docstrings & examples.
3. New bypass ideas? Add a dedicated function + flag.

```bash
git clone https://github.com/YourUserName/403x.git
cd 403x
git checkout -b feature-awesome-bypass
# hack hack hack
git commit -m "feat: add awesome bypass"
git push origin feature-awesome-bypass
```

---

## License

Released under the [MIT License](https://choosealicense.com/licenses/mit/).

---

## Author

Created by [Vahe Demirkhanyan](mailto:vdemirkhanyan@yahoo.ca)

<p align="center">
  <strong>Knock politely, then bash the door down – with 403X.</strong>
</p>
