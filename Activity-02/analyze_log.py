"""Template script for IT 390R log‑analysis lab

Students: complete the **TODO** sections in `analyze_failed_logins` and
`analyze_successful_creds`.  All other tasks already work, so you can run the
script right away to explore the output format.
"""

import argparse
import re
from collections import Counter, defaultdict
from datetime import datetime

# ── Regex patterns ──────────────────────────────────────────────────────────
FAILED_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"login attempt \[.*?/.*?\] failed"
)

NEW_CONN_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z "
    r"\[cowrie\.ssh\.factory\.CowrieSSHFactory\] New connection: "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+):\d+"
)

SUCCESS_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"login attempt \[(?P<user>[^/]+)/(?P<pw>[^\]]+)\] succeeded"
)

FINGERPRINT_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"SSH client hassh fingerprint: (?P<fp>[0-9a-f:]{32})"
)

COMMAND_PATTERN = re.compile(r"CMD: (.+)")

# ── Helper to print tables ──────────────────────────────────────────────────

def _print_counter(counter: Counter, head1: str, head2: str, sort_keys=False):
    """Nicely format a Counter as a two‑column table."""
    width = max((len(str(k)) for k in counter), default=len(head1))
    print(f"{head1:<{width}} {head2:>8}")
    print("-" * (width + 9))
    items = sorted(counter.items()) if sort_keys else counter.most_common()
    for key, cnt in items:
        print(f"{key:<{width}} {cnt:>8}")

# ── Task 1: Failed logins ───────────────────────────────────────────────────

def analyze_failed_logins(path: str, min_count: int):
    """Parse *failed* SSH login attempts and show a count per source IP."""
    failed_ips = Counter()
    
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ip = match.group("ip")
                failed_ips[ip] += 1

    # Filter out IPs with fewer than min_count failed logins
    filtered_ips = Counter({ip: count for ip, count in failed_ips.items() if count >= min_count})
    
    _print_counter(filtered_ips, "Source IP", "Failures")
#CHATGPT prompt: "create code for analyzing failed logins and count how many times"

# ── Task 2: Connections (already done) ──────────────────────────────────────

def connections(path: str):
    per_min = Counter()
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = NEW_CONN_PATTERN.search(line)
            if m:
                dt = datetime.strptime(m.group("ts")[:19], "%Y-%m-%dT%H:%M:%S")
                per_min[dt.strftime("%Y-%m-%d %H:%M")] += 1
    print("Connections per minute")
    _print_counter(per_min, "Timestamp", "Count", sort_keys=True)

# ── Task 3: Successful credentials ──────────────────────────────────────────

def analyze_successful_creds(path: str):
    """Display username/password pairs that *succeeded* and how many unique IPs used each."""
    cred_map = defaultdict(set)

    with open(path, encoding="utf-8") as fp:
        for line in fp:
            match = SUCCESS_LOGIN_PATTERN.search(line)
            if match:
                user = match.group("user")
                pw = match.group("pw")
                ip = match.group("ip")
                cred_map[(user, pw)].add(ip)

    # Sort by descending number of unique IPs
    sorted_creds = sorted(cred_map.items(), key=lambda item: len(item[1]), reverse=True)

    print(f"{'Username':<15} {'Password':<15} {'IP Count'}")
    print("-" * 45)
    for (user, pw), ips in sorted_creds:
        print(f"{user:<15} {pw:<15} {len(ips)}")
#CHATGPT prompt: "create code for showing successful username and pairs that succeed, and count how many times unique IP is used"

# ── Task 4: Bot fingerprints ────────────────────────────────────────────────

def identify_bots(path: str, min_ips: int):
    fp_map = defaultdict(set)
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = FINGERPRINT_PATTERN.search(line)
            if m:
                fp_map[m.group("fp")].add(m.group("ip"))
    bots = {fp: ips for fp, ips in fp_map.items() if len(ips) >= min_ips}
    print(f"Fingerprints seen from ≥ {min_ips} unique IPs")
    print(f"{'Fingerprint':<47} {'IPs':>6}")
    print("-" * 53)
    for fp, ips in sorted(bots.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{fp:<47} {len(ips):>6}")

# ── Extra Task: Top commands ────────────────────────────────────────────────

def analyze_top_commands(path: str):
    """Show most common shell commands issued by attackers."""
    cmd_counter = Counter()

    with open(path, encoding="utf-8") as fp:
        for line in fp:
            match = COMMAND_PATTERN.search(line)
            if match:
                cmd = match.group(1).strip()
                cmd_counter[cmd] += 1

    _print_counter(cmd_counter, "Command", "Count")
#CHATGPT prompt: "create code for showing top commands that attackers used"

# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Cowrie log analyzer — student template")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--task",
                        required=True,
                        choices=["failed-logins", "connections",
                                 "successful-creds", "identify-bots", "top-commands"],
                        help="Which analysis to run")
    parser.add_argument("--min-count", type=int, default=1,
                        help="Min events to report (failed-logins)")
    parser.add_argument("--min-ips", type=int, default=3,
                        help="Min IPs per fingerprint (identify-bots)")
    args = parser.parse_args()

    if args.task == "failed-logins":
        analyze_failed_logins(args.logfile, args.min_count)
    elif args.task == "connections":
        connections(args.logfile)
    elif args.task == "successful-creds":
        analyze_successful_creds(args.logfile)
    elif args.task == "identify-bots":
        identify_bots(args.logfile, args.min_ips)
    elif args.task == "top-commands":
        analyze_top_commands(args.logfile)

if __name__ == "__main__":
    main()
