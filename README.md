# check-domain-dns

Nagios Core DNS integrity monitoring with an independent JSON baseline for each domain.

## Installation on Debian

```bash
sudo apt-get install python3-dnspython
```

Install `check_domain_dns.py` in your Nagios plugin directory. The baseline state directory is **not** tracked in Git.

```bash
sudo install -o root -g root -m 0755 check_domain_dns.py /usr/lib/nagios/plugins/check_domain_dns.py
sudo install -d -o root -g nagios -m 0750 /var/lib/nagios4/check-domain-dns
sudo /usr/lib/nagios/plugins/check_domain_dns.py example.org --baseline
sudo chown root:nagios /var/lib/nagios4/check-domain-dns/example.org.json
sudo chmod 0640 /var/lib/nagios4/check-domain-dns/example.org.json
sudo -u nagios /usr/lib/nagios/plugins/check_domain_dns.py example.org
```

Ensure the parent directory is traversable by the Nagios user. The monitor needs read-only access to baseline files. Create/update baselines as root, review their contents, then keep files root:nagios 0640 so the nagios service account cannot silently redefine the trusted state.

## Usage

```bash
check_domain_dns.py example.org --baseline
check_domain_dns.py example.org --baseline --exclude www,caa
check_domain_dns.py example.org
check_domain_dns.py example.org --double-check 1.1.1.1
check_domain_dns.py example.org --single-check 9.9.9.9
check_domain_dns.py example.org --update
check_domain_dns.py example.org --update --exclude www
```

The checked sets are NS, MX, CAA at the apex, plus A and AAAA for the apex and `www.` host. The sets are sorted and deduplicated before comparison. NoAnswer (including absent CAA/AAAA) is recorded as an empty set; NXDOMAIN, SERVFAIL and timeouts are failures. Exit codes: OK=0, WARNING=1 for query errors, CRITICAL=2 for changes or resolver disagreements, UNKNOWN=3 for missing or invalid baseline / configuration.

`--baseline` refuses an existing file; `--update` requires it. Updates preserve previous exclusions unless a new `--exclude` is supplied. Query failures or mismatches block baseline writes. State JSON is written atomically. **Review results from another independent resolver before accepting any baseline update.** The monitor intentionally never learns changed records automatically.

`--double-check` compares local and explicitly selected public DNS resolver, in addition to the saved baseline. `--single-check` instead uses only the selected server. Public resolvers may differ legitimately because of CDNs, geographic load balancing or cached answers; consider initially using double-check only for predictable records. This is not DNSSEC verification and cannot prove that a local answer is authentic.

## Nagios retries

Normal Nagios Core hard-state rules cannot give an immediate CRITICAL notification while delaying WARNING on the **same** service. Setting `max_check_attempts 1` makes both CRITICAL changes and WARNING query failures hard states immediately. A future split into separate integrity and availability services can provide distinct retry policies. For availability: `max_check_attempts 3`, `retry_interval 2` gives up to two subsequent attempts, spaced two minutes apart (roughly four minutes until the third attempt). With a single service and `max_check_attempts 3`, both warning and critical states are delayed.

Define your own Nagios service commands and check intervals. A missing baseline reports UNKNOWN; the plugin never creates one automatically.

## Security / operational notes

The JSON baseline is trusted security monitoring configuration. Preserve it across Nagios deployments and backups. Keep the state directory outside the Git working tree, don't allow arbitrary services to modify it, and review the baseline contents before activation. Detecting resolver poisoning requires an independent vantage point; this plugin does not provide DNSSEC validation or geographic quorum, and caching / DNS propagation may cause transient mismatches.

## License

Licensed under the GNU General Public License v3.0 or later (`GPL-3.0-or-later`). See [LICENSE](LICENSE).
