# F5 Validation Routine

This project contains a read-only Java SSH validation runner for BIG-IP F5 and generic Linux VMs, plus a plain Java report generator. It requires JDK 17 or newer and uses the bundled open-source JSch jar in `lib/`; it does not require Maven or Gradle.

The helper scripts use this JDK lookup order:

1. `F5_VALIDATION_JDK_HOME`
2. `<effective-config>/.JDK`
3. `JAVA_HOME`
4. `java` and `javac` from `PATH`

The effective config directory is selected by `config/.conf_effective`. If that file is missing, empty, or contains only comments, the default is `config/real`. Put `real` in the file for private local values, or `sample` to run against reference values:

```bash
printf 'real\n' > config/.conf_effective
```

`config/sample` contains reference values only. `config/real` contains private local values and is ignored by git.

To configure a specific JDK for this checkout, write its directory to `<effective-config>/.JDK`. Paths with spaces are supported:

```bash
printf 'C:\Program Files\Java\jdk-17' > config/real/.JDK
```

Run Java tests:

```bash
/cygdrive/c/cygwin64/bin/bash -lc 'cd /cygdrive/c/f5_git && ./scripts/test-java.sh'
```

## Run Against Multiple SSH Targets

Create private config values under `config/real` from the reference files in `config/sample`:

```bash
mkdir -p config/real
cp config/sample/f5-targets.csv config/real/f5-targets.csv
cp config/sample/vm_outbound_checks.csv config/real/vm_outbound_checks.csv
cp config/sample/.part_prefix_filter config/real/.part_prefix_filter
```

If you want encrypted CSV passwords, set one master key in the local ignored config file. Do not store this key in the CSV or commit it:

```bash
printf 'use-a-long-random-master-key' > config/real/.MASTER_KEY
```

Encrypt each F5 password and paste the encrypted value into the CSV:

```bash
./scripts/encrypt-password.sh
```

CSV format:

```csv
name,mgmt_ip,username,password,target_type
f5-east,10.0.10.11,admin,v1:...,auto
app-vm-01,10.0.20.21,azureuser,plain-password,vm
```

Password values with the `v1:` prefix are decrypted with `.MASTER_KEY`. Password values without the `v1:` prefix are used literally and do not require `.MASTER_KEY`.

`target_type` can be `auto`, `f5`, or `vm`. Blank or old four-column rows default to `auto`; the validator detects F5/BIG-IP dynamically, primarily by checking `/etc/issue` for `BIG-IP`, with other F5 evidence as fallback.

Optional outbound connectivity checks are read from `<effective-config>/vm_outbound_checks.csv` when that file exists. The same check list is executed from every configured VM/F5 target:

CSV format:

```csv
name,host,port,protocol
external-https,203.0.113.10,443,TCP
external-dns,203.0.113.53,53,UDP
external-radius-sim,203.0.113.181,1812,UDP
```

`protocol` must be `TCP` or `UDP`. The `host` value can be either a DNS name or an IP address. DNS is resolved on the remote VM/F5, and the report shows both the configured host and the resolved IP. TCP checks use `nc` when available, otherwise Bash `/dev/tcp`. UDP checks require `nc`/netcat on the target. UDP port `53` sends a minimal DNS query packet, UDP ports `1812` and `1813` send a minimal RADIUS-style packet, and other UDP ports send a one-byte generic datagram. UDP checks report bytes sent and bytes received; they pass only when response bytes are received. Results are shown in the report under `Outbound Connectivity`.

Optional F5 partition/pool filtering is read from `<effective-config>/.part_prefix_filter` when that file exists. Put one partition-name prefix on the first non-comment line:

Example content:

```text
MyTenant
```

With this file present, only F5 partitions whose names start with `MyTenant` are shown in the F5 partition/pool report. Delete the file, leave it empty, or comment all lines to show all partitions.

For F5 targets, the partition/pool inventory also correlates pool members, virtual servers, client SSL profiles, configured certificate objects, chain certificate objects, and virtual-server runtime statistics. Installed certificate metadata is read from each partition with `tmsh list sys crypto cert`. Certificate start/end dates are enriched from BIG-IP's public certificate file objects by asking tmsh for `sys file ssl-cert ... cache-path` and passing that tmsh-returned public certificate asset to `openssl x509 -startdate -enddate`; the validator does not scan `/config/ssl/ssl.crt`, `/config/filestore`, or guess certificate filenames. This remains compatible with HSM-backed private keys because only the public certificate object is read, not private key material. The report shows certificate fields that tmsh returns, including expiry, subject, issuer, common name, fingerprint, key size, and issuer-certificate references when present. A certificate start date is shown only when it is returned by the tmsh certificate repository path; it is not guessed from file timestamps or object creation time. The report shows each VIP destination, protocol, pool member IP:port values, current VIP connections, bits/bytes/packets in and out when exposed by BIG-IP, SSL profile, certificate validity, and chain details. Pool member IP:port values discovered from F5 pools are also tested from the F5 using the outbound connectivity check command and appear in `Outbound Connectivity` as `pool:<partition>/<pool>:<ip>:<port>` rows.

When `rrdtool` is available on an F5 target, the report also includes the last 48 hours of read-only RRD time-series from useful local CPU and traffic files such as `cpu`, `rollupcpu`, `throughput`, `connections`, `bladeconnections`, `bwgain`, and related BIG-IP RRDs. Each RRD data source is shown as a normalized graph with raw min/max values.

Run the validation across all configured SSH targets:

```bash
./scripts/run-f5-fleet-validation.sh
```

From Cygwin Bash:

```bash
cd CHECKOUT_LOC/f5_git
./scripts/run-f5-fleet-validation.sh
```

If no targets CSV argument is supplied, the fleet script reads `<effective-config>/f5-targets.csv`.

The fleet runner does not copy scripts to target machines. It uses Java SSH through the bundled JSch library and runs commands as the SSH login user only; it does not test sudo, feed sudo passwords, or elevate to root. It runs read-only commands such as `hostname`, `uptime`, `df`, `ps`, `systemctl`, and `netstat`. When a target is detected as F5/BIG-IP, it also runs read-only F5 checks such as `tmsh` service inspection and expected external listener validation. VM and F5 results appear in the same unified report.

Before every SSH command is sent to a target, the runner prints the exact command and waits for operator confirmation. Type `Y` to send that command. Any other response rejects the command and the target validation is marked failed. After each command runs, the runner prints the exit status, stdout, and stderr in the terminal.

To approve every SSH command for one run without prompting:

```bash
./scripts/run-f5-fleet-validation.sh --yes
```

For direct Java runs, set `SSH_APPROVE_ALL_COMMANDS=true`.

Password-based SSH is handled directly by Java/JSch. CSV password values with the `v1:` prefix are decrypted in memory using `<effective-config>/.MASTER_KEY` or the `MASTER_KEY` environment variable. CSV password values without the `v1:` prefix are used as literal plain passwords and do not require a master key.

## Generate Unified Report

Collect all generated JSON files into one directory, then run:

```bash
./scripts/test-java.sh
./scripts/generate-report.sh f5-validation-results f5-validation-report.md
```

If you prefer to run the Java commands directly:

```bash
export F5_VALIDATION_JDK_HOME="$(cat config/real/.JDK)"
mkdir -p build/classes
find src/main/java -name "*.java" -print > build/sources-main.txt
"$F5_VALIDATION_JDK_HOME/bin/javac" -cp "lib/*" -d build/classes @build/sources-main.txt
"$F5_VALIDATION_JDK_HOME/bin/java" -cp "build/classes:lib/*" org.qypp.Main report --input-dir f5-validation-results --output f5-validation-report.md
```

Reports hide full validation command bodies by default. Runtime timing rows show the check description and extracted arguments only. Add `--details-report` when generating a report to include the full command column:

```bash
./scripts/generate-report.sh f5-validation-results f5-validation-report.md --details-report
```

## Configuration

- `EXPECTED_EXTERNAL_PORTS`: allowed listening ports, default `443`.
- `CRITICAL_SERVICES`: service names expected to be up. Defaults to empty unless configured.
- `LOG_LOOKBACK_LINES`: lines tailed from each `/var/log` file, default `5000`.
- `OUTPUT_DIR`: collector output directory, default `./f5-validation-results`.
- `DISK_PATHS`: space-separated VM disk paths to check, default `/`.
- `CPU_WARN_PERCENT` and `CPU_FAIL_PERCENT`: VM CPU thresholds, defaults `80` and `95`.
- `MEMORY_WARN_PERCENT` and `MEMORY_FAIL_PERCENT`: VM memory thresholds, defaults `80` and `90`.
- `DISK_WARN_PERCENT` and `DISK_FAIL_PERCENT`: VM disk thresholds, defaults `80` and `90`.
- `OUTBOUND_CHECK_TIMEOUT_SECONDS`: outbound TCP/UDP check timeout, default `5`.

Fleet runner settings:

- `F5_VALIDATION_JDK_HOME`: optional JDK directory used by the local Java helper scripts.
- `config/.conf_effective`: local selector for the effective config directory. Defaults to `real` when empty or missing. This file is ignored by git.
- `<effective-config>/.JDK`: optional local JDK directory file used by helper scripts when `F5_VALIDATION_JDK_HOME` is not set.
- `<effective-config>/.MASTER_KEY`: local master key file used only when one or more CSV password values use the `v1:` encrypted format. This file must not be committed.
- `MASTER_KEY`: optional environment override for encrypted CSV passwords.
- `SSH_CONNECT_TIMEOUT_MILLIS`: Java SSH connect timeout, default `10000`.
- `SSH_COMMAND_TIMEOUT_MILLIS`: Java SSH command channel timeout, default `10000`.
- `SSH_STRICT_HOST_KEY_CHECKING`: JSch host key checking setting, default `no`.
- `SSH_APPROVE_ALL_COMMANDS`: set to `true` to run all SSH commands without per-command confirmation.
- `--details-ssh`: fleet runner flag that prints full SSH command bodies in the console. Default console output shows only check descriptions and extracted arguments.
