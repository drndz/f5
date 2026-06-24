# F5 Validation Routine

This project contains a read-only Java SSH validation runner for BIG-IP F5 and generic Linux VMs, plus a plain Java report generator. It requires JDK 17 or newer and uses the bundled open-source JSch jar in `lib/`; it does not require Maven or Gradle.

The helper scripts use this JDK lookup order:

1. `F5_VALIDATION_JDK_HOME`
2. `config/.JDK`
3. `JAVA_HOME`
4. `java` and `javac` from `PATH`

To configure a specific JDK for this checkout, write its directory to `config/.JDK`. Paths with spaces are supported:

```bash
printf 'C:\Program Files\Java\jdk-17' > config/.JDK
```

Run Java tests:

```bash
/cygdrive/c/cygwin64/bin/bash -lc 'cd /cygdrive/c/f5_git && ./scripts/test-java.sh'
```

## Run Against Multiple SSH Targets

Create `config/f5-targets.csv` from the example file:

```bash
cp config/f5-targets.csv.example config/f5-targets.csv
```

Set one master key in the local ignored config file. Do not store this key in the CSV or commit it:

```bash
printf 'use-a-long-random-master-key' > config/.F5_MASTER_KEY
```

Encrypt each F5 password and paste the encrypted value into the CSV:

```bash
./scripts/encrypt-password.sh
```

CSV format:

```csv
name,mgmt_ip,username,encrypted_password,target_type
f5-east,10.0.10.11,admin,v1:...,auto
app-vm-01,10.0.20.21,azureuser,v1:...,vm
```

`target_type` can be `auto`, `f5`, or `vm`. Blank or old four-column rows default to `auto`; the validator detects F5/BIG-IP dynamically, primarily by checking `/etc/issue` for `BIG-IP`, with other F5 evidence as fallback.

Run the validation across all configured SSH targets:

```bash
./scripts/run-f5-fleet-validation.sh config/f5-targets.csv f5-validation-results
```

From Cygwin Bash:

```bash
cd CHECKOUT_LOC/f5_git
./scripts/run-f5-fleet-validation.sh config/f5-targets.csv f5-validation-results
```

The fleet runner does not copy scripts to target machines. It uses Java SSH through the bundled JSch library and runs read-only commands such as `hostname`, `uptime`, `df`, `ps`, `systemctl`, and `ss`. When a target is detected as F5/BIG-IP, it also runs read-only F5 checks such as `tmsh` service inspection and expected external listener validation. VM and F5 results appear in the same unified report.

Before every SSH command is sent to a target, the runner prints the exact command and waits for operator confirmation. Type `Y` to send that command. Any other response rejects the command and the target validation is marked failed. After each command runs, the runner prints the exit status, stdout, and stderr in the terminal.

To approve every SSH command for one run without prompting:

```bash
./scripts/run-f5-fleet-validation.sh --yes config/f5-targets.csv f5-validation-results
```

For direct Java runs, set `SSH_APPROVE_ALL_COMMANDS=true`.

Password-based SSH is handled directly by Java/JSch. The runner reads `config/.F5_MASTER_KEY`, decrypts the CSV password in memory, and passes it to the Java SSH session. The CSV stores only encrypted password values. `F5_MASTER_KEY` can still be set as an environment variable to override the file in automation.

## Generate Unified Report

Collect all generated JSON files into one directory, then run:

```bash
./scripts/test-java.sh
./scripts/generate-report.sh f5-validation-results f5-validation-report.md
```

If you prefer to run the Java commands directly:

```bash
export F5_VALIDATION_JDK_HOME="$(cat config/.JDK)"
mkdir -p build/classes
find src/main/java -name "*.java" -print > build/sources-main.txt
"$F5_VALIDATION_JDK_HOME/bin/javac" -cp "lib/*" -d build/classes @build/sources-main.txt
"$F5_VALIDATION_JDK_HOME/bin/java" -cp "build/classes:lib/*" org.qypp.Main report --input-dir f5-validation-results --output f5-validation-report.md
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

Fleet runner settings:

- `F5_VALIDATION_JDK_HOME`: optional JDK directory used by the local Java helper scripts.
- `config/.JDK`: optional local JDK directory file used by helper scripts when `F5_VALIDATION_JDK_HOME` is not set. This file is ignored by git.
- `config/.F5_MASTER_KEY`: local master key file used to decrypt CSV passwords. This file is ignored by git and must not be committed.
- `F5_MASTER_KEY`: optional environment override for automation.
- `SSH_CONNECT_TIMEOUT_MILLIS`: Java SSH connect timeout, default `10000`.
- `SSH_COMMAND_TIMEOUT_MILLIS`: Java SSH command channel timeout, default `10000`.
- `SSH_STRICT_HOST_KEY_CHECKING`: JSch host key checking setting, default `no`.
- `SSH_APPROVE_ALL_COMMANDS`: set to `true` to run all SSH commands without per-command confirmation.
