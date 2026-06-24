package org.qypp.fleet;

import org.qypp.f5.F5Check;
import org.qypp.f5.F5Report;
import org.qypp.f5.ReportArtifactWriter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class FleetSshValidator {
    private FleetSshValidator() {
    }

    public static void run(Path targetsFile, Path outputDir, String masterKey) throws IOException {
        List<F5Report> reports = new ArrayList<>();
        String runTimestamp = safeTimestamp(Instant.now().toString());
        Path runOutputDir = outputDir.resolve(runTimestamp);
        Files.createDirectories(runOutputDir);
        for (FleetTarget target : readTargets(targetsFile)) {
            System.out.println("Running " + target.targetType() + " validation over Java SSH on " + target.name() + " (" + target.host() + ")");
            F5Report report = validate(target, masterKey);
            reports.add(report);
            Files.writeString(runOutputDir.resolve(target.name() + "-" + safeFileName(report.hostname()) + ".json"), toJson(report));
        }
        reports.sort(Comparator.comparing(F5Report::hostname));
        Path reportFile = runOutputDir.resolve("validation-report.md");
        ReportArtifactWriter.write(reportFile, reports);
        System.out.println("Wrote " + reportFile.toAbsolutePath());
    }

    private static List<FleetTarget> readTargets(Path targetsFile) throws IOException {
        List<FleetTarget> targets = new ArrayList<>();
        for (String line : Files.readAllLines(targetsFile)) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("name,")) {
                continue;
            }
            targets.add(FleetTarget.parse(trimmed));
        }
        return targets;
    }

    private static F5Report validate(FleetTarget target, String masterKey) {
        String collectedAt = Instant.now().toString();
        List<F5Check> checks = new ArrayList<>();
        String password = PasswordCrypto.decrypt(target.encryptedPassword(), masterKey);
        int connectTimeout = intEnv("SSH_CONNECT_TIMEOUT_MILLIS", 10_000);
        int commandTimeout = intEnv("SSH_COMMAND_TIMEOUT_MILLIS", 10_000);

        boolean allowTmshFallback = shouldProbeTmsh(target);
        try (SshCommandClient ssh = new SshCommandClient(target.host(), target.username(), password, connectTimeout, commandTimeout, allowTmshFallback)) {
            checks.add(new F5Check("ssh_connectivity", "PASS", "Java SSH commands executed successfully."));
            boolean tmshF5Detected = allowTmshFallback && ssh.detectF5TmshShell();
            PrivilegeAccess privilege = privilegeAccess(ssh, password);
            String privilegeMode = privilege.mode();
            boolean privilegedCollection = privilege.privileged();
            checks.add(new F5Check("privileged_collection", "PASS", privilegedCollection
                    ? "Read-only diagnostics are using " + privilegeMode + " privileges."
                    : "No root or usable sudo privilege detected; using standard read-only diagnostics."));
            String hostname = valueOr(target.name(), ssh.run("uname -n 2>/dev/null || tmsh list sys global-settings hostname 2>/dev/null | awk '/hostname/ {print $2; exit}' || hostname 2>/dev/null || echo unknown"));
            String os = valueOr("unknown", ssh.run("sed -n 's/^PRETTY_NAME=//p; s/^NAME=//p' /etc/os-release 2>/dev/null | head -n 1 | tr -d '\\042' || uname -a 2>/dev/null || echo unknown"));
            String f5Issue = ssh.run("cat /etc/issue 2>/dev/null || true");
            String f5Evidence = f5Issue + "\n" + ssh.run("if command -v tmsh >/dev/null 2>&1; then echo tmsh-present; fi; cat /VERSION /etc/product /etc/os-release 2>/dev/null || true");
            boolean f5Detected = tmshF5Detected || f5Detected(os + "\n" + f5Evidence);
            FleetTarget effectiveTarget = new FleetTarget(target.name(), target.host(), target.username(), target.encryptedPassword(), f5Detected ? "f5" : "vm");
            checks.add(new F5Check("target_detection", "PASS", f5Detected
                    ? "F5/BIG-IP detected from remote OS evidence; F5-specific checks are enabled."
                    : "F5/BIG-IP was not detected; running standard VM checks only."));
            String uptime = valueOr("unknown", ssh.run("uptime -p 2>/dev/null || uptime 2>/dev/null || echo unknown"));
            int processCount = intValue(ssh.run("ps -eo pid= 2>/dev/null | wc -l | tr -d ' '"));
            long memoryTotal = longValue(ssh.run("awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0"));
            long memoryAvailable = longValue(ssh.run("awk '/MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0"));
            long memoryUsed = Math.max(0, memoryTotal - memoryAvailable);
            long memoryPercent = percent(memoryUsed, memoryTotal);
            long cpuCoreCount = Math.max(1, longValue(ssh.run("getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1")));
            String loadAverageOutput = ssh.run("awk '{print $1\" \"$2\" \"$3}' /proc/loadavg 2>/dev/null || echo '0 0 0'");
            double[] loadAverages = loadAverages(loadAverageOutput);
            long loadAverage1mPercent = Math.round(loadAverages[0] * 100.0 / cpuCoreCount);
            long loadAverage5mPercent = Math.round(loadAverages[1] * 100.0 / cpuCoreCount);
            long loadAverage15mPercent = Math.round(loadAverages[2] * 100.0 / cpuCoreCount);
            long cpuPercent = loadAverage1mPercent;
            long diskPercent = longValue(ssh.run("df -P " + env("DISK_PATHS", "/") + " 2>/dev/null | awk 'NR>1 {gsub(/%/, \"\", $5); if ($5 > max) max=$5} END {print max+0}'"));
            List<String> diskMounts = lines(ssh.run("df -Pk " + env("DISK_PATHS", "/") + " 2>/dev/null | awk 'NR>1 {gsub(/%/, \"\", $5); printf \"%s|%.2f|%.2f|%.2f|%.2f|%s%%\\n\", $6, $2/1048576, $3/1048576, $4/1048576, $4/1048576, $5}'"));
            long ipConnectionCount = longValue(runReadOnly(ssh, privilege, "cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || ss -H -tun 2>/dev/null | wc -l | tr -d ' ' || echo 0"));
            long ipConnectionMax = longValue(runReadOnly(ssh, privilege, "cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0"));
            List<String> activeConnections = lines(runReadOnly(ssh, privilege, activeConnectionsCommand()));
            String serviceOutput = serviceOutput(effectiveTarget, ssh, privilege);
            int serviceCount = nonBlankLines(serviceOutput);
            List<String> runningServices = lines(serviceOutput);
            List<String> processesByCpu = lines(runReadOnly(ssh, privilege, "ps -eo pid=,pcpu=,pmem=,rss=,comm= --sort=-pcpu 2>/dev/null | awk '{printf \"%s|%s|%s|%.2f|%s\\n\", $1, $2, $3, $4/1024, $5}'"));
            List<String> processesByMemory = lines(runReadOnly(ssh, privilege, "ps -eo pid=,pcpu=,pmem=,rss=,comm= --sort=-pmem 2>/dev/null | awk '{printf \"%s|%s|%s|%.2f|%s\\n\", $1, $2, $3, $4/1024, $5}'"));
            List<String> networkInterfaces = lines(ssh.run("for iface in /sys/class/net/*; do name=${iface##*/}; rx=$(cat \"$iface/statistics/rx_bytes\" 2>/dev/null || echo 0); tx=$(cat \"$iface/statistics/tx_bytes\" 2>/dev/null || echo 0); ips=$(ip -o addr show dev \"$name\" 2>/dev/null | awk '{print $4}' | paste -sd ',' -); awk -v n=\"$name\" -v ips=\"$ips\" -v rx=\"$rx\" -v tx=\"$tx\" 'BEGIN {printf \"%s|%s|%.3f|%.3f\\n\", n, ips, rx/1073741824, tx/1073741824}'; done"));
            String listenerOutput = listenerOutput(ssh, privilege);
            Map<String, String> serviceNames = serviceNames(ssh.run("awk '!/^#/ && $2 ~ /^[0-9]+\\/(tcp|udp)$/ {split($2,a,\"/\"); print a[2]\"|\"a[1]\"|\"$1}' /etc/services 2>/dev/null || true"));
            int listenerCount = nonBlankLines(listenerOutput);
            List<Integer> ports = ports(listenerOutput);
            List<String> listeningEndpoints = listeningEndpoints(listenerOutput, serviceNames);
            List<String> criticalDown = criticalDown(effectiveTarget, serviceOutput);
            List<String> logErrors = lines(runReadOnly(ssh, privilege, "find /var/log -maxdepth 1 -type f 2>/dev/null | while IFS= read -r file; do tail -n " + logLookback(effectiveTarget) + " \"$file\" 2>/dev/null; done | grep -Ei 'error|fail|fatal|crit|panic|segfault|denied' | tail -n 100 || true"));

            addCriticalCheck(checks, criticalDown, effectiveTarget);
            addPortCheck(checks, ports, effectiveTarget);
            addThreshold(checks, "load_1m", loadAverage1mPercent, intEnv("CPU_WARN_PERCENT", 80), intEnv("CPU_FAIL_PERCENT", 95), "1 minute load is " + loadAverage1mPercent + "% of available cores.");
            addThreshold(checks, "memory", memoryPercent, intEnv("MEMORY_WARN_PERCENT", 80), intEnv("MEMORY_FAIL_PERCENT", 90), "Memory usage is " + memoryPercent + "%.");
            addThreshold(checks, "disk", diskPercent, intEnv("DISK_WARN_PERCENT", 80), intEnv("DISK_FAIL_PERCENT", 90), "Maximum disk usage is " + diskPercent + "%.");
            checks.add(new F5Check("recent_logs", logErrors.isEmpty() ? "PASS" : "WARN", logErrors.isEmpty() ? "No recent error patterns found in /var/log." : "Recent error patterns found in /var/log. See report details."));

            return new F5Report(target.name(), effectiveTarget.targetType(), hostname, collectedAt, status(checks), privilegeMode, privilegedCollection, os, uptime, processCount, cpuCoreCount, cpuPercent, loadAverages[0], loadAverages[1], loadAverages[2], loadAverage1mPercent, loadAverage5mPercent, loadAverage15mPercent, diskPercent, serviceCount, listenerCount, memoryUsed, memoryTotal, diskMounts, ipConnectionCount, ipConnectionMax, activeConnections, criticalDown, ports, listeningEndpoints, processesByCpu, processesByMemory, runningServices, networkInterfaces, logErrors, checks);
        } catch (RuntimeException | IOException exception) {
            checks.add(new F5Check("ssh_connectivity", "FAIL", "Could not run Java SSH commands on " + target.host() + ": " + exception.getMessage()));
            return new F5Report(
                    target.name(), target.targetType(), target.host(), collectedAt, "FAIL", "standard", false,
                    "unknown", "unknown", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, List.of(), 0, 0, List.of(), List.of(), List.of(), List.of(),
                    List.of(), List.of(), List.of(), List.of(), List.of(), checks
            );
        }
    }

    private static boolean shouldProbeTmsh(FleetTarget target) {
        String type = target.targetType();
        return type == null || type.isBlank() || "auto".equalsIgnoreCase(type) || "f5".equalsIgnoreCase(type);
    }

    private static PrivilegeAccess privilegeAccess(SshCommandClient ssh, String password) {
        if ("0".equals(ssh.run("id -u 2>/dev/null || echo 999").strip())) {
            return new PrivilegeAccess("root", "", false);
        }
        if (ssh.succeeds("command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null", "")) {
            return new PrivilegeAccess("sudo", "", false);
        }
        if (ssh.succeeds("command -v sudo >/dev/null 2>&1 && sudo -S -p '' true 2>/dev/null", password + "\n")) {
            return new PrivilegeAccess("sudo-password", password, true);
        }
        return new PrivilegeAccess("standard", "", false);
    }

    private static String runReadOnly(SshCommandClient ssh, PrivilegeAccess privilege, String command) {
        return switch (privilege.mode()) {
            case "root" -> ssh.run(command);
            case "sudo" -> ssh.run("sudo -n sh -c " + shellQuote(command));
            case "sudo-password" -> ssh.run("sudo -S -p '' sh -c " + shellQuote(command), privilege.password() + "\n");
            default -> ssh.run(command);
        };
    }

    private static boolean f5Detected(String evidence) {
        String normalized = evidence == null ? "" : evidence.toLowerCase();
        return normalized.contains("big-ip")
                || normalized.contains("bigip")
                || normalized.contains("tmsh-present")
                || normalized.contains("f5 networks")
                || normalized.contains("f5os")
                || normalized.contains("traffic management operating system");
    }

    private static String serviceOutput(FleetTarget target, SshCommandClient ssh, PrivilegeAccess privilege) {
        if ("f5".equalsIgnoreCase(target.targetType())) {
            return ssh.run("if command -v tmsh >/dev/null 2>&1; then tmsh show sys service 2>/dev/null; elif command -v systemctl >/dev/null 2>&1; then echo systemctl; else echo ps; fi").equals("systemctl")
                    ? runReadOnly(ssh, privilege, loadedActiveServicesCommand())
                    : ssh.run("if command -v tmsh >/dev/null 2>&1; then tmsh show sys service 2>/dev/null; else ps -eo comm= 2>/dev/null; fi");
        }
        return ssh.run("if command -v systemctl >/dev/null 2>&1; then echo systemctl; else echo ps; fi").equals("systemctl")
                ? runReadOnly(ssh, privilege, loadedActiveServicesCommand())
                : ssh.run("ps -eo comm= 2>/dev/null");
    }

    private static String loadedActiveServicesCommand() {
        return "systemctl --type=service --state=active --no-pager --no-legend 2>/dev/null | " +
                "while read -r unit load active sub rest; do " +
                "[ \"$load\" = loaded ] && [ \"$active\" = active ] && [ \"$sub\" != exited ] && printf \"%s loaded active %s\\n\" \"$unit\" \"$sub\"; " +
                "done";
    }

    private static String activeConnectionsCommand() {
        return "if command -v ss >/dev/null 2>&1; then " +
                "ss -H -tun 2>/dev/null | awk '" +
                "function clean(endpoint) {gsub(/\\[/, \"\", endpoint); gsub(/\\]/, \"\", endpoint); return endpoint} " +
                "function endpoint_port(endpoint, value) {value=endpoint; sub(/^.*:/, \"\", value); return value} " +
                "function endpoint_ip(endpoint, value) {value=endpoint; sub(/:[^:]*$/, \"\", value); return value} " +
                "function numeric(value) {return value ~ /^[0-9]+$/} " +
                "function connection_direction(localPort, peerPort) {" +
                "if (numeric(localPort) && numeric(peerPort) && localPort < 32768 && peerPort >= 32768) return \"in\"; " +
                "if (numeric(localPort) && numeric(peerPort) && peerPort < 32768 && localPort >= 32768) return \"out\"; " +
                "if (numeric(localPort) && numeric(peerPort) && peerPort < localPort) return \"out\"; " +
                "return \"peer\"} " +
                "{proto=$1; local=clean($(NF-1)); peer=clean($NF); if (peer == \"\" || peer == \"*:*\") next; " +
                "localPort=endpoint_port(local); peerPort=endpoint_port(peer); ip=endpoint_ip(peer); " +
                "if (ip == \"\" || peerPort == \"*\" || ip ~ /^127\\./ || ip == \"::1\" || ip == \"0.0.0.0\" || ip == \"*\") next; " +
                "direction=connection_direction(localPort, peerPort); displayPort=(direction == \"in\" ? localPort : peerPort); " +
                "counts[direction \"|\" proto \"|\" ip \"|\" displayPort]++} " +
                "END {for (key in counts) print key \"|\" counts[key]}' | sort -t'|' -k4,4nr -k2,2 -k3,3; " +
                "fi";
    }

    private static String listenerOutput(SshCommandClient ssh, PrivilegeAccess privilege) {
        String listenerTool = ssh.run("if command -v ss >/dev/null 2>&1; then echo ss; elif command -v netstat >/dev/null 2>&1; then echo netstat; fi");
        if ("ss".equals(listenerTool)) {
            return runReadOnly(ssh, privilege, "ss -H -tulpen 2>/dev/null || ss -H -tulnp 2>/dev/null || ss -H -tuln 2>/dev/null");
        }
        if ("netstat".equals(listenerTool)) {
            return runReadOnly(ssh, privilege, "netstat -tulpen 2>/dev/null || netstat -tuln 2>/dev/null");
        }
        return "";
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    private record PrivilegeAccess(String mode, String password, boolean passwordBacked) {
        boolean privileged() {
            return "root".equals(mode) || "sudo".equals(mode) || "sudo-password".equals(mode);
        }
    }

    private static List<String> criticalDown(FleetTarget target, String serviceOutput) {
        String defaultServices = "f5".equalsIgnoreCase(target.targetType()) ? "mcpd tmm bigd gtmd named httpd sshd restjavad restnoded" : "";
        String services = env("CRITICAL_SERVICES", defaultServices);
        if (services.isBlank()) {
            return List.of();
        }
        List<String> down = new ArrayList<>();
        String lower = serviceOutput.toLowerCase();
        for (String service : services.split("\\s+")) {
            if (!lower.contains(service.toLowerCase())) {
                down.add(service);
            }
        }
        return down;
    }

    private static void addCriticalCheck(List<F5Check> checks, List<String> criticalDown, FleetTarget target) {
        if (criticalDown.isEmpty()) {
            if ("vm".equalsIgnoreCase(target.targetType()) && env("CRITICAL_SERVICES", "").isBlank()) {
                checks.add(new F5Check("critical_services", "WARN", "No CRITICAL_SERVICES configured for this target."));
            } else {
                checks.add(new F5Check("critical_services", "PASS", "All configured critical services appear to be running."));
            }
        } else {
            checks.add(new F5Check("critical_services", "FAIL", "Down or unconfirmed services: " + criticalDown));
        }
    }

    private static void addPortCheck(List<F5Check> checks, List<Integer> ports, FleetTarget target) {
        if (!"f5".equalsIgnoreCase(target.targetType())) {
            checks.add(new F5Check("listeners", "PASS", "Detected " + ports.size() + " unique TCP/UDP listener ports."));
            return;
        }
        List<Integer> expected = new ArrayList<>();
        for (String port : env("EXPECTED_EXTERNAL_PORTS", "443").split("\\s+")) {
            expected.add(Integer.parseInt(port));
        }
        List<Integer> unexpected = ports.stream().filter(port -> !expected.contains(port)).toList();
        checks.add(new F5Check("external_listening_ports", unexpected.isEmpty() ? "PASS" : "FAIL", unexpected.isEmpty() ? "Listening ports match expected set: " + expected + "." : "Unexpected listening ports detected: " + unexpected));
    }

    private static void addThreshold(List<F5Check> checks, String name, long value, int warn, int fail, String detail) {
        checks.add(new F5Check(name, value >= fail ? "FAIL" : value >= warn ? "WARN" : "PASS", detail));
    }

    private static List<Integer> ports(String listenerOutput) {
        List<Integer> ports = new ArrayList<>();
        for (String line : listenerOutput.split("\\R")) {
            ListenerEndpoint endpoint = parseListenerEndpoint(line);
            if (endpoint != null) {
                try {
                    int port = Integer.parseInt(endpoint.port());
                    if (!ports.contains(port)) {
                        ports.add(port);
                    }
                } catch (NumberFormatException ignored) {
                }
            }
        }
        ports.sort(Integer::compareTo);
        return ports;
    }

    private static List<String> listeningEndpoints(String listenerOutput, Map<String, String> serviceNames) {
        List<String> endpoints = new ArrayList<>();
        for (String line : listenerOutput.split("\\R")) {
            ListenerEndpoint endpoint = parseListenerEndpoint(line);
            if (endpoint != null && !endpoint.loopback()) {
                String process = "unknown".equals(endpoint.process()) ? serviceNames.getOrDefault(serviceKey(endpoint.protocol(), endpoint.port()), "unknown") : endpoint.process();
                String value = endpoint.protocol() + "|" + endpoint.address() + "|" + endpoint.port() + "|" + process;
                if (!endpoints.contains(value)) {
                    endpoints.add(value);
                }
            }
        }
        endpoints.sort(String::compareTo);
        return endpoints;
    }

    private static Map<String, String> serviceNames(String output) {
        Map<String, String> serviceNames = new HashMap<>();
        for (String line : lines(output)) {
            String[] parts = line.split("\\|", -1);
            if (parts.length >= 3) {
                serviceNames.putIfAbsent(serviceKey(parts[0], parts[1]), parts[2]);
            }
        }
        return serviceNames;
    }

    private static String serviceKey(String protocol, String port) {
        String normalizedProtocol = protocol == null ? "" : protocol.toLowerCase();
        if (normalizedProtocol.startsWith("tcp")) {
            normalizedProtocol = "tcp";
        } else if (normalizedProtocol.startsWith("udp")) {
            normalizedProtocol = "udp";
        }
        return normalizedProtocol + "|" + port;
    }

    private static ListenerEndpoint parseListenerEndpoint(String line) {
        if (line == null || line.isBlank()) {
            return null;
        }
        String[] parts = line.trim().split("\\s+");
        if (parts.length < 4) {
            return null;
        }
        String protocol = parts[0].toLowerCase();
        String localAddress = parts.length >= 5 ? parts[4] : parts[3];
        if (parts.length >= 4 && parts[1].matches("\\d+") && parts[2].matches("\\d+")) {
            localAddress = parts[3];
        }
        if (!protocol.startsWith("tcp") && !protocol.startsWith("udp")) {
            return null;
        }
        if (parts[0].startsWith("tcp") && parts.length >= 6 && !line.toLowerCase().contains("listen")) {
            return null;
        }
        AddressPort addressPort = addressPort(localAddress);
        if (addressPort == null) {
            return null;
        }
        return new ListenerEndpoint(protocol, addressPort.address(), addressPort.port(), processName(line), isLoopback(addressPort.address()));
    }

    private static AddressPort addressPort(String localAddress) {
        String value = localAddress == null ? "" : localAddress.strip();
        if (value.isBlank()) {
            return null;
        }
        int closeBracket = value.lastIndexOf("]:");
        int colon = closeBracket >= 0 ? closeBracket + 1 : value.lastIndexOf(':');
        if (colon < 0 || colon == value.length() - 1) {
            return null;
        }
        String address = value.substring(0, colon);
        String port = value.substring(colon + 1);
        if (!port.matches("\\d+")) {
            return null;
        }
        address = address.replace("[", "").replace("]", "");
        int scope = address.indexOf('%');
        if (scope >= 0) {
            address = address.substring(0, scope);
        }
        if (address.isBlank()) {
            address = "*";
        }
        return new AddressPort(address, port);
    }

    private static boolean isLoopback(String address) {
        String normalized = address == null ? "" : address.toLowerCase();
        return normalized.equals("localhost")
                || normalized.startsWith("127.")
                || normalized.equals("::1")
                || normalized.equals("0:0:0:0:0:0:0:1");
    }

    private static String processName(String line) {
        int users = line.indexOf("users:(");
        if (users >= 0) {
            int firstQuote = line.indexOf('"', users);
            int secondQuote = firstQuote < 0 ? -1 : line.indexOf('"', firstQuote + 1);
            if (firstQuote >= 0 && secondQuote > firstQuote) {
                return line.substring(firstQuote + 1, secondQuote);
            }
        }
        String[] parts = line.trim().split("\\s+");
        for (int i = parts.length - 1; i >= 0; i--) {
            if (parts[i].matches("\\d+/.+")) {
                return parts[i].substring(parts[i].indexOf('/') + 1);
            }
        }
        return "unknown";
    }

    private record AddressPort(String address, String port) {
    }

    private record ListenerEndpoint(String protocol, String address, String port, String process, boolean loopback) {
    }

    private static String toJson(F5Report report) {
        return """
                {
                  "target_type": "%s",
                  "label": "%s",
                  "hostname": "%s",
                  "collected_at": "%s",
                  "status": "%s",
                  "privilege_mode": "%s",
                  "privileged_collection": %s,
                  "os": "%s",
                  "uptime": "%s",
                  "process_count": %d,
                  "cpu_core_count": %d,
                  "cpu_load_percent": %d,
                  "load_average_1m": %.2f,
                  "load_average_5m": %.2f,
                  "load_average_15m": %.2f,
                  "load_average_1m_percent": %d,
                  "load_average_5m_percent": %d,
                  "load_average_15m_percent": %d,
                  "disk_used_percent": %d,
                  "service_count": %d,
                  "listener_count": %d,
                  "memory_used_kb": %d,
                  "memory_total_kb": %d,
                  "disk_mounts": %s,
                  "ip_connection_count": %d,
                  "ip_connection_max": %d,
                  "active_connections": %s,
                  "critical_services_down": %s,
                  "external_listening_ports": %s,
                  "listening_endpoints": %s,
                  "processes_by_cpu": %s,
                  "processes_by_memory": %s,
                  "running_services": %s,
                  "network_interfaces": %s,
                  "recent_log_errors": %s,
                  "checks": %s
                }
                """.formatted(
                escape(report.targetType()), escape(report.label()), escape(report.hostname()), escape(report.collectedAt()), escape(report.status()),
                escape(report.privilegeMode()), report.privilegedCollection(),
                escape(report.os()), escape(report.uptime()), report.processCount(), report.cpuCoreCount(), report.cpuLoadPercent(),
                report.loadAverage1m(), report.loadAverage5m(), report.loadAverage15m(),
                report.loadAverage1mPercent(), report.loadAverage5mPercent(), report.loadAverage15mPercent(), report.diskUsedPercent(),
                report.serviceCount(), report.listenerCount(), report.memoryUsedKb(), report.memoryTotalKb(),
                stringArray(report.diskMounts()), report.ipConnectionCount(), report.ipConnectionMax(), stringArray(report.activeConnections()),
                stringArray(report.criticalServices()), report.externalListeningPorts(), stringArray(report.listeningEndpoints()),
                stringArray(report.processesByCpu()), stringArray(report.processesByMemory()), stringArray(report.runningServices()),
                stringArray(report.networkInterfaces()), stringArray(report.recentLogErrors()), checksJson(report.checks()));
    }

    private static String checksJson(List<F5Check> checks) {
        List<String> values = new ArrayList<>();
        for (F5Check check : checks) {
            values.add("{\"name\":\"" + escape(check.name()) + "\",\"status\":\"" + escape(check.status()) + "\",\"detail\":\"" + escape(check.detail()) + "\"}");
        }
        return "[" + String.join(",", values) + "]";
    }

    private static String stringArray(List<String> values) {
        return "[" + String.join(",", values.stream().map(value -> "\"" + escape(value) + "\"").toList()) + "]";
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "").replace("\n", "\\n");
    }

    private static String status(List<F5Check> checks) {
        if (checks.stream().anyMatch(F5Check::failed)) {
            return "FAIL";
        }
        if (checks.stream().anyMatch(F5Check::warning)) {
            return "WARN";
        }
        return "PASS";
    }

    private static List<String> lines(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return List.of(value.split("\\R"));
    }

    private static int nonBlankLines(String value) {
        return (int) lines(value).stream().filter(line -> !line.isBlank()).count();
    }

    private static long percent(long used, long total) {
        return total <= 0 ? 0 : Math.round(used * 100.0 / total);
    }

    private static long longValue(String value) {
        try {
            return Long.parseLong(value.strip().replaceAll("[^0-9-].*$", ""));
        } catch (RuntimeException exception) {
            return 0;
        }
    }

    private static double[] loadAverages(String value) {
        double[] result = new double[]{0, 0, 0};
        String[] parts = value == null ? new String[0] : value.strip().split("\\s+");
        for (int i = 0; i < Math.min(3, parts.length); i++) {
            try {
                result[i] = Double.parseDouble(parts[i]);
            } catch (NumberFormatException ignored) {
                result[i] = 0;
            }
        }
        return result;
    }

    private static int intValue(String value) {
        return (int) longValue(value);
    }

    private static int intEnv(String key, int defaultValue) {
        return intValue(env(key, Integer.toString(defaultValue)));
    }

    private static String env(String key, String defaultValue) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private static int logLookback(FleetTarget target) {
        return intEnv("LOG_LOOKBACK_LINES", "f5".equalsIgnoreCase(target.targetType()) ? 5000 : 2000);
    }

    private static String valueOr(String fallback, String value) {
        return value == null || value.isBlank() ? fallback : value.strip();
    }

    private static String safeFileName(String value) {
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    private static String safeTimestamp(String value) {
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
    }
}
