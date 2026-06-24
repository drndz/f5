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
        if (allowTmshFallback) {
            System.out.println("F5/tmsh probe is enabled for " + target.name() + " because target_type=" + target.targetType() + ".");
        } else {
            System.out.println("F5/tmsh probe is skipped for " + target.name() + " because target_type=vm.");
        }
        try (SshCommandClient ssh = new SshCommandClient(target.host(), target.username(), password, connectTimeout, commandTimeout, allowTmshFallback)) {
            checks.add(new F5Check("ssh_connectivity", "PASS", "Java SSH commands executed successfully."));
            boolean tmshF5Detected = allowTmshFallback && ssh.detectF5TmshShell();
            PrivilegeAccess privilege = privilegeAccess(ssh, password);
            String privilegeMode = privilege.mode();
            boolean privilegedCollection = privilege.privileged();
            checks.add(new F5Check("privileged_collection", "PASS", privilegedCollection
                    ? "Read-only diagnostics are using " + privilegeMode + " privileges."
                    : "No root or usable sudo privilege detected; using standard read-only diagnostics."));
            String hostname = hostname(target, ssh);
            String osRelease = ssh.run("cat /etc/os-release 2>/dev/null || true");
            String os = valueOr("unknown", osName(osRelease, ssh.run("uname -a 2>/dev/null || true")));
            String f5Issue = ssh.run("cat /etc/issue 2>/dev/null || true");
            String f5Evidence = f5Issue + "\n" + ssh.run("command -v tmsh 2>/dev/null || true") + "\n" + ssh.run("cat /VERSION /etc/product 2>/dev/null || true") + "\n" + osRelease;
            boolean f5Detected = tmshF5Detected || f5Detected(os + "\n" + f5Evidence);
            FleetTarget effectiveTarget = new FleetTarget(target.name(), target.host(), target.username(), target.encryptedPassword(), f5Detected ? "f5" : "vm");
            checks.add(new F5Check("target_detection", "PASS", f5Detected
                    ? "F5/BIG-IP detected from remote OS evidence; F5-specific checks are enabled."
                    : "F5/BIG-IP was not detected; running standard VM checks only."));
            String uptime = valueOr("unknown", ssh.run("uptime -p 2>/dev/null || uptime 2>/dev/null || echo unknown"));
            String meminfo = ssh.run("cat /proc/meminfo 2>/dev/null || true");
            long memoryTotal = meminfoKb(meminfo, "MemTotal");
            long memoryAvailable = meminfoKb(meminfo, "MemAvailable");
            long memoryUsed = Math.max(0, memoryTotal - memoryAvailable);
            long memoryPercent = percent(memoryUsed, memoryTotal);
            long cpuCoreCount = Math.max(1, longValue(ssh.run("getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1")));
            String loadAverageOutput = ssh.run("cat /proc/loadavg 2>/dev/null || echo '0 0 0'");
            double[] loadAverages = loadAverages(loadAverageOutput);
            long loadAverage1mPercent = Math.round(loadAverages[0] * 100.0 / cpuCoreCount);
            long loadAverage5mPercent = Math.round(loadAverages[1] * 100.0 / cpuCoreCount);
            long loadAverage15mPercent = Math.round(loadAverages[2] * 100.0 / cpuCoreCount);
            long cpuPercent = loadAverage1mPercent;
            DiskUsage diskUsage = diskUsage(ssh.run("df -Pk " + env("DISK_PATHS", "/") + " 2>/dev/null || true"));
            long diskPercent = diskUsage.maxPercent();
            List<String> diskMounts = diskUsage.mounts();
            String activeConnectionRaw = runReadOnly(ssh, privilege, "ss -H -tun 2>/dev/null || true");
            long ipConnectionCount = conntrackCount(runReadOnly(ssh, privilege, "cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || true"), activeConnectionRaw);
            long ipConnectionMax = longValue(runReadOnly(ssh, privilege, "cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0"));
            List<String> activeConnections = activeConnectionGroups(activeConnectionRaw);
            String serviceOutput = serviceOutput(effectiveTarget, ssh, privilege);
            int serviceCount = nonBlankLines(serviceOutput);
            List<String> runningServices = lines(serviceOutput);
            String rawProcesses = runReadOnly(ssh, privilege, "ps -eo pid=,pcpu=,pmem=,rss=,comm= 2>/dev/null || true");
            int processCount = processRows(rawProcesses).size();
            List<String> processesByCpu = processesByCpu(rawProcesses);
            List<String> processesByMemory = processesByMemory(rawProcesses);
            List<String> networkInterfaces = networkInterfaces(ssh.run("cat /proc/net/dev 2>/dev/null || true"), ssh.run("ip -o -4 addr show 2>/dev/null || true"));
            String listenerOutput = listenerOutput(ssh, privilege);
            Map<String, String> serviceNames = serviceNamesFromEtcServices(ssh.run("cat /etc/services 2>/dev/null || true"));
            int listenerCount = nonBlankLines(listenerOutput);
            List<Integer> ports = ports(listenerOutput);
            List<String> listeningEndpoints = listeningEndpoints(listenerOutput, serviceNames);
            List<String> criticalDown = criticalDown(effectiveTarget, serviceOutput);
            List<String> logErrors = logErrors(runReadOnly(ssh, privilege, "tail -n " + logLookback(effectiveTarget) + " /var/log/ltm /var/log/audit /var/log/kern.log /var/log/messages /var/log/syslog 2>/dev/null || true"));

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
            String tmshServices = ssh.run("tmsh show sys service 2>/dev/null || true");
            if (!tmshServices.isBlank()) {
                return tmshServices;
            }
        }
        String systemctlOutput = runReadOnly(ssh, privilege, "systemctl --type=service --state=active --no-pager --no-legend 2>/dev/null || true");
        if (!systemctlOutput.isBlank()) {
            return String.join("\n", loadedActiveServiceLines(systemctlOutput));
        }
        return ssh.run("ps -eo comm= 2>/dev/null || true");
    }

    private static String listenerOutput(SshCommandClient ssh, PrivilegeAccess privilege) {
        String ssOutput = runReadOnly(ssh, privilege, "ss -H -tulpen 2>/dev/null || true");
        if (!ssOutput.isBlank()) {
            return ssOutput;
        }
        return runReadOnly(ssh, privilege, "netstat -tulpen 2>/dev/null || true");
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    private record PrivilegeAccess(String mode, String password, boolean passwordBacked) {
        boolean privileged() {
            return "root".equals(mode) || "sudo".equals(mode) || "sudo-password".equals(mode);
        }
    }

    private record DiskUsage(long maxPercent, List<String> mounts) {
    }

    private record Endpoint(String ip, String port) {
    }

    private record ProcessRow(String pid, double cpuPercent, double memoryPercent, long rssKb, String command) {
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

    private static Map<String, String> serviceNamesFromEtcServices(String output) {
        Map<String, String> serviceNames = new HashMap<>();
        for (String line : lines(output)) {
            String trimmed = line.strip();
            if (trimmed.isBlank() || trimmed.startsWith("#")) {
                continue;
            }
            String[] parts = trimmed.split("\\s+");
            if (parts.length < 2 || !parts[1].contains("/")) {
                continue;
            }
            String[] portProtocol = parts[1].split("/", 2);
            if (portProtocol.length == 2 && portProtocol[0].matches("\\d+")) {
                serviceNames.putIfAbsent(serviceKey(portProtocol[1], portProtocol[0]), parts[0]);
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

    private static String hostname(FleetTarget target, SshCommandClient ssh) {
        String uname = ssh.run("uname -n 2>/dev/null || true");
        if (!uname.isBlank()) {
            return uname.strip();
        }
        String tmshHostname = ssh.run("tmsh list sys global-settings hostname 2>/dev/null || true");
        for (String line : lines(tmshHostname)) {
            String[] parts = line.strip().split("\\s+");
            if (parts.length >= 2 && "hostname".equals(parts[0])) {
                return parts[1];
            }
        }
        return target.name();
    }

    private static String osName(String osRelease, String uname) {
        String name = "";
        for (String line : lines(osRelease)) {
            if (line.startsWith("PRETTY_NAME=")) {
                return unquote(line.substring("PRETTY_NAME=".length()));
            }
            if (line.startsWith("NAME=")) {
                name = unquote(line.substring("NAME=".length()));
            }
        }
        return name.isBlank() ? valueOr("unknown", uname) : name;
    }

    private static String unquote(String value) {
        String stripped = value == null ? "" : value.strip();
        if (stripped.length() >= 2 && stripped.startsWith("\"") && stripped.endsWith("\"")) {
            return stripped.substring(1, stripped.length() - 1);
        }
        return stripped;
    }

    private static long meminfoKb(String meminfo, String key) {
        String prefix = key + ":";
        for (String line : lines(meminfo)) {
            if (line.startsWith(prefix)) {
                return longValue(line.substring(prefix.length()).strip());
            }
        }
        return 0;
    }

    private static DiskUsage diskUsage(String dfOutput) {
        long maxPercent = 0;
        List<String> mounts = new ArrayList<>();
        for (String line : lines(dfOutput)) {
            if (line.startsWith("Filesystem") || line.isBlank()) {
                continue;
            }
            String[] parts = line.trim().split("\\s+");
            if (parts.length < 6) {
                continue;
            }
            long totalKb = longValue(parts[1]);
            long usedKb = longValue(parts[2]);
            long availableKb = longValue(parts[3]);
            long percent = longValue(parts[4]);
            maxPercent = Math.max(maxPercent, percent);
            mounts.add(parts[5] + "|" + gb(totalKb) + "|" + gb(usedKb) + "|" + gb(availableKb) + "|" + gb(availableKb) + "|" + percent + "%");
        }
        return new DiskUsage(maxPercent, mounts);
    }

    private static List<ProcessRow> processRows(String psOutput) {
        List<ProcessRow> rows = new ArrayList<>();
        for (String line : lines(psOutput)) {
            String[] parts = line.strip().split("\\s+", 5);
            if (parts.length < 5) {
                continue;
            }
            rows.add(new ProcessRow(parts[0], doubleValue(parts[1]), doubleValue(parts[2]), longValue(parts[3]), parts[4]));
        }
        return rows;
    }

    private static List<String> processesByCpu(String psOutput) {
        return processRows(psOutput).stream()
                .sorted(Comparator.comparingDouble(ProcessRow::cpuPercent).reversed())
                .map(FleetSshValidator::processReportLine)
                .toList();
    }

    private static List<String> processesByMemory(String psOutput) {
        return processRows(psOutput).stream()
                .sorted(Comparator.comparingDouble(ProcessRow::memoryPercent).reversed())
                .map(FleetSshValidator::processReportLine)
                .toList();
    }

    private static String processReportLine(ProcessRow row) {
        return row.pid() + "|" + formatDouble(row.cpuPercent()) + "|" + formatDouble(row.memoryPercent()) + "|" + gb(row.rssKb()) + "|" + row.command();
    }

    private static List<String> networkInterfaces(String procNetDev, String ipAddrOutput) {
        Map<String, List<String>> ipsByInterface = new HashMap<>();
        for (String line : lines(ipAddrOutput)) {
            String[] parts = line.strip().split("\\s+");
            if (parts.length >= 4 && "inet".equals(parts[2])) {
                ipsByInterface.computeIfAbsent(parts[1], ignored -> new ArrayList<>()).add(parts[3]);
            }
        }
        List<String> interfaces = new ArrayList<>();
        for (String line : lines(procNetDev)) {
            int separator = line.indexOf(':');
            if (separator < 0) {
                continue;
            }
            String name = line.substring(0, separator).strip();
            String[] counters = line.substring(separator + 1).strip().split("\\s+");
            if (counters.length < 16) {
                continue;
            }
            double rxGb = longValue(counters[0]) / 1073741824.0;
            double txGb = longValue(counters[8]) / 1073741824.0;
            String ips = String.join(",", ipsByInterface.getOrDefault(name, List.of()));
            interfaces.add(name + "|" + ips + "|" + formatDouble(rxGb, 3) + "|" + formatDouble(txGb, 3));
        }
        interfaces.sort(String::compareTo);
        return interfaces;
    }

    private static List<String> loadedActiveServiceLines(String systemctlOutput) {
        List<String> services = new ArrayList<>();
        for (String line : lines(systemctlOutput)) {
            String[] parts = line.strip().split("\\s+", 5);
            if (parts.length >= 4 && "loaded".equals(parts[1]) && "active".equals(parts[2]) && !"exited".equals(parts[3])) {
                services.add(parts[0] + " loaded active " + parts[3]);
            }
        }
        services.sort(String::compareTo);
        return services;
    }

    private static List<String> logErrors(String rawLogs) {
        List<String> matches = new ArrayList<>();
        for (String line : lines(rawLogs)) {
            String lower = line.toLowerCase();
            if (lower.contains("error") || lower.contains("fail") || lower.contains("fatal")
                    || lower.contains("crit") || lower.contains("panic") || lower.contains("segfault")
                    || lower.contains("denied")) {
                matches.add(line);
            }
        }
        int from = Math.max(0, matches.size() - 100);
        return new ArrayList<>(matches.subList(from, matches.size()));
    }

    private static long conntrackCount(String nfConntrackCount, String ssOutput) {
        long conntrack = longValue(nfConntrackCount);
        return conntrack > 0 ? conntrack : lines(ssOutput).stream().filter(line -> !line.isBlank()).count();
    }

    private static List<String> activeConnectionGroups(String ssOutput) {
        Map<String, Integer> counts = new HashMap<>();
        for (String line : lines(ssOutput)) {
            String[] parts = line.trim().split("\\s+");
            if (parts.length < 5) {
                continue;
            }
            String proto = parts[0];
            Endpoint local = endpoint(cleanEndpoint(parts[parts.length - 2]));
            Endpoint peer = endpoint(cleanEndpoint(parts[parts.length - 1]));
            if (peer.ip().isBlank() || peer.port().isBlank() || "*".equals(peer.port())
                    || peer.ip().startsWith("127.") || "::1".equals(peer.ip())
                    || "0.0.0.0".equals(peer.ip()) || "*".equals(peer.ip())) {
                continue;
            }
            String direction = connectionDirection(local.port(), peer.port());
            String displayPort = "in".equals(direction) ? local.port() : peer.port();
            String key = direction + "|" + proto + "|" + peer.ip() + "|" + displayPort;
            counts.merge(key, 1, Integer::sum);
        }
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
                .map(entry -> entry.getKey() + "|" + entry.getValue())
                .toList();
    }

    private static String cleanEndpoint(String endpoint) {
        return endpoint == null ? "" : endpoint.replace("[", "").replace("]", "");
    }

    private static Endpoint endpoint(String endpoint) {
        int portSeparator = endpoint.lastIndexOf(':');
        if (portSeparator < 0) {
            return new Endpoint(endpoint, "");
        }
        String ip = endpoint.substring(0, portSeparator);
        int scopeSeparator = ip.indexOf('%');
        if (scopeSeparator >= 0) {
            ip = ip.substring(0, scopeSeparator);
        }
        return new Endpoint(ip, endpoint.substring(portSeparator + 1));
    }

    private static String connectionDirection(String localPort, String peerPort) {
        long local = longValue(localPort);
        long peer = longValue(peerPort);
        if (local > 0 && peer > 0 && local < 32768 && peer >= 32768) {
            return "in";
        }
        if (local > 0 && peer > 0 && peer < 32768 && local >= 32768) {
            return "out";
        }
        if (local > 0 && peer > 0 && peer < local) {
            return "out";
        }
        return "peer";
    }

    private static String gb(long kb) {
        return String.format(java.util.Locale.ROOT, "%.2f", kb / 1048576.0);
    }

    private static double doubleValue(String value) {
        try {
            return Double.parseDouble(value.strip());
        } catch (RuntimeException exception) {
            return 0;
        }
    }

    private static String formatDouble(double value) {
        return formatDouble(value, 2);
    }

    private static String formatDouble(double value, int decimals) {
        return String.format(java.util.Locale.ROOT, "%." + decimals + "f", value);
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
