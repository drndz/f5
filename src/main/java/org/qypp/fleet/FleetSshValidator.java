package org.qypp.fleet;

import org.qypp.f5.F5Check;
import org.qypp.f5.F5Report;
import org.qypp.f5.ReportArtifactWriter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Locale;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FleetSshValidator {
    private static final String CRYPTO_CERT_KEYS = "cert-validation-options|cert-validators|certificate-key-size|city|common-name|country|email-address|expiration|fingerprint|issuer|issuer-certificate|organization|ou|public-key-type|state|subject|subject-alternative-name";

    private FleetSshValidator() {
    }

    public static void run(Path targetsFile, Path outputDir, String masterKey) throws IOException {
        run(targetsFile, outputDir, masterKey, false);
    }

    public static void run(Path targetsFile, Path outputDir, String masterKey, boolean detailsSsh) throws IOException {
        List<F5Report> reports = new ArrayList<>();
        List<OutboundCheck> outboundChecks = readOutboundChecks(targetsFile);
        String partitionPrefixFilter = readPartitionPrefixFilter(targetsFile);
        String runTimestamp = safeTimestamp(Instant.now().toString());
        Path runOutputDir = outputDir.resolve(runTimestamp);
        Files.createDirectories(runOutputDir);
        for (FleetTarget target : readTargets(targetsFile)) {
            System.out.println("Running " + target.targetType() + " validation over Java SSH on " + target.name() + " (" + target.host() + ")");
            ValidationCommands commands = ValidationCommands.load(targetsFile, target.targetType());
            F5Report report = validate(target, masterKey, commands, outboundChecks, partitionPrefixFilter, detailsSsh);
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

    private static List<OutboundCheck> readOutboundChecks(Path targetsFile) throws IOException {
        Path configDir = targetsFile.toAbsolutePath().getParent();
        if (configDir == null) {
            configDir = Path.of(".").toAbsolutePath();
        }
        Path checksFile = configDir.resolve("vm_outbound_checks.csv");
        if (!Files.exists(checksFile)) {
            return List.of();
        }
        List<OutboundCheck> checks = new ArrayList<>();
        for (String line : Files.readAllLines(checksFile)) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("name,")) {
                continue;
            }
            checks.add(OutboundCheck.parse(trimmed));
        }
        return checks;
    }

    private static String readPartitionPrefixFilter(Path targetsFile) throws IOException {
        Path configDir = targetsFile.toAbsolutePath().getParent();
        if (configDir == null) {
            configDir = Path.of(".").toAbsolutePath();
        }
        Path filterFile = configDir.resolve(".part_prefix_filter");
        if (!Files.exists(filterFile)) {
            return "";
        }
        return Files.readAllLines(filterFile).stream()
                .map(String::strip)
                .filter(line -> !line.isBlank())
                .filter(line -> !line.startsWith("#"))
                .findFirst()
                .orElse("");
    }

    private static F5Report validate(FleetTarget target, String masterKey, ValidationCommands commands, List<OutboundCheck> configuredOutboundChecks, String partitionPrefixFilter, boolean detailsSsh) {
        String collectedAt = Instant.now().toString();
        List<F5Check> checks = new ArrayList<>();
        String password = PasswordCrypto.decryptOrPlain(target.encryptedPassword(), masterKey);
        int connectTimeout = intEnv("SSH_CONNECT_TIMEOUT_MILLIS", 10_000);
        int commandTimeout = intEnv("SSH_COMMAND_TIMEOUT_MILLIS", 10_000);

        boolean allowTmshFallback = shouldProbeTmsh(target);
        if (allowTmshFallback) {
            System.out.println("F5/tmsh probe is enabled for " + target.name() + " because target_type=" + target.targetType() + ".");
        } else {
            System.out.println("F5/tmsh probe is skipped for " + target.name() + " because target_type=vm.");
        }
        try (SshCommandClient ssh = new SshCommandClient(target.host(), target.username(), password, connectTimeout, commandTimeout, allowTmshFallback, detailsSsh)) {
            checks.add(new F5Check("ssh_connectivity", "PASS", "Java SSH commands executed successfully."));
            boolean tmshF5Detected = allowTmshFallback && ssh.detectF5TmshShell(commands.command("CK01"));
            String privilegeMode = "login-user";
            boolean privilegedCollection = false;
            String hostname = hostname(target, ssh, commands);
            String osRelease = ssh.run(commands.command("CK04"));
            String os = valueOr("unknown", osName(osRelease, ssh.run(commands.command("CK05"))));
            String f5Issue = ssh.run(commands.command("CK06"));
            String f5Evidence = f5Issue + "\n" + runIfDefined(ssh, commands, "CK07") + "\n" + runIfDefined(ssh, commands, "CK08") + "\n" + osRelease;
            boolean f5Detected = tmshF5Detected || f5Detected(os + "\n" + f5Evidence);
            FleetTarget effectiveTarget = new FleetTarget(target.name(), target.host(), target.username(), target.encryptedPassword(), f5Detected ? "f5" : "vm");
            checks.add(new F5Check("target_detection", "PASS", f5Detected
                    ? "F5/BIG-IP detected from remote OS evidence; F5-specific checks are enabled."
                    : "F5/BIG-IP was not detected; running standard VM checks only."));
            String uptime = valueOr("unknown", ssh.run(commands.command("CK09")));
            String meminfo = ssh.run(commands.command("CK10"));
            long memoryTotal = meminfoKb(meminfo, "MemTotal");
            long memoryAvailable = meminfoKb(meminfo, "MemAvailable");
            long memoryUsed = Math.max(0, memoryTotal - memoryAvailable);
            long memoryPercent = percent(memoryUsed, memoryTotal);
            long cpuCoreCount = Math.max(1, longValue(ssh.run(commands.command("CK11"))));
            String loadAverageOutput = ssh.run(commands.command("CK12"));
            double[] loadAverages = loadAverages(loadAverageOutput);
            long loadAverage1mPercent = Math.round(loadAverages[0] * 100.0 / cpuCoreCount);
            long loadAverage5mPercent = Math.round(loadAverages[1] * 100.0 / cpuCoreCount);
            long loadAverage15mPercent = Math.round(loadAverages[2] * 100.0 / cpuCoreCount);
            long cpuPercent = loadAverage1mPercent;
            DiskUsage diskUsage = diskUsage(ssh.run(commands.command("CK13", Map.of("DISK_PATHS", env("DISK_PATHS", "")))));
            long diskPercent = diskUsage.maxPercent();
            List<String> diskMounts = diskUsage.mounts();
            String activeConnectionRaw = ssh.run(commands.command("CK14"));
            long ipConnectionCount = conntrackCount(ssh.run(commands.command("CK15")), activeConnectionRaw);
            long ipConnectionMax = longValue(ssh.run(commands.command("CK16")));
            List<String> activeConnections = activeConnectionGroups(activeConnectionRaw);
            String serviceOutput = serviceOutput(effectiveTarget, ssh, commands);
            int serviceCount = nonBlankLines(serviceOutput);
            List<String> runningServices = lines(serviceOutput);
            String rawProcesses = ssh.run(commands.command("CK19"));
            int processCount = processRows(rawProcesses).size();
            List<String> processesByCpu = processesByCpu(rawProcesses);
            List<String> processesByMemory = processesByMemory(rawProcesses);
            List<String> networkInterfaces = networkInterfaces(ssh.run(commands.command("CK20")), ssh.run(commands.command("CK21")));
            List<String> systemUsers = systemUsers(ssh.run(commands.command("CK29")));
            List<String> loggedUsers = loggedUsers(runIfDefined(ssh, commands, "CK32"));
            String listenerOutput = listenerOutput(ssh, commands);
            Map<String, String> serviceNames = serviceNamesFromEtcServices(ssh.run(commands.command("CK24")));
            int listenerCount = nonBlankLines(listenerOutput);
            List<Integer> ports = ports(listenerOutput);
            List<String> listeningEndpoints = listeningEndpoints(listenerOutput, serviceNames);
            List<String> criticalDown = criticalDown(effectiveTarget, serviceOutput, rawProcesses, listeningEndpoints);
            List<String> logErrors = logErrors(ssh.run(commands.command("CK25", Map.of("LOG_LOOKBACK_LINES", Integer.toString(logLookback(effectiveTarget))))));
            String vmstatSample = runIfDefined(ssh, commands, "CK26");
            String f5SystemPerformance = "f5".equalsIgnoreCase(effectiveTarget.targetType()) ? runIfDefined(ssh, commands, "CK27") : "";
            String f5ConnectionPerformance = "f5".equalsIgnoreCase(effectiveTarget.targetType()) ? runIfDefined(ssh, commands, "CK28") : "";
            List<String> f5LoadHistory = "f5".equalsIgnoreCase(effectiveTarget.targetType()) ? f5LoadHistory(runIfDefined(ssh, commands, "CK30")) : List.of();
            F5Inventory f5Inventory = "f5".equalsIgnoreCase(effectiveTarget.targetType()) ? f5Inventory(f5InventoryOutput(ssh, commands), partitionPrefixFilter, serviceNames) : F5Inventory.empty();
            List<String> f5PartitionsPools = f5Inventory.rows();
            List<String> outboundResults = new ArrayList<>(outboundChecks(ssh, commands, configuredOutboundChecks, true));
            outboundResults.addAll(poolMemberConnectivityChecks(ssh, commands, f5Inventory.connectivityChecks()));

            addCriticalCheck(checks, criticalDown, effectiveTarget);
            addPortCheck(checks, ports, effectiveTarget);
            addThreshold(checks, "load_1m", loadAverage1mPercent, intEnv("CPU_WARN_PERCENT", 80), intEnv("CPU_FAIL_PERCENT", 95), "1 minute load is " + loadAverage1mPercent + "% of available cores.");
            addThreshold(checks, "memory", memoryPercent, intEnv("MEMORY_WARN_PERCENT", 80), intEnv("MEMORY_FAIL_PERCENT", 90), "Memory usage is " + memoryPercent + "%.");
            addThreshold(checks, "disk", diskPercent, intEnv("DISK_WARN_PERCENT", 80), intEnv("DISK_FAIL_PERCENT", 90), "Maximum disk usage is " + diskPercent + "%.");
            checks.add(new F5Check("vmstat_sample", vmstatSample.isBlank() ? "WARN" : "PASS", vmstatSample.isBlank() ? "vmstat is not available or returned no data." : "Latest vmstat sample: " + oneLine(vmstatSample)));
            if ("f5".equalsIgnoreCase(effectiveTarget.targetType())) {
                checks.add(new F5Check("f5_system_performance", f5SystemPerformance.isBlank() ? "WARN" : "PASS", f5SystemPerformance.isBlank() ? "F5 tmsh system performance counters returned no data." : "F5 system performance counters collected."));
                checks.add(new F5Check("f5_connection_performance", f5ConnectionPerformance.isBlank() ? "WARN" : "PASS", f5ConnectionPerformance.isBlank() ? "F5 tmsh connection performance counters returned no data." : "F5 connection performance counters collected."));
                checks.add(new F5Check("f5_load_history", f5LoadHistory.isEmpty() ? "WARN" : "PASS", f5LoadHistory.isEmpty() ? "No F5 RRD load history samples were found." : "Collected " + f5LoadHistory.size() + " raw F5 historical load samples from the last 48 hours of local RRD data."));
                checks.add(new F5Check("f5_partitions_pools", f5PartitionsPools.isEmpty() ? "WARN" : "PASS", f5PartitionsPools.isEmpty() ? "No F5 partitions or pools were listed." : "Collected " + f5PartitionsPools.size() + " F5 partition/pool rows."));
            }
            addOutboundChecks(checks, outboundResults, configuredOutboundChecks);
            addRuntimeChecks(checks, ssh.commandTimingRows());
            checks.add(new F5Check("recent_logs", logErrors.isEmpty() ? "PASS" : "WARN", logErrors.isEmpty() ? "No recent error patterns found in /var/log." : "Recent error patterns found in /var/log. See report details."));

            return new F5Report(target.name(), effectiveTarget.targetType(), hostname, collectedAt, status(checks), privilegeMode, privilegedCollection, os, uptime, processCount, cpuCoreCount, cpuPercent, loadAverages[0], loadAverages[1], loadAverages[2], loadAverage1mPercent, loadAverage5mPercent, loadAverage15mPercent, diskPercent, serviceCount, listenerCount, memoryUsed, memoryTotal, diskMounts, ipConnectionCount, ipConnectionMax, activeConnections, criticalDown, ports, listeningEndpoints, processesByCpu, processesByMemory, runningServices, networkInterfaces, systemUsers, loggedUsers, f5LoadHistory, f5PartitionsPools, outboundResults, logErrors, checks);
        } catch (RuntimeException | IOException exception) {
            checks.add(new F5Check("ssh_connectivity", "FAIL", "Could not run Java SSH commands on " + target.host() + ": " + exception.getMessage()));
            return new F5Report(
                    target.name(), target.targetType(), target.host(), collectedAt, "FAIL", "login-user", false,
                    "unknown", "unknown", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, List.of(), 0, 0, List.of(), List.of(), List.of(), List.of(),
                    List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), checks
            );
        }
    }

    private static boolean shouldProbeTmsh(FleetTarget target) {
        String type = target.targetType();
        return type == null || type.isBlank() || "auto".equalsIgnoreCase(type) || "f5".equalsIgnoreCase(type);
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

    private static String serviceOutput(FleetTarget target, SshCommandClient ssh, ValidationCommands commands) {
        if (!commands.hasCommand("CK17")) {
            return ssh.run(commands.command("CK18"));
        }
        String serviceOutput = "f5".equalsIgnoreCase(target.targetType())
                ? ssh.run(commands.command("CK17"))
                : ssh.run(commands.command("CK17"));
        if (serviceOutput.isBlank()) {
            return ssh.run(commands.command("CK18"));
        }
        if ("vm".equalsIgnoreCase(target.targetType())) {
            return String.join("\n", loadedActiveServiceLines(serviceOutput));
        }
        return serviceOutput;
    }

    private static String listenerOutput(SshCommandClient ssh, ValidationCommands commands) {
        String netstatOutput = ssh.run(commands.command("CK22"));
        if (!netstatOutput.isBlank()) {
            return netstatOutput;
        }
        return ssh.run(commands.command("CK23"));
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    private record DiskUsage(long maxPercent, List<String> mounts) {
    }

    private record Endpoint(String ip, String port) {
    }

    private record ActiveSocket(Endpoint local, Endpoint peer) {
    }

    private record ProcessRow(String pid, double cpuPercent, double memoryPercent, long rssKb, long sharedKb, String command) {
    }

    private record OutboundCheck(String name, String host, int port, String protocol, String checkType, boolean explicitCheckType) {
        static OutboundCheck parse(String line) {
            String[] parts = line.split(",", -1);
            if (parts.length < 4) {
                throw new IllegalArgumentException("Expected CSV columns: name,host,port,protocol,check_type");
            }
            String protocol = parts[3].trim().toUpperCase(java.util.Locale.ROOT);
            if (!"TCP".equals(protocol) && !"UDP".equals(protocol)) {
                throw new IllegalArgumentException("Outbound check protocol must be TCP or UDP: " + parts[3]);
            }
            boolean explicitType = parts.length >= 5 && !parts[4].isBlank();
            String checkType = explicitType ? parts[4].trim().toUpperCase(java.util.Locale.ROOT) : defaultCheckType(protocol);
            validateCheckType(protocol, checkType);
            return new OutboundCheck(parts[0].trim(), parts[1].trim(), Integer.parseInt(parts[2].trim()), protocol, checkType, explicitType);
        }

        private static String defaultCheckType(String protocol) {
            return "TCP".equals(protocol) ? "CONNECT" : "AUTO";
        }

        private static void validateCheckType(String protocol, String checkType) {
            if ("TCP".equals(protocol)) {
                if (!"CONNECT".equals(checkType) && !"TLS".equals(checkType)) {
                    throw new IllegalArgumentException("TCP outbound check type must be CONNECT or TLS: " + checkType);
                }
                return;
            }
            if (!"AUTO".equals(checkType) && !"DNS".equals(checkType) && !"RADIUS".equals(checkType)) {
                throw new IllegalArgumentException("UDP outbound check type must be AUTO, DNS, or RADIUS: " + checkType);
            }
        }
    }

    private static List<String> criticalDown(FleetTarget target, String serviceOutput, String processOutput, List<String> listeningEndpoints) {
        String defaultServices = "f5".equalsIgnoreCase(target.targetType()) ? "mcpd tmm bigd gtmd named httpd sshd restjavad restnoded" : "";
        String services = env("CRITICAL_SERVICES", defaultServices);
        if (services.isBlank()) {
            return List.of();
        }
        List<String> down = new ArrayList<>();
        String serviceEvidence = serviceOutput.toLowerCase();
        String processEvidence = processOutput.toLowerCase();
        String listenerEvidence = String.join("\n", listeningEndpoints).toLowerCase();
        for (String service : services.split("\\s+")) {
            String normalized = service.toLowerCase();
            if (!serviceEvidence.contains(normalized)
                    && !processEvidenceContains(processEvidence, normalized)
                    && !listenerEvidenceContains(listenerEvidence, normalized)) {
                down.add(service);
            }
        }
        return down;
    }

    private static boolean processEvidenceContains(String processEvidence, String service) {
        for (String line : lines(processEvidence)) {
            String[] parts = line.strip().split("\\s+");
            if (parts.length >= 6 && service.equalsIgnoreCase(parts[5])) {
                return true;
            }
        }
        return false;
    }

    private static boolean listenerEvidenceContains(String listenerEvidence, String service) {
        for (String line : lines(listenerEvidence)) {
            String[] parts = line.split("\\|", -1);
            if (parts.length >= 4 && service.equalsIgnoreCase(parts[3])) {
                return true;
            }
        }
        return false;
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

    private static void addOutboundChecks(List<F5Check> checks, List<String> outboundResults, List<OutboundCheck> configuredOutboundChecks) {
        if (configuredOutboundChecks.isEmpty()) {
            return;
        }
        long failed = outboundResults.stream().filter(result -> result.contains("|FAIL|")).count();
        checks.add(new F5Check("outbound_connectivity", failed == 0 ? "PASS" : "FAIL",
                failed == 0 ? "All configured outbound checks passed." : failed + " configured outbound checks failed."));
    }

    private static void addRuntimeChecks(List<F5Check> checks, List<String> timingRows) {
        if (timingRows.isEmpty()) {
            return;
        }
        long totalMillis = 0;
        long maxMillis = 0;
        String slowest = "";
        for (String row : timingRows) {
            String[] parts = row.split("\\|", 4);
            long elapsed = longValue(part(parts, 1));
            totalMillis += elapsed;
            if (elapsed > maxMillis) {
                maxMillis = elapsed;
                slowest = row;
            }
        }
        checks.add(new F5Check("runtime_total", "INFO", "SSH command wall time sum " + totalMillis + " ms across " + timingRows.size() + " command attempts."));
        if (!slowest.isBlank()) {
            checks.add(new F5Check("runtime_slowest", "INFO", slowest));
        }
        timingRows.stream()
                .sorted((left, right) -> Long.compare(timingMillis(right), timingMillis(left)))
                .limit(20)
                .forEach(row -> checks.add(new F5Check("runtime_command", "INFO", row)));
    }

    private static long timingMillis(String row) {
        String[] parts = row.split("\\|", 4);
        return longValue(part(parts, 1));
    }

    private static List<Integer> ports(String listenerOutput) {
        List<Integer> ports = new ArrayList<>();
        for (String line : listenerOutput.split("\\R")) {
            ListenerEndpoint endpoint = parseListenerEndpoint(line);
            if (endpoint != null && !endpoint.loopback()) {
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
            if (endpoint != null) {
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
        if (!protocol.startsWith("tcp") && !protocol.startsWith("udp")) {
            return null;
        }
        if (isHeaderLine(parts)) {
            return null;
        }
        if (protocol.startsWith("tcp") && parts.length >= 6 && !line.toLowerCase().contains("listen")) {
            return null;
        }
        String localAddress = localAddressColumn(parts);
        AddressPort addressPort = addressPort(localAddress);
        if (addressPort == null) {
            return null;
        }
        return new ListenerEndpoint(protocol, addressPort.address(), addressPort.port(), processName(line), isLoopback(addressPort.address()));
    }

    private static boolean isHeaderLine(String[] parts) {
        String joined = String.join(" ", parts).toLowerCase();
        return joined.contains("local address") || joined.contains("foreign address") || joined.startsWith("netid ");
    }

    private static String localAddressColumn(String[] parts) {
        if (parts.length >= 5 && parts[1].matches("\\d+") && parts[2].matches("\\d+")) {
            return parts[3];
        }
        if (parts.length >= 6 && parts[1].matches("\\d+")) {
            return parts[3];
        }
        return parts.length >= 5 ? parts[4] : parts[3];
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
                  "system_users": %s,
                  "logged_users": %s,
                  "f5_load_history": %s,
                  "f5_partitions_pools": %s,
                  "outbound_checks": %s,
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
                stringArray(report.networkInterfaces()), stringArray(report.systemUsers()), stringArray(report.loggedUsers()), stringArray(report.f5LoadHistory()),
                stringArray(report.f5PartitionsPools()),
                stringArray(report.outboundChecks()), stringArray(report.recentLogErrors()), checksJson(report.checks()));
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

    private static String hostname(FleetTarget target, SshCommandClient ssh, ValidationCommands commands) {
        String uname = ssh.run(commands.command("CK02"));
        if (!uname.isBlank()) {
            return uname.strip();
        }
        if (!commands.hasCommand("CK03")) {
            return target.name();
        }
        String tmshHostname = ssh.run(commands.command("CK03"));
        for (String line : lines(tmshHostname)) {
            String[] parts = line.strip().split("\\s+");
            if (parts.length >= 2 && "hostname".equals(parts[0])) {
                return parts[1];
            }
        }
        return target.name();
    }

    private static String runIfDefined(SshCommandClient ssh, ValidationCommands commands, String id) {
        return commands.hasCommand(id) ? ssh.run(commands.command(id)) : "";
    }

    private static String f5InventoryOutput(SshCommandClient ssh, ValidationCommands commands) {
        List<String> values = new ArrayList<>();
        for (String id : List.of("CK33", "CK35")) {
            String output = runIfDefined(ssh, commands, id);
            if (!output.isBlank()) {
                values.add(output);
            }
        }
        return String.join("\n", values);
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
            long percent = percent(usedKb, totalKb);
            maxPercent = Math.max(maxPercent, percent);
            mounts.add(parts[5] + "|" + gb(totalKb) + "|" + gb(usedKb) + "|" + gb(availableKb) + "|" + gb(availableKb) + "|" + percent + "%");
        }
        return new DiskUsage(maxPercent, mounts);
    }

    private static List<ProcessRow> processRows(String psOutput) {
        List<ProcessRow> rows = new ArrayList<>();
        for (String line : lines(psOutput)) {
            String trimmed = line.strip();
            if (trimmed.isBlank() || trimmed.startsWith("PID ") || trimmed.startsWith("USER ")) {
                continue;
            }
            String[] parts = trimmed.split("\\s+", 11);
            if (parts.length >= 6 && parts[0].matches("\\d+")) {
                rows.add(new ProcessRow(parts[0], doubleValue(parts[1]), doubleValue(parts[2]), longValue(parts[3]), longValue(parts[4]), parts[5]));
            } else if (parts.length >= 5 && parts[0].matches("\\d+")) {
                rows.add(new ProcessRow(parts[0], doubleValue(parts[1]), doubleValue(parts[2]), longValue(parts[3]), 0, parts[4]));
            } else if (parts.length >= 11 && parts[1].matches("\\d+")) {
                rows.add(new ProcessRow(parts[1], doubleValue(parts[2]), doubleValue(parts[3]), longValue(parts[5]), 0, commandName(parts[10])));
            }
        }
        return rows;
    }

    private static String commandName(String command) {
        String trimmed = command == null ? "" : command.strip();
        if (trimmed.isBlank()) {
            return "unknown";
        }
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            return trimmed;
        }
        String first = trimmed.split("\\s+", 2)[0];
        int slash = first.lastIndexOf('/');
        return slash >= 0 && slash < first.length() - 1 ? first.substring(slash + 1) : first;
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
        return row.pid() + "|" + formatDouble(row.cpuPercent()) + "|" + formatDouble(row.memoryPercent()) + "|" + gb(row.rssKb()) + "|" + gb(row.sharedKb()) + "|" + row.command();
    }

    private static List<String> networkInterfaces(String procNetDev, String ipAddrOutput) {
        Map<String, List<String>> ipsByInterface = new HashMap<>();
        for (String line : lines(ipAddrOutput)) {
            String[] parts = line.strip().split("\\s+");
            if (parts.length >= 4 && ("inet".equals(parts[2]) || "inet6".equals(parts[2]))) {
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

    private static List<String> systemUsers(String rawUsersAndLastlog) {
        Map<String, UserRow> users = new LinkedHashMap<>();
        boolean lastlogSection = false;
        for (String line : lines(rawUsersAndLastlog)) {
            String trimmed = line.strip();
            if (trimmed.isBlank()) {
                continue;
            }
            if ("__LASTLOG__".equals(trimmed)) {
                lastlogSection = true;
                continue;
            }
            if (!lastlogSection) {
                String[] parts = trimmed.split(":", -1);
                if (parts.length >= 7 && !parts[0].isBlank()) {
                    users.put(parts[0], new UserRow(parts[0], parts[2], parts[6], "unknown"));
                }
                continue;
            }
            String[] parts = trimmed.split("\\s+", 2);
            if (parts.length < 2 || "Username".equalsIgnoreCase(parts[0])) {
                continue;
            }
            UserRow existing = users.get(parts[0]);
            if (existing != null) {
                users.put(parts[0], new UserRow(existing.username(), existing.uid(), existing.shell(), parts[1].strip()));
            }
        }
        return users.values().stream()
                .map(user -> user.username() + "|" + user.uid() + "|" + user.shell() + "|" + user.lastLogin())
                .toList();
    }

    private record UserRow(String username, String uid, String shell, String lastLogin) {
    }

    private static List<String> loggedUsers(String rawLogins) {
        Map<String, LoggedUserRow> logins = new LinkedHashMap<>();
        boolean authLogSection = false;
        for (String line : lines(rawLogins)) {
            String trimmed = line.strip();
            if (trimmed.isBlank()) {
                continue;
            }
            if ("__SSH_AUTH_LOGS__".equals(trimmed)) {
                authLogSection = true;
                continue;
            }
            LoggedUserRow row = authLogSection ? loggedUserFromSshd(trimmed) : loggedUserFromLast(trimmed);
            if (row != null) {
                logins.putIfAbsent(row.user(), row);
            }
        }
        return logins.values().stream()
                .limit(1)
                .map(row -> row.user() + "||" + row.timestamp() + "|" + row.event())
                .toList();
    }

    private static LoggedUserRow loggedUserFromSshd(String line) {
        int sshd = line.indexOf("sshd");
        if (sshd < 0) {
            return null;
        }
        String timestamp = line.length() >= 15 ? line.substring(0, 15).strip() : "unknown";
        String normalized = line.replace("invalid user ", "");
        String event;
        if (normalized.contains("Accepted ")) {
            event = "accepted";
        } else if (normalized.contains("Failed ")) {
            event = "failed";
        } else if (normalized.contains("session opened")) {
            event = "session opened";
        } else if (normalized.contains("session closed")) {
            event = "session closed";
        } else {
            event = "ssh";
        }
        String user = between(normalized, " for ", " from ");
        if (user.isBlank()) {
            user = between(normalized, " user=", " ");
        }
        String source = between(normalized, " from ", " ");
        if (source.isBlank()) {
            source = "unknown";
        }
        if (user.isBlank()) {
            user = "unknown";
        }
        return new LoggedUserRow(user, source, timestamp, event);
    }

    private static LoggedUserRow loggedUserFromLast(String line) {
        if (line.startsWith("reboot ") || line.startsWith("shutdown ")) {
            return null;
        }
        String[] parts = line.split("\\s+");
        if (parts.length < 8) {
            return null;
        }
        String user = parts[0];
        int timestampStart = 3;
        String source = parts.length > 2 ? parts[2] : "unknown";
        if (isWeekday(source)) {
            source = "local";
            timestampStart = 2;
        }
        if (parts.length <= timestampStart + 4) {
            return null;
        }
        String timestamp = String.join(" ", List.of(parts[timestampStart], parts[timestampStart + 1], parts[timestampStart + 2], parts[timestampStart + 3], parts[timestampStart + 4]));
        return new LoggedUserRow(user, source, timestamp, "login");
    }

    private static boolean isWeekday(String value) {
        return "Mon".equals(value) || "Tue".equals(value) || "Wed".equals(value) || "Thu".equals(value)
                || "Fri".equals(value) || "Sat".equals(value) || "Sun".equals(value);
    }

    private static String between(String value, String start, String end) {
        int startIndex = value.indexOf(start);
        if (startIndex < 0) {
            return "";
        }
        int valueStart = startIndex + start.length();
        int endIndex = value.indexOf(end, valueStart);
        if (endIndex < 0) {
            endIndex = value.length();
        }
        return value.substring(valueStart, endIndex).strip();
    }

    private record LoggedUserRow(String user, String source, String timestamp, String event) {
    }

    private static List<String> f5LoadHistory(String rawHistory) {
        List<String> values = new ArrayList<>();
        String source = "";
        for (String line : lines(rawHistory)) {
            String trimmed = line.strip();
            if (trimmed.isBlank()) {
                continue;
            }
            if (trimmed.startsWith("__RRD_FILE__ ")) {
                source = trimmed.substring("__RRD_FILE__ ".length()).strip();
                continue;
            }
            String[] parts = trimmed.split("\\|", -1);
            if (parts.length >= 3 && parts[0].matches("\\d+") && isDecimal(parts[2])) {
                values.add(source + "#" + part(parts, 1) + "|" + parts[0] + "|" + parts[2]);
            } else if (parts.length >= 2 && parts[0].matches("\\d+") && isDecimal(parts[1])) {
                values.add(source + "|" + parts[0] + "|" + parts[1]);
            }
        }
        return values;
    }

    private static F5Inventory f5Inventory(String rawInventory, String partitionPrefixFilter, Map<String, String> serviceNames) {
        Map<String, PoolInventory> pools = new LinkedHashMap<>();
        Map<String, List<String>> partitions = new LinkedHashMap<>();
        Map<String, VirtualInventory> virtuals = new LinkedHashMap<>();
        Map<String, VirtualStats> virtualStats = virtualStats(rawInventory);
        Map<String, ClientSslInventory> clientSslProfiles = new LinkedHashMap<>();
        Map<String, ClientSslInventory> serverSslProfiles = new LinkedHashMap<>();
        Map<String, CertInventory> certs = new LinkedHashMap<>();
        String currentPartition = "";
        CryptoCertBuilder cryptoCert = null;
        int cryptoCertDepth = 0;
        for (String line : lines(rawInventory)) {
            String trimmed = line.strip();
            if (cryptoCert != null) {
                cryptoCert.read(trimmed);
                cryptoCertDepth += countChar(trimmed, '{') - countChar(trimmed, '}');
                if (cryptoCertDepth <= 0) {
                    putCert(certs, cryptoCert.toCert());
                    cryptoCert = null;
                }
                continue;
            }
            if (trimmed.startsWith("__F5_PARTITION__ ")) {
                currentPartition = stripPath(trimmed.substring("__F5_PARTITION__ ".length()).strip());
                continue;
            }
            if (trimmed.startsWith("__SSL_CERT_DATES__ ")) {
                mergeCertDates(certs, trimmed.substring("__SSL_CERT_DATES__ ".length()).strip(), currentPartition);
                continue;
            }
            if (trimmed.startsWith("auth partition ")) {
                String partition = token(trimmed, 2);
                if (!partition.isBlank()) {
                    partitions.computeIfAbsent(stripPath(partition), ignored -> new ArrayList<>());
                }
                continue;
            }
            if (trimmed.startsWith("ltm pool ")) {
                String poolPath = token(trimmed, 2);
                PoolPath pool = poolPath(poolPath);
                if (!pool.partition().isBlank()) {
                    partitions.computeIfAbsent(pool.partition(), ignored -> new ArrayList<>()).add(poolPath);
                    pools.put(poolPath, new PoolInventory(pool.partition(), pool.name(), poolPath, poolMembers(trimmed, serviceNames), oneLine(trimmed)));
                }
                continue;
            }
            if (trimmed.startsWith("ltm virtual ")) {
                VirtualInventory virtual = virtualInventory(trimmed);
                if (!virtual.partition().isBlank()) {
                    virtuals.put(virtual.path(), virtual);
                }
                continue;
            }
            if (trimmed.startsWith("ltm profile client-ssl ")) {
                ClientSslInventory profile = clientSslInventory(trimmed);
                if (!profile.path().isBlank()) {
                    putClientSslProfile(clientSslProfiles, profile);
                }
                continue;
            }
            if (trimmed.startsWith("ltm profile server-ssl ")) {
                ClientSslInventory profile = clientSslInventory(trimmed);
                if (!profile.path().isBlank()) {
                    putClientSslProfile(serverSslProfiles, profile);
                }
                continue;
            }
            if (trimmed.startsWith("sys crypto cert ")) {
                if (trimmed.contains("{") && !trimmed.endsWith("}")) {
                    cryptoCert = new CryptoCertBuilder(cryptoCertPath(token(trimmed, 3), currentPartition));
                    cryptoCertDepth = countChar(trimmed, '{') - countChar(trimmed, '}');
                    cryptoCert.read(trimmed);
                    if (cryptoCertDepth <= 0) {
                        putCert(certs, cryptoCert.toCert());
                        cryptoCert = null;
                    }
                } else {
                    CertInventory cert = cryptoCertInventory(trimmed, currentPartition);
                    if (!cert.path().isBlank()) {
                        putCert(certs, cert);
                    }
                }
                continue;
            }
            if (trimmed.startsWith("sys file ssl-cert ")) {
                CertInventory cert = certInventory(trimmed);
                if (!cert.path().isBlank()) {
                    putCert(certs, cert);
                }
            }
        }
        List<String> rows = new ArrayList<>();
        List<OutboundCheck> connectivityChecks = new ArrayList<>();
        Map<String, PartitionTraffic> partitionTraffic = partitionTraffic(virtuals, pools, virtualStats);
        for (Map.Entry<String, List<String>> entry : partitions.entrySet()) {
            if (!partitionPrefixFilter.isBlank() && !entry.getKey().startsWith(partitionPrefixFilter)) {
                continue;
            }
            if (entry.getValue().isEmpty()) {
                rows.add(entry.getKey() + "|(no pools)|");
            } else {
                for (String poolPath : entry.getValue()) {
                    PoolInventory pool = pools.get(poolPath);
                    if (pool == null) {
                        continue;
                    }
                    List<VirtualInventory> poolVirtuals = virtuals.values().stream()
                            .filter(virtual -> poolPath.equals(virtual.poolPath()))
                            .toList();
                    String memberSummary = pool.members().isEmpty() ? "none" : String.join("<br>", pool.members().stream().map(PoolMember::display).toList());
                    List<String> checkProtocols = poolVirtuals.isEmpty()
                            ? List.of("TCP")
                            : poolVirtuals.stream()
                            .map(virtual -> "udp".equalsIgnoreCase(virtual.protocol()) ? "UDP" : "TCP")
                            .distinct()
                            .toList();
                    addPoolMemberConnectivityChecks(connectivityChecks, pool, checkProtocols);
                    if (poolVirtuals.isEmpty()) {
                        rows.add(String.join("|", List.of(pool.partition(), "pool", pool.name(), "", "", partitionTraffic.getOrDefault(pool.partition(), PartitionTraffic.empty()).display(), memberSummary, "", "", "", "", "", "", "", "", "", pool.detail())));
                        continue;
                    }
                    for (VirtualInventory virtual : poolVirtuals) {
                        ClientSslInventory ssl = clientSslProfile(clientSslProfiles, virtual.clientSslProfile(), pool.partition());
                        String certDetail = ssl == null ? "" : certDetail(ssl.certPath(), certs, profilePartition(ssl, pool.partition()));
                        String chainDetail = ssl == null ? "" : chainDetail(ssl, certs, profilePartition(ssl, pool.partition()));
                        ClientSslInventory serverSsl = clientSslProfile(serverSslProfiles, virtual.serverSslProfile(), pool.partition());
                        String serverCertDetail = serverSsl == null ? "" : certDetail(serverSsl.certPath(), certs, profilePartition(serverSsl, pool.partition()));
                        String serverChainDetail = serverSsl == null ? "" : chainDetail(serverSsl, certs, profilePartition(serverSsl, pool.partition()));
                        rows.add(String.join("|", List.of(
                                pool.partition(),
                                "pool+vip",
                                pool.name(),
                                virtual.destination(),
                                virtual.protocol(),
                                partitionTraffic.getOrDefault(pool.partition(), PartitionTraffic.empty()).display(),
                                memberSummary,
                                virtualStatsFor(virtualStats, virtual).display(),
                                stripPath(virtual.clientSslProfile()),
                                ssl == null ? "" : stripPath(ssl.certPath()),
                                certDetail,
                                chainDetail,
                                stripPath(virtual.serverSslProfile()),
                                serverSsl == null ? "" : stripPath(serverSsl.certPath()),
                                serverCertDetail,
                                serverChainDetail,
                                "VIP " + virtual.name() + "; " + pool.detail()
                        )));
                    }
                }
            }
        }
        for (ClientSslInventory serverSsl : uniqueProfiles(serverSslProfiles)) {
            PoolPath profilePath = poolPath(serverSsl.path());
            if (!partitionPrefixFilter.isBlank() && !profilePath.partition().startsWith(partitionPrefixFilter)) {
                continue;
            }
            if (profilePath.partition().equals("Common") || serverSsl.certPath().isBlank()) {
                continue;
            }
            String serverCertDetail = serverSsl.certPath().isBlank()
                    ? "no certificate configured"
                    : certDetail(serverSsl.certPath(), certs, profilePath.partition());
            String serverChainDetail = serverSsl.certPath().isBlank()
                    ? ""
                    : chainDetail(serverSsl, certs, profilePath.partition());
            rows.add(String.join("|", List.of(
                    profilePath.partition(),
                    "server-ssl",
                    profilePath.name(),
                    "",
                    "",
                    partitionTraffic.getOrDefault(profilePath.partition(), PartitionTraffic.empty()).display(),
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    stripPath(serverSsl.path()),
                    stripPath(serverSsl.certPath()),
                    serverCertDetail,
                    serverChainDetail,
                    "F5 server-side outbound SSL profile"
            )));
        }
        return new F5Inventory(rows, connectivityChecks);
    }

    private static Map<String, PartitionTraffic> partitionTraffic(Map<String, VirtualInventory> virtuals, Map<String, PoolInventory> pools, Map<String, VirtualStats> virtualStats) {
        Map<String, PartitionTraffic> values = new LinkedHashMap<>();
        for (VirtualInventory virtual : virtuals.values()) {
            PoolInventory pool = pools.get(virtual.poolPath());
            String partition = pool == null ? virtual.partition() : pool.partition();
            if (partition.isBlank()) {
                continue;
            }
            values.merge(partition, PartitionTraffic.from(virtualStatsFor(virtualStats, virtual)), PartitionTraffic::plus);
        }
        return values;
    }

    private static VirtualStats virtualStatsFor(Map<String, VirtualStats> virtualStats, VirtualInventory virtual) {
        for (String alias : f5PathAliases(virtual.path(), virtual.partition())) {
            VirtualStats stats = virtualStats.get(alias);
            if (stats != null) {
                return stats;
            }
        }
        for (String alias : f5PathAliases(virtual.name(), virtual.partition())) {
            VirtualStats stats = virtualStats.get(alias);
            if (stats != null) {
                return stats;
            }
        }
        return VirtualStats.empty();
    }

    private static void putClientSslProfile(Map<String, ClientSslInventory> profiles, ClientSslInventory profile) {
        for (String alias : f5PathAliases(profile.path(), "")) {
            profiles.putIfAbsent(alias, profile);
        }
    }

    private static void putCert(Map<String, CertInventory> certs, CertInventory cert) {
        for (String alias : f5PathAliases(cert.path(), "")) {
            CertInventory existing = certs.get(alias);
            if (existing == null || cert.fromCrypto() || !existing.fromCrypto()) {
                certs.put(alias, cert);
            }
        }
    }

    private static ClientSslInventory clientSslProfile(Map<String, ClientSslInventory> profiles, String path, String partition) {
        for (String alias : f5PathAliases(path, partition)) {
            ClientSslInventory profile = profiles.get(alias);
            if (profile != null) {
                return profile;
            }
        }
        return null;
    }

    private static List<ClientSslInventory> uniqueProfiles(Map<String, ClientSslInventory> profiles) {
        Map<String, ClientSslInventory> unique = new LinkedHashMap<>();
        for (ClientSslInventory profile : profiles.values()) {
            unique.putIfAbsent(profile.path(), profile);
        }
        return new ArrayList<>(unique.values());
    }

    private static CertInventory cert(Map<String, CertInventory> certs, String path, String partition) {
        for (String alias : f5PathAliases(path, partition)) {
            CertInventory cert = certs.get(alias);
            if (cert != null) {
                return cert;
            }
        }
        return null;
    }

    private static List<String> f5PathAliases(String path, String partition) {
        if (path == null || path.isBlank()) {
            return List.of();
        }
        String normalized = path.strip();
        List<String> aliases = new ArrayList<>();
        aliases.add(normalized);
        if (normalized.startsWith("/")) {
            aliases.add(normalized.substring(1));
        } else {
            aliases.add("/" + normalized);
        }
        if (!partition.isBlank() && !normalized.contains("/")) {
            aliases.add(partition + "/" + normalized);
            aliases.add("/" + partition + "/" + normalized);
        }
        aliases.add(stripPath(normalized));
        if (normalized.endsWith(".crt")) {
            String withoutCrt = normalized.substring(0, normalized.length() - 4);
            aliases.add(withoutCrt);
            aliases.add(stripPath(withoutCrt));
        } else {
            aliases.add(normalized + ".crt");
            aliases.add(stripPath(normalized) + ".crt");
        }
        return aliases.stream().filter(alias -> !alias.isBlank()).distinct().toList();
    }

    private static void addPoolMemberConnectivityChecks(List<OutboundCheck> checks, PoolInventory pool, List<String> protocols) {
        for (PoolMember member : pool.members()) {
            if (member.address().isBlank() || member.port() <= 0) {
                continue;
            }
            for (String protocol : protocols) {
                String checkType = "TCP".equalsIgnoreCase(protocol) ? "CONNECT" : "RADIUS";
                checks.add(new OutboundCheck("pool:" + pool.partition() + "/" + pool.name() + ":" + protocol + ":" + member.address() + ":" + member.port(), member.address(), member.port(), protocol, checkType, true));
            }
            if (protocols.stream().anyMatch(protocol -> "TCP".equalsIgnoreCase(protocol))) {
                checks.add(new OutboundCheck("pool:" + pool.partition() + "/" + pool.name() + ":TLS:" + member.address() + ":" + member.port(), member.address(), member.port(), "TCP", "TLS", true));
            }
        }
    }

    private static Map<String, VirtualStats> virtualStats(String rawInventory) {
        Map<String, VirtualStats> stats = new LinkedHashMap<>();
        String currentPath = "";
        String bitsIn = "";
        String bitsOut = "";
        String bytesIn = "";
        String bytesOut = "";
        String packetsIn = "";
        String packetsOut = "";
        String currentConnections = "";
        boolean inVirtualStats = false;
        for (String line : lines(rawInventory)) {
            String trimmed = line.strip();
            if (trimmed.startsWith("Ltm::Virtual Server: ") || trimmed.startsWith("Ltm::Virtual Server /")) {
                if (!currentPath.isBlank()) {
                    putVirtualStats(stats, currentPath, new VirtualStats(bitsIn, bitsOut, bytesIn, bytesOut, packetsIn, packetsOut, currentConnections));
                }
                currentPath = trimmed.substring("Ltm::Virtual Server".length()).replace(":", "").strip();
                bitsIn = "";
                bitsOut = "";
                bytesIn = "";
                bytesOut = "";
                packetsIn = "";
                packetsOut = "";
                currentConnections = "";
                inVirtualStats = true;
                continue;
            }
            if (!inVirtualStats || currentPath.isBlank()) {
                continue;
            }
            String lower = trimmed.toLowerCase();
            if (lower.contains("bits in")) {
                bitsIn = statValue(trimmed);
            } else if (lower.contains("bits out")) {
                bitsOut = statValue(trimmed);
            } else if (lower.contains("bytes in")) {
                bytesIn = statValue(trimmed);
            } else if (lower.contains("bytes out")) {
                bytesOut = statValue(trimmed);
            } else if (lower.contains("packets in")) {
                packetsIn = statValue(trimmed);
            } else if (lower.contains("packets out")) {
                packetsOut = statValue(trimmed);
            } else if ((lower.contains("current") || lower.contains("cur")) && lower.contains("conn")) {
                currentConnections = statValue(trimmed);
            }
        }
        if (!currentPath.isBlank()) {
            putVirtualStats(stats, currentPath, new VirtualStats(bitsIn, bitsOut, bytesIn, bytesOut, packetsIn, packetsOut, currentConnections));
        }
        return stats;
    }

    private static void putVirtualStats(Map<String, VirtualStats> stats, String path, VirtualStats value) {
        PoolPath parsed = poolPath(path);
        for (String alias : f5PathAliases(path, parsed.partition())) {
            stats.putIfAbsent(alias, value);
        }
    }

    private static String statValue(String line) {
        Matcher matcher = Pattern.compile("([0-9][0-9,]*(?:\\.[0-9]+)?(?:\\s*[A-Za-z/]+)?)\\s*$").matcher(line);
        return matcher.find() ? matcher.group(1).replace(",", "") : "";
    }

    private static double statNumber(String value) {
        if (value == null || value.isBlank()) {
            return 0;
        }
        Matcher matcher = Pattern.compile("([0-9]+(?:\\.[0-9]+)?)").matcher(value.replace(",", ""));
        return matcher.find() ? doubleValue(matcher.group(1)) : 0;
    }

    private static String formatNumber(double value) {
        if (value == Math.rint(value)) {
            return Long.toString(Math.round(value));
        }
        return String.format(java.util.Locale.ROOT, "%.2f", value);
    }

    private static List<PoolMember> poolMembers(String line, Map<String, String> serviceNames) {
        List<PoolMember> members = new ArrayList<>();
        Matcher matcher = Pattern.compile("(?:/)?(?:[^\\s{}/]+/)?(\\d+(?:\\.\\d+){3}|[A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)\\s*\\{([^}]*)}").matcher(line);
        while (matcher.find()) {
            String address = valueAfter(matcher.group(3), "address");
            if (address.isBlank()) {
                address = matcher.group(1);
            }
            int port = servicePort(matcher.group(2), serviceNames);
            members.add(new PoolMember(address, port, oneLine(matcher.group(3))));
        }
        return members;
    }

    private static int servicePort(String value, Map<String, String> serviceNames) {
        if (value == null || value.isBlank()) {
            return 0;
        }
        String normalized = value.strip();
        if (normalized.matches("\\d+")) {
            return intValue(normalized);
        }
        for (Map.Entry<String, String> entry : serviceNames.entrySet()) {
            if (entry.getValue().equalsIgnoreCase(normalized)) {
                String[] parts = entry.getKey().split("\\|", -1);
                return intValue(part(parts, 1));
            }
        }
        return switch (normalized.toLowerCase()) {
            case "http" -> 80;
            case "https" -> 443;
            case "domain", "dns" -> 53;
            case "ssh" -> 22;
            case "smtp" -> 25;
            case "ldap" -> 389;
            case "ldaps" -> 636;
            default -> 0;
        };
    }

    private static VirtualInventory virtualInventory(String line) {
        String path = token(line, 2);
        PoolPath virtual = poolPath(path);
        return new VirtualInventory(
                virtual.partition(),
                virtual.name(),
                path,
                stripPartition(valueAfter(line, "destination")),
                valueAfter(line, "ip-protocol"),
                valueAfter(line, "pool"),
                firstClientSslProfile(line),
                firstServerSslProfile(line)
        );
    }

    private static ClientSslInventory clientSslInventory(String line) {
        String path = token(line, 3);
        String cert = configuredPath(firstPathAfter(line, "cert"));
        String chain = configuredPath(firstPathAfter(line, "chain"));
        return new ClientSslInventory(path, cert, chain);
    }

    private static String configuredPath(String value) {
        String normalized = value == null ? "" : value.strip();
        return "none".equalsIgnoreCase(normalized) ? "" : normalized;
    }

    private static CertInventory certInventory(String line) {
        String path = token(line, 3);
        return new CertInventory(
                path,
                "",
                quotedOrTokenAfter(line, "expiration-string"),
                valueAfter(line, "expiration-date"),
                quotedOrTokenAfter(line, "subject"),
                quotedOrTokenAfter(line, "issuer"),
                "",
                "",
                "",
                "",
                false
        );
    }

    private static CertInventory cryptoCertInventory(String line, String partition) {
        String path = cryptoCertPath(token(line, 3), partition);
        String commonName = cryptoValue(line, "common-name");
        String subject = cryptoValue(line, "subject");
        if (subject.isBlank() && !commonName.isBlank()) {
            subject = "CN=" + commonName;
        }
        return new CertInventory(
                path,
                "",
                cryptoValue(line, "expiration"),
                "",
                subject,
                cryptoValue(line, "issuer"),
                commonName,
                cryptoValue(line, "fingerprint"),
                cryptoValue(line, "certificate-key-size"),
                cryptoValue(line, "issuer-certificate"),
                true
        );
    }

    private static String cryptoCertPath(String path, String partition) {
        if (!partition.isBlank() && path != null && !path.contains("/")) {
            return partition + "/" + path;
        }
        return path == null ? "" : path;
    }

    private static String cryptoValue(String line, String key) {
        Matcher quoted = Pattern.compile("\\b" + Pattern.quote(key) + "\\s+\"([^\"]*)\"").matcher(line);
        if (quoted.find()) {
            return quoted.group(1);
        }
        Matcher matcher = Pattern.compile("\\b" + Pattern.quote(key) + "\\s+(.+?)(?=\\s+(?:" + CRYPTO_CERT_KEYS + ")\\b|\\s*}|$)").matcher(line);
        if (!matcher.find()) {
            return "";
        }
        String value = matcher.group(1).strip();
        return value.equals("{ }") ? "" : value;
    }

    private static String firstClientSslProfile(String line) {
        Matcher matcher = Pattern.compile("([^\\s{}]+)\\s*\\{\\s*context\\s+clientside").matcher(line);
        return matcher.find() ? matcher.group(1) : "";
    }

    private static String firstServerSslProfile(String line) {
        Matcher matcher = Pattern.compile("([^\\s{}]+)\\s*\\{\\s*context\\s+serverside").matcher(line);
        return matcher.find() ? matcher.group(1) : "";
    }

    private static String firstPathAfter(String line, String key) {
        return valueAfter(line, key);
    }

    private static String quotedOrTokenAfter(String line, String key) {
        Matcher quoted = Pattern.compile("\\b" + Pattern.quote(key) + "\\s+\"([^\"]*)\"").matcher(line);
        if (quoted.find()) {
            return quoted.group(1);
        }
        return valueAfter(line, key);
    }

    private static String valueAfter(String line, String key) {
        Matcher matcher = Pattern.compile("\\b" + Pattern.quote(key) + "\\s+([^\\s{}]+)").matcher(line);
        return matcher.find() ? matcher.group(1) : "";
    }

    private static int countChar(String value, char expected) {
        int count = 0;
        for (int index = 0; index < value.length(); index++) {
            if (value.charAt(index) == expected) {
                count++;
            }
        }
        return count;
    }

    private static String stripPartition(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String stripped = value.strip();
        int slash = stripped.lastIndexOf('/');
        return slash >= 0 && slash < stripped.length() - 1 ? stripped.substring(slash + 1) : stripped;
    }

    private static String certDetail(String certPath, Map<String, CertInventory> certs, String partition) {
        CertInventory cert = cert(certs, certPath, partition);
        if (cert == null) {
            return certPath.isBlank() ? "" : "cert object not listed: " + certPath;
        }
        return certValidity(cert) + installedCertDetail(cert);
    }

    private static String chainDetail(ClientSslInventory ssl, Map<String, CertInventory> certs, String partition) {
        if (ssl.chainPath().isBlank()) {
            CertInventory leaf = cert(certs, ssl.certPath(), partition);
            if (leaf == null) {
                return "no chain object configured";
            }
            return issuerChainDetail(leaf, certs, partition);
        }
        CertInventory chain = cert(certs, ssl.chainPath(), partition);
        if (chain == null) {
            return "chain object not listed: " + ssl.chainPath();
        }
        return stripPath(ssl.chainPath()) + " " + certValidity(chain)
                + installedCertDetail(chain)
                + issuerChainSuffix(chain, certs, partition, 2);
    }

    private static String installedCertDetail(CertInventory cert) {
        List<String> details = new ArrayList<>();
        if (!cert.notBefore().isBlank()) {
            details.add("valid from " + cert.notBefore());
        }
        if (!cert.expiration().isBlank()) {
            details.add("expires " + cert.expiration());
        }
        if (!cert.subject().isBlank()) {
            details.add("subject " + cert.subject());
        }
        if (!cert.issuer().isBlank()) {
            details.add("issuer " + cert.issuer());
        }
        if (details.isEmpty()) {
            details.add("certificate metadata not reported by tmsh");
        }
        String metadata = certMetadata(cert);
        if (!metadata.isBlank()) {
            details.add(metadata.substring(2));
        }
        return "; " + String.join("; ", details);
    }

    private static String issuerChainDetail(CertInventory leaf, Map<String, CertInventory> certs, String partition) {
        String suffix = issuerChainSuffix(leaf, certs, partition, 1);
        if (suffix.isBlank()) {
            return "leaf only" + installedCertDetail(leaf) + "; no separate chain object configured";
        }
        return "installed issuer chain" + suffix;
    }

    private static String issuerChainSuffix(CertInventory start, Map<String, CertInventory> certs, String partition, int firstIndex) {
        List<String> values = new ArrayList<>();
        CertInventory current = start;
        Set<String> seen = new java.util.LinkedHashSet<>();
        while (current != null && !current.issuerCertificate().isBlank()) {
            String issuerPath = current.issuerCertificate();
            CertInventory issuer = cert(certs, issuerPath, partition);
            if (issuer == null) {
                values.add("CA #" + (firstIndex + values.size()) + " object not listed: " + issuerPath);
                break;
            }
            String key = issuer.path().isBlank() ? issuerPath : issuer.path();
            if (!seen.add(key)) {
                values.add("CA #" + (firstIndex + values.size()) + " repeats issuer-certificate " + issuerPath);
                break;
            }
            values.add("CA #" + (firstIndex + values.size()) + " " + stripPath(issuer.path()) + " "
                    + certValidity(issuer)
                    + installedCertDetail(issuer));
            current = issuer;
        }
        return values.isEmpty() ? "" : "; " + String.join("; ", values);
    }

    private static String certMetadata(CertInventory cert) {
        List<String> values = new ArrayList<>();
        if (!cert.commonName().isBlank()) {
            values.add("common-name " + cert.commonName());
        }
        if (!cert.keySize().isBlank()) {
            values.add("key-size " + cert.keySize());
        }
        if (!cert.fingerprint().isBlank()) {
            values.add("fingerprint " + cert.fingerprint());
        }
        if (!cert.issuerCertificate().isBlank()) {
            values.add("issuer-certificate " + cert.issuerCertificate());
        }
        return values.isEmpty() ? "" : "; " + String.join("; ", values);
    }

    private static void mergeCertDates(Map<String, CertInventory> certs, String marker, String partition) {
        int separator = marker.indexOf(';');
        String path = separator >= 0 ? marker.substring(0, separator).strip() : marker.strip();
        String values = separator >= 0 ? marker.substring(separator + 1) : "";
        String notBefore = markerValue(values, "NOT_BEFORE");
        String notAfter = markerValue(values, "NOT_AFTER");
        String fingerprint = markerValue(values, "FINGERPRINT");
        for (String alias : f5PathAliases(path, partition)) {
            CertInventory existing = certs.get(alias);
            if (existing == null) {
                continue;
            }
            CertInventory merged = new CertInventory(
                    existing.path(),
                    notBefore.isBlank() ? existing.notBefore() : notBefore,
                    notAfter.isBlank() ? existing.expiration() : notAfter,
                    existing.expirationEpoch(),
                    existing.subject(),
                    existing.issuer(),
                    existing.commonName(),
                    fingerprint.isBlank() ? existing.fingerprint() : fingerprint,
                    existing.keySize(),
                    existing.issuerCertificate(),
                    existing.fromCrypto()
            );
            for (String existingAlias : f5PathAliases(existing.path(), "")) {
                certs.put(existingAlias, merged);
            }
        }
    }

    private static String profilePartition(ClientSslInventory ssl, String fallbackPartition) {
        PoolPath profilePath = poolPath(ssl.path());
        return profilePath.partition().isBlank() || "Common".equals(profilePath.partition()) ? fallbackPartition : profilePath.partition();
    }

    private static String certValidity(CertInventory cert) {
        long epoch = certExpirationEpoch(cert);
        if (epoch <= 0) {
            return "validity unknown";
        }
        long now = Instant.now().getEpochSecond();
        if (epoch < now) {
            return "EXPIRED";
        }
        long days = Math.max(0, (epoch - now) / 86_400);
        return days < 90 ? "EXPIRING in " + days + " days" : "VALID for " + days + " days";
    }

    private static long certExpirationEpoch(CertInventory cert) {
        long epoch = longValue(cert.expirationEpoch());
        if (epoch > 0) {
            return epoch;
        }
        return certExpirationEpoch(cert.expiration());
    }

    private static long certExpirationEpoch(String expiration) {
        if (expiration == null || expiration.isBlank()) {
            return 0;
        }
        try {
            return ZonedDateTime.parse(expiration.strip(), DateTimeFormatter.ofPattern("MMM d HH:mm:ss yyyy z", Locale.US).withZone(ZoneOffset.UTC)).toEpochSecond();
        } catch (DateTimeParseException ignored) {
            return 0;
        }
    }

    private static List<String> poolMemberConnectivityChecks(SshCommandClient ssh, ValidationCommands commands, List<OutboundCheck> checks) {
        return outboundChecks(ssh, commands, checks, false);
    }

    private static String emptyAsUnknown(String value) {
        return value == null || value.isBlank() ? "unknown" : value;
    }

    private static String token(String value, int index) {
        String[] parts = value.split("\\s+");
        return index < parts.length ? parts[index] : "";
    }

    private static String part(String[] parts, int index) {
        return index < parts.length ? parts[index] : "";
    }

    private static PoolPath poolPath(String value) {
        String stripped = stripPath(value);
        if (value.startsWith("/")) {
            String[] parts = value.substring(1).split("/", 2);
            if (parts.length == 2) {
                return new PoolPath(parts[0], parts[1]);
            }
        }
        if (value.contains("/")) {
            String[] parts = value.split("/", 2);
            if (parts.length == 2 && !parts[0].isBlank() && !parts[1].isBlank()) {
                return new PoolPath(parts[0], parts[1]);
            }
        }
        return new PoolPath("Common", stripped);
    }

    private static String stripPath(String value) {
        String stripped = value == null ? "" : value.strip();
        int slash = stripped.lastIndexOf('/');
        return slash >= 0 && slash < stripped.length() - 1 ? stripped.substring(slash + 1) : stripped;
    }

    private record PoolPath(String partition, String name) {
    }

    private record F5Inventory(List<String> rows, List<OutboundCheck> connectivityChecks) {
        private static F5Inventory empty() {
            return new F5Inventory(List.of(), List.of());
        }
    }

    private record PoolInventory(String partition, String name, String path, List<PoolMember> members, String detail) {
    }

    private record PoolMember(String address, int port, String detail) {
        private String display() {
            return address + ":" + port + (detail.isBlank() ? "" : " " + detail);
        }
    }

    private record VirtualInventory(String partition, String name, String path, String destination, String protocol, String poolPath, String clientSslProfile, String serverSslProfile) {
    }

    private record VirtualStats(String bitsIn, String bitsOut, String bytesIn, String bytesOut, String packetsIn, String packetsOut, String currentConnections) {
        private static VirtualStats empty() {
            return new VirtualStats("", "", "", "", "", "", "");
        }

        private String display() {
            List<String> values = new ArrayList<>();
            if (!currentConnections.isBlank()) {
                values.add("current connections " + currentConnections);
            }
            if (!bitsIn.isBlank() || !bitsOut.isBlank()) {
                values.add("bits in/out " + emptyAsUnknown(bitsIn) + " / " + emptyAsUnknown(bitsOut));
            }
            if (!bytesIn.isBlank() || !bytesOut.isBlank()) {
                values.add("bytes in/out " + emptyAsUnknown(bytesIn) + " / " + emptyAsUnknown(bytesOut));
            }
            if (!packetsIn.isBlank() || !packetsOut.isBlank()) {
                values.add("packets in/out " + emptyAsUnknown(packetsIn) + " / " + emptyAsUnknown(packetsOut));
            }
            return String.join("<br>", values);
        }
    }

    private record PartitionTraffic(double bitsIn, double bitsOut, double bytesIn, double bytesOut, double packetsIn, double packetsOut, double currentConnections) {
        private static PartitionTraffic empty() {
            return new PartitionTraffic(0, 0, 0, 0, 0, 0, 0);
        }

        private static PartitionTraffic from(VirtualStats stats) {
            return new PartitionTraffic(
                    statNumber(stats.bitsIn()),
                    statNumber(stats.bitsOut()),
                    statNumber(stats.bytesIn()),
                    statNumber(stats.bytesOut()),
                    statNumber(stats.packetsIn()),
                    statNumber(stats.packetsOut()),
                    statNumber(stats.currentConnections())
            );
        }

        private PartitionTraffic plus(PartitionTraffic other) {
            return new PartitionTraffic(
                    bitsIn + other.bitsIn,
                    bitsOut + other.bitsOut,
                    bytesIn + other.bytesIn,
                    bytesOut + other.bytesOut,
                    packetsIn + other.packetsIn,
                    packetsOut + other.packetsOut,
                    currentConnections + other.currentConnections
            );
        }

        private String display() {
            List<String> values = new ArrayList<>();
            if (currentConnections > 0) {
                values.add("current connections " + formatNumber(currentConnections));
            }
            if (bitsIn > 0 || bitsOut > 0) {
                values.add("bits in/out " + formatNumber(bitsIn) + " / " + formatNumber(bitsOut));
            }
            if (bytesIn > 0 || bytesOut > 0) {
                values.add("bytes in/out " + formatNumber(bytesIn) + " / " + formatNumber(bytesOut));
            }
            if (packetsIn > 0 || packetsOut > 0) {
                values.add("packets in/out " + formatNumber(packetsIn) + " / " + formatNumber(packetsOut));
            }
            return String.join("<br>", values);
        }
    }

    private record ClientSslInventory(String path, String certPath, String chainPath) {
    }

    private record CertInventory(
            String path,
            String notBefore,
            String expiration,
            String expirationEpoch,
            String subject,
            String issuer,
            String commonName,
            String fingerprint,
            String keySize,
            String issuerCertificate,
            boolean fromCrypto) {
    }

    private static final class CryptoCertBuilder {
        private final String path;
        private String expiration = "";
        private String subject = "";
        private String issuer = "";
        private String commonName = "";
        private String fingerprint = "";
        private String keySize = "";
        private String issuerCertificate = "";

        private CryptoCertBuilder(String path) {
            this.path = path;
        }

        private void read(String line) {
            String[] parts = line.split("\\s+", 2);
            if (parts.length < 2) {
                return;
            }
            String key = parts[0];
            String value = parts[1].strip();
            if (value.isBlank() || "{".equals(value) || "}".equals(value)) {
                return;
            }
            switch (key) {
                case "certificate-key-size" -> keySize = value;
                case "common-name" -> commonName = value;
                case "expiration" -> expiration = value;
                case "fingerprint" -> fingerprint = value;
                case "issuer" -> issuer = value;
                case "issuer-certificate" -> issuerCertificate = value;
                case "subject" -> subject = value;
                default -> {
                }
            }
        }

        private CertInventory toCert() {
            String effectiveSubject = subject.isBlank() && !commonName.isBlank() ? "CN=" + commonName : subject;
            return new CertInventory(path, "", expiration, "", effectiveSubject, issuer, commonName, fingerprint, keySize, issuerCertificate, true);
        }
    }

    private static boolean isDecimal(String value) {
        try {
            Double.parseDouble(value);
            return true;
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private static List<String> outboundChecks(SshCommandClient ssh, ValidationCommands commands, List<OutboundCheck> checks) {
        return outboundChecks(ssh, commands, checks, false);
    }

    private static List<String> outboundChecks(SshCommandClient ssh, ValidationCommands commands, List<OutboundCheck> checks, boolean addTlsForTcp) {
        if (checks.isEmpty() || !commands.hasCommand("CK31")) {
            return List.of();
        }
        List<String> results = new ArrayList<>();
        String timeoutSeconds = env("OUTBOUND_CHECK_TIMEOUT_SECONDS", "5");
        for (OutboundCheck check : checks) {
            if ("TCP".equalsIgnoreCase(check.protocol()) && "TLS".equalsIgnoreCase(check.checkType())) {
                results.add(tlsOutboundCheck(ssh, commands, check, timeoutSeconds));
                continue;
            }
            ValidationCommand command = commands.command("CK31", Map.of(
                    "CHECK_NAME", shellQuote(check.name()),
                    "HOST", shellQuote(check.host()),
                    "PORT", Integer.toString(check.port()),
                    "PROTOCOL", shellQuote(check.protocol()),
                    "CHECK_TYPE", shellQuote(check.checkType()),
                    "TIMEOUT_SECONDS", timeoutSeconds
            ));
            long started = System.nanoTime();
            String output = ssh.run(command);
            long elapsedMillis = elapsedMillis(started);
            boolean pass = output.contains("OUTBOUND_CHECK_PASS");
            boolean unknown = output.contains("OUTBOUND_CHECK_UNKNOWN");
            results.add(check.name() + "|" + check.host() + "|" + resolvedIp(output, check.host()) + "|" + check.port() + "|" + check.protocol() + "|"
                    + (pass ? "PASS" : unknown ? "UNKNOWN" : "FAIL") + "|" + oneLine(output + "\nELAPSED_MS=" + elapsedMillis));
            if (addTlsForTcp && "TCP".equalsIgnoreCase(check.protocol()) && !check.explicitCheckType()) {
                results.add(tlsOutboundCheck(ssh, commands, new OutboundCheck(check.name() + ":TLS", check.host(), check.port(), "TCP", "TLS", true), timeoutSeconds));
            }
        }
        return results;
    }

    private static String tlsOutboundCheck(SshCommandClient ssh, ValidationCommands commands, OutboundCheck check, String timeoutSeconds) {
        if (!commands.hasCommand("CK34")) {
            String detail = "OUTBOUND_CHECK_UNKNOWN RESOLVED_IP=" + check.host() + " TLS_CERT_PRESENT=0; TLS_ERROR=TLS probe command is not defined";
            return check.name() + "|" + check.host() + "|" + check.host() + "|" + check.port() + "|TLS|UNKNOWN|" + detail;
        }
        ValidationCommand command = commands.command("CK34", Map.of(
                "HOST", shellQuote(check.host()),
                "PORT", Integer.toString(check.port()),
                "TIMEOUT_SECONDS", timeoutSeconds
        ));
        long started = System.nanoTime();
        String output = ssh.run(command);
        long elapsedMillis = elapsedMillis(started);
        String notAfter = markerValue(output, "TLS_CERT_NOT_AFTER");
        String validity = notAfter.isBlank() ? "" : tlsCertValidity(notAfter);
        if (!validity.isBlank()) {
            output = output + "\nTLS_CERT_VALIDITY=" + validity;
        }
        output = output + "\nELAPSED_MS=" + elapsedMillis;
        boolean pass = output.contains("OUTBOUND_CHECK_PASS");
        boolean unknown = output.contains("OUTBOUND_CHECK_UNKNOWN");
        return check.name() + "|" + check.host() + "|" + resolvedIp(output, check.host()) + "|" + check.port() + "|TLS|"
                + (pass ? "PASS" : unknown ? "UNKNOWN" : "FAIL") + "|" + oneLine(output);
    }

    private static long elapsedMillis(long started) {
        return Math.max(0, (System.nanoTime() - started) / 1_000_000L);
    }

    private static String tlsCertValidity(String notAfter) {
        long epoch = certExpirationEpoch(notAfter);
        if (epoch <= 0) {
            return "validity unknown";
        }
        long now = Instant.now().getEpochSecond();
        if (epoch < now) {
            return "EXPIRED";
        }
        long days = Math.max(0, (epoch - now) / 86_400);
        return days < 90 ? "EXPIRING in " + days + " days" : "VALID for " + days + " days";
    }

    private static String markerValue(String output, String key) {
        Matcher matcher = Pattern.compile(Pattern.quote(key) + "=([^;\\n]+)").matcher(output == null ? "" : output);
        return matcher.find() ? matcher.group(1).strip() : "";
    }

    private static String resolvedIp(String output, String fallback) {
        for (String line : lines(output)) {
            if (line.startsWith("RESOLVED_IP=")) {
                String value = line.substring("RESOLVED_IP=".length()).strip();
                if (!value.isBlank()) {
                    return value;
                }
            }
        }
        return fallback;
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

    private static long conntrackCount(String nfConntrackCount, String connectionOutput) {
        long conntrack = longValue(nfConntrackCount);
        return conntrack > 0 ? conntrack : lines(connectionOutput).stream().filter(line -> !line.isBlank()).count();
    }

    private static List<String> activeConnectionGroups(String connectionOutput) {
        Map<String, Integer> counts = new HashMap<>();
        for (String line : lines(connectionOutput)) {
            String[] parts = line.trim().split("\\s+");
            if (parts.length < 5) {
                continue;
            }
            String proto = parts[0];
            if ("Netid".equalsIgnoreCase(proto) || "Proto".equalsIgnoreCase(proto)) {
                continue;
            }
            ActiveSocket socket = activeSocket(parts);
            if (socket == null) {
                continue;
            }
            Endpoint local = socket.local();
            Endpoint peer = socket.peer();
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

    private static ActiveSocket activeSocket(String[] parts) {
        if (parts.length >= 6 && parts[1].matches("\\d+") && parts[2].matches("\\d+")) {
            String state = parts[5].toUpperCase(java.util.Locale.ROOT);
            if (parts[0].startsWith("tcp") && !"ESTABLISHED".equals(state)) {
                return null;
            }
            return new ActiveSocket(endpoint(cleanEndpoint(parts[3])), endpoint(cleanEndpoint(parts[4])));
        }
        return new ActiveSocket(endpoint(cleanEndpoint(parts[parts.length - 2])), endpoint(cleanEndpoint(parts[parts.length - 1])));
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

    private static String oneLine(String value) {
        return value == null ? "" : value.strip().replaceAll("\\s+", " ");
    }

    private static String safeFileName(String value) {
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    private static String safeTimestamp(String value) {
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
    }
}
