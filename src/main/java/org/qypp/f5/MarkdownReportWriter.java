package org.qypp.f5;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class MarkdownReportWriter {
    private MarkdownReportWriter() {
    }

    public static String write(List<F5Report> reports) {
        StringBuilder markdown = new StringBuilder();
        markdown.append("# Validation Report\n\n");
        markdown.append("Generated at: ").append(OffsetDateTime.now()).append("\n\n");
        markdown.append("## Summary\n\n");
        markdown.append("| Label | Host | Type | Status | Failed checks | Privilege | CPU Core / Load | Processes by CPU | Memory | Processes by Memory | Disk | IP Connections | Active connection groups | Listener details | Network interfaces | Service details |\n");
        markdown.append("| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");

        reports.stream()
                .sorted(Comparator.comparing(F5Report::hostname))
                .forEach(report -> markdown.append("| ")
                        .append(escape(displayLabel(report))).append(" | ")
                        .append(escape(report.hostname())).append(" | ")
                        .append(escape(report.targetType())).append(" | ")
                        .append(statusCell(report.status())).append(" | ")
                        .append(report.checks().stream().filter(F5Check::failed).count()).append(" | ")
                        .append(privilegeSummary(report)).append(" | ")
                        .append(cpuLoadSummary(report)).append(" | ")
                        .append(cpuProcessSummary(report.processesByCpu())).append(" | ")
                        .append(metricCell(report.memoryUsedPercent(), gb(report.memoryUsedKb()) + " / " + gb(report.memoryTotalKb()) + " GB")).append(" | ")
                        .append(memoryProcessSummary(report)).append(" | ")
                        .append(metricCell(report.diskUsedPercent(), diskSummary(report))).append(" | ")
                        .append(ipConnectionCell(report)).append(" | ")
                        .append(activeConnectionSummary(report)).append(" | ")
                        .append(listenerSummary(report)).append(" | ")
                        .append(networkSummary(report)).append(" | ")
                        .append(serviceSummary(report)).append(" |\n"));

        markdown.append("\n## Network Topology\n\n");
        markdown.append(networkTopology(reports)).append("\n");

        markdown.append("\n## Device Details\n\n");
        for (F5Report report : reports.stream().sorted(Comparator.comparing(F5Report::hostname)).toList()) {
            markdown.append("### ").append(escape(displayLabel(report))).append("\n\n");
            markdown.append("- Hostname: ").append(escape(report.hostname())).append("\n");
            markdown.append("- Collected at: ").append(report.collectedAt()).append("\n");
            markdown.append("- Type: ").append(escape(report.targetType())).append("\n");
            markdown.append("- Privilege mode: ").append(privilegeSummary(report)).append("\n");
            markdown.append("- Command mode: read-only diagnostics; no service restart, config write, package install, or filesystem mutation commands are executed\n");
            markdown.append("- OS: ").append(emptyAsUnknown(report.os())).append("\n");
            markdown.append("- Uptime: ").append(emptyAsUnknown(report.uptime())).append("\n");
            markdown.append("- Processes: ").append(report.processCount()).append("\n");
            markdown.append("- CPU cores: ").append(report.cpuCoreCount()).append("\n");
            markdown.append("- Load average: ")
                    .append(format(report.loadAverage1m())).append(" / ")
                    .append(format(report.loadAverage5m())).append(" / ")
                    .append(format(report.loadAverage15m())).append(" (1m / 5m / 15m)\n");
            markdown.append("- Memory: ").append(report.memoryUsedPercent()).append("%")
                    .append(" (").append(gb(report.memoryUsedKb())).append(" GB used / ")
                    .append(gb(report.memoryTotalKb())).append(" GB total)\n");
            markdown.append("- Disk: ").append(report.diskUsedPercent()).append("%\n");
            markdown.append("- IP connections: ").append(report.ipConnectionCount()).append(" current / ")
                    .append(report.ipConnectionMax()).append(" max\n");
            markdown.append("- Active connection groups: ").append(report.activeConnections().size()).append("\n");
            markdown.append("- Critical services down: ").append(emptyAsOk(report.criticalServices())).append("\n");
            markdown.append("- External listening ports: ").append(report.externalListeningPorts()).append("\n");
            markdown.append("- Non-local listener endpoints: ").append(report.listeningEndpoints().size()).append("\n");
            markdown.append("- Network interfaces: ").append(report.networkInterfaces().size()).append("\n");
            markdown.append("- Running services listed: ").append(visibleServices(report).size()).append("\n");
            markdown.append("- Recent `/var/log` errors: ").append(report.recentLogErrors().size()).append("\n\n");
            markdown.append("Resource graphs:\n\n");
            markdown.append("- Load 1m: ").append(metricCell(report.loadAverage1mPercent(), loadDetail(report.loadAverage1m()))).append("\n");
            markdown.append("- Load 5m: ").append(metricCell(report.loadAverage5mPercent(), loadDetail(report.loadAverage5m()))).append("\n");
            markdown.append("- Load 15m: ").append(metricCell(report.loadAverage15mPercent(), loadDetail(report.loadAverage15m()))).append("\n");
            markdown.append("- Memory: ").append(htmlBar(report.memoryUsedPercent())).append("\n");
            markdown.append("- Disk: ").append(htmlBar(report.diskUsedPercent())).append("\n");
            if (report.ipConnectionMax() > 0) {
                long connPercent = Math.round(report.ipConnectionCount() * 100.0 / report.ipConnectionMax());
                markdown.append("- IP connections: ").append(htmlBar(connPercent)).append("\n");
            }
            markdown.append("\n");
            if (!report.diskMounts().isEmpty()) {
                markdown.append("| Mount | Total GB | Used GB | Free GB | Available GB | Used |\n");
                markdown.append("| --- | ---: | ---: | ---: | ---: | ---: |\n");
                for (String mount : report.diskMounts()) {
                    String[] parts = mount.split("\\|", -1);
                    markdown.append("| ")
                            .append(escape(part(parts, 0))).append(" | ")
                            .append(escape(part(parts, 1))).append(" | ")
                            .append(escape(part(parts, 2))).append(" | ")
                            .append(escape(part(parts, 3))).append(" | ")
                            .append(escape(diskAvailable(parts))).append(" | ")
                            .append(escape(diskUsedPercent(parts))).append(" |\n");
                }
                markdown.append("\n");
            }
            if (!report.processesByCpu().isEmpty()) {
                markdown.append("Processes sorted by CPU (")
                        .append(report.processesByCpu().size())
                        .append("):\n\n");
                appendProcessTable(markdown, report.processesByCpu());
            }
            if (!report.processesByMemory().isEmpty()) {
                markdown.append("Processes sorted by memory (")
                        .append(report.processesByMemory().size())
                        .append("):\n\n");
                appendProcessTable(markdown, report.processesByMemory());
            }
            if (!report.listeningEndpoints().isEmpty()) {
                markdown.append("| Protocol | Bind address/interface | Port | Process/service |\n");
                markdown.append("| --- | --- | ---: | --- |\n");
                for (String endpoint : report.listeningEndpoints()) {
                    String[] parts = endpoint.split("\\|", -1);
                    markdown.append("| ")
                            .append(escape(part(parts, 0))).append(" | ")
                            .append(listenerBindCell(part(parts, 1))).append(" | ")
                            .append(escape(part(parts, 2))).append(" | ")
                            .append(listenerServiceCell(parts)).append(" |\n");
                }
                markdown.append("\n");
            }
            if (!report.activeConnections().isEmpty()) {
                markdown.append("Active connections grouped by peer:\n\n");
                markdown.append("| Direction | Protocol | Peer IP | Service/peer port | Active count |\n");
                markdown.append("| --- | --- | --- | ---: | ---: |\n");
                for (String connection : report.activeConnections()) {
                    ActiveConnection parts = activeConnection(connection);
                    markdown.append("| ")
                            .append(escape(directionLabel(parts.direction()))).append(" | ")
                            .append(escape(parts.protocol())).append(" | ")
                            .append(escape(parts.peerIp())).append(" | ")
                            .append(escape(parts.port())).append(" | ")
                            .append(escape(parts.count())).append(" |\n");
                }
                markdown.append("\n");
            }
            if (!report.networkInterfaces().isEmpty()) {
                markdown.append("Network interfaces:\n\n");
                markdown.append("| Interface | IP addresses | RX GB | TX GB |\n");
                markdown.append("| --- | --- | ---: | ---: |\n");
                for (String networkInterface : report.networkInterfaces()) {
                    String[] parts = networkInterface.split("\\|", -1);
                    markdown.append("| ")
                            .append(escape(part(parts, 0))).append(" | ")
                            .append(escape(emptyAsUnknown(part(parts, 1)))).append(" | ")
                            .append(escape(part(parts, 2))).append(" | ")
                            .append(escape(part(parts, 3))).append(" |\n");
                }
                markdown.append("\n");
            }
            List<String> visibleServices = visibleServices(report);
            if (!visibleServices.isEmpty()) {
                markdown.append("Running services (")
                        .append(visibleServices.size())
                        .append("):\n\n");
                appendSingleColumnTable(markdown, "Service", visibleServices);
                markdown.append("\n");
            }
            markdown.append("| Check | Status | Detail |\n");
            markdown.append("| --- | --- | --- |\n");
            for (F5Check check : report.checks()) {
                markdown.append("| ")
                        .append(escape(check.name())).append(" | ")
                        .append(check.status()).append(" | ")
                        .append(escape(check.detail())).append(" |\n");
            }
            if (!report.recentLogErrors().isEmpty()) {
                markdown.append("\nRecent log findings:\n\n");
                for (String error : report.recentLogErrors()) {
                    markdown.append("- `").append(error.replace("`", "'")).append("`\n");
                }
            }
            markdown.append("\n");
        }
        return markdown.toString();
    }

    private static String emptyAsOk(List<?> values) {
        return values.isEmpty() ? "none" : values.toString();
    }

    private static List<String> visibleServices(F5Report report) {
        return report.runningServices().stream()
                .filter(MarkdownReportWriter::activeNonExitedService)
                .toList();
    }

    private static String emptyAsUnknown(String value) {
        return value == null || value.isBlank() ? "unknown" : escape(value);
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("|", "\\|").replace("\n", " ");
    }

    private static String displayLabel(F5Report report) {
        return report.label() == null || report.label().isBlank() ? report.hostname() : report.label();
    }

    private static String privilegeSummary(F5Report report) {
        String mode = report.privilegeMode() == null || report.privilegeMode().isBlank() ? "standard" : report.privilegeMode();
        return report.privilegedCollection() ? escape(mode) + " read-only" : escape(mode);
    }

    private static String gb(long kb) {
        return String.format("%.2f", kb / 1024.0 / 1024.0);
    }

    private static String part(String[] parts, int index) {
        return index < parts.length ? parts[index] : "";
    }

    private static String bar(long percent) {
        long bounded = Math.max(0, Math.min(100, percent));
        int filled = (int) Math.round(bounded / 10.0);
        return "#".repeat(filled) + "-".repeat(10 - filled);
    }

    private static String coloredBar(long percent) {
        long bounded = Math.max(0, Math.min(100, percent));
        int filled = (int) Math.round(bounded / 10.0);
        String fill = bounded >= 80 ? "🟥" : bounded >= 60 ? "🟨" : "🟩";
        return fill.repeat(filled) + "⬜".repeat(10 - filled);
    }

    private static String htmlBar(long percent) {
        return htmlBar(percent, Math.max(0, Math.min(100, percent)) + "%");
    }

    private static String htmlBar(long percent, String text) {
        long bounded = Math.max(0, Math.min(100, percent));
        String color = bounded >= 80 ? "#dc2626" : bounded >= 60 ? "#f59e0b" : "#16a34a";
        return "<span style=\"display:inline-block;position:relative;width:120px;height:14px;line-height:14px;background:#e5e7eb;border:1px solid #9ca3af;text-align:center;font-size:10px;color:#111827\">" +
                "<span style=\"display:block;width:" + bounded + "%;height:14px;background:" + color + "\"></span>" +
                "<span style=\"position:relative;top:-14px\">" + escape(text) + "</span></span>";
    }

    private static String metricCell(long percent, String detail) {
        if (detail == null || detail.isBlank()) {
            return htmlBar(percent);
        }
        return htmlBar(percent) + "<br><small>" + detail + "</small>";
    }

    private static String loadSummary(F5Report report) {
        return miniMetric("1m", report.loadAverage1mPercent(), report.loadAverage1m())
                + "<br>" + miniMetric("5m", report.loadAverage5mPercent(), report.loadAverage5m())
                + "<br>" + miniMetric("15m", report.loadAverage15mPercent(), report.loadAverage15m());
    }

    private static String cpuLoadSummary(F5Report report) {
        return "<strong>" + report.cpuCoreCount() + " cores</strong><br>" + loadSummary(report);
    }

    private static String statusCell(String status) {
        String normalized = status == null ? "" : status.strip().toUpperCase();
        String color = switch (normalized) {
            case "PASS", "OK" -> "#15803d";
            case "WARN", "WARNING" -> "#f97316";
            case "FAIL", "FAILED", "ERROR" -> "#dc2626";
            default -> "#475569";
        };
        return "<strong style=\"color:" + color + "\">" + escape(status) + "</strong>";
    }

    private static String miniMetric(String label, long percent, double load) {
        return miniBar(percent, label + " " + format(load));
    }

    private static String miniBar(long percent, String text) {
        long bounded = Math.max(0, Math.min(100, percent));
        String color = bounded >= 80 ? "#dc2626" : bounded >= 60 ? "#f59e0b" : "#16a34a";
        return "<span style=\"display:inline-block;position:relative;width:72px;height:11px;line-height:11px;background:#e5e7eb;border:1px solid #9ca3af;text-align:center;font-size:9px;color:#111827\">" +
                "<span style=\"display:block;width:" + bounded + "%;height:11px;background:" + color + "\"></span>" +
                "<span style=\"position:relative;top:-11px\">" + escape(text) + "</span></span>";
    }

    private static String ipConnectionCell(F5Report report) {
        if (report.ipConnectionMax() <= 0) {
            return "<small>" + report.ipConnectionCount() + " current<br>" + report.ipConnectionMax() + " max</small>";
        }
        long percent = Math.round(report.ipConnectionCount() * 100.0 / report.ipConnectionMax());
        return metricCell(percent, report.ipConnectionCount() + " current<br>" + report.ipConnectionMax() + " max");
    }

    private static String activeConnectionSummary(F5Report report) {
        if (report.activeConnections().isEmpty()) {
            return "none";
        }
        List<String> values = report.activeConnections().stream()
                .map(MarkdownReportWriter::compactActiveConnection)
                .toList();
        List<String> top = values.stream().limit(5).toList();
        if (values.size() <= 5) {
            return String.join("<br>", top);
        }
        return String.join("<br>", top)
                + "<br><details><summary>+" + (values.size() - 5) + " more</summary>"
                + String.join("<br>", values.subList(5, values.size()))
                + "</details>";
    }

    private static String compactActiveConnection(String connection) {
        ActiveConnection parts = activeConnection(connection);
        return "<small>" + escape(directionLabel(parts.direction())) + " "
                + escape(parts.protocol()) + " "
                + escape(parts.peerIp()) + ":" + escape(parts.port())
                + " count " + escape(parts.count()) + "</small>";
    }

    private static String diskSummary(F5Report report) {
        if (report.diskMounts().isEmpty()) {
            return "max " + report.diskUsedPercent() + "%";
        }
        String[] parts = report.diskMounts().get(0).split("\\|", -1);
        return part(parts, 2) + " used / " + part(parts, 1) + " total GB";
    }

    private static String listenerSummary(F5Report report) {
        if (report.listeningEndpoints().isEmpty()) {
            return "<strong>0 listeners</strong>";
        }
        List<String> values = report.listeningEndpoints().stream()
                .map(MarkdownReportWriter::compactListener)
                .toList();
        String header = "<strong>" + report.listeningEndpoints().size() + " listeners</strong>";
        if (values.size() <= 10) {
            return header + "<br>" + String.join("<br>", values);
        }
        List<String> top = values.stream().limit(10).toList();
        return header + "<br>" + String.join("<br>", top)
                + "<br><details><summary>+" + (values.size() - 10) + " more</summary>"
                + String.join("<br>", values.subList(10, values.size()))
                + "</details>";
    }

    private static String compactListener(String endpoint) {
        String[] parts = endpoint.split("\\|", -1);
        String value = escape(part(parts, 0)) + " " + escape(part(parts, 1)) + ":" + escape(part(parts, 2)) + " " + escape(part(parts, 3));
        if ("0.0.0.0".equals(part(parts, 1))) {
            return "<small><strong style=\"color:#dc2626\">" + value + "</strong></small>";
        }
        return "<small>" + value + "</small>";
    }

    private static String listenerBindCell(String bindAddress) {
        if ("0.0.0.0".equals(bindAddress)) {
            return "<strong style=\"color:#dc2626\">0.0.0.0</strong>";
        }
        return escape(bindAddress);
    }

    private static String listenerServiceCell(String[] parts) {
        String service = escape(part(parts, 3));
        if ("0.0.0.0".equals(part(parts, 1))) {
            return "<strong style=\"color:#dc2626\">" + service + "</strong>";
        }
        return service;
    }

    private static String cpuProcessSummary(List<String> processes) {
        if (processes.isEmpty()) {
            return "none";
        }
        return String.join("<br>", processes.stream()
                .limit(5)
                .map(MarkdownReportWriter::compactCpuProcess)
                .toList());
    }

    private static String compactCpuProcess(String process) {
        String[] parts = process.split("\\|", -1);
        double cpu = doubleValue(part(parts, 1));
        return "<small>" + escape(part(parts, 4)) + "</small> " + htmlBar(Math.round(cpu), String.format("%.1f%%", cpu));
    }

    private static String memoryProcessSummary(F5Report report) {
        if (report.processesByMemory().isEmpty()) {
            return "none";
        }
        double totalGb = report.memoryTotalKb() / 1024.0 / 1024.0;
        return String.join("<br>", report.processesByMemory().stream()
                .limit(5)
                .map(process -> compactMemoryProcess(process, totalGb))
                .toList());
    }

    private static String compactMemoryProcess(String process, double totalGb) {
        String[] parts = process.split("\\|", -1);
        double gb = mbToGbValue(part(parts, 3));
        long width = totalGb <= 0 ? 0 : Math.round(gb * 100.0 / totalGb);
        return "<small>" + escape(part(parts, 4)) + "</small> " + htmlBar(width, String.format("%.3f GB", gb));
    }

    private static double mbToGbValue(String mb) {
        try {
            return Double.parseDouble(mb) / 1024.0;
        } catch (NumberFormatException exception) {
            return 0;
        }
    }

    private static String serviceSummary(F5Report report) {
        if (report.runningServices().isEmpty()) {
            return "none";
        }
        List<String> services = visibleServices(report).stream()
                .sorted(Comparator.comparingInt(MarkdownReportWriter::serviceRank).thenComparing(MarkdownReportWriter::serviceName))
                .map(MarkdownReportWriter::serviceName)
                .map(service -> "<small>" + escape(service) + "</small>")
                .toList();
        if (services.isEmpty()) {
            return "none";
        }
        List<String> top = services.stream().limit(5).toList();
        if (services.size() <= 5) {
            return String.join("<br>", top);
        }
        return String.join("<br>", top)
                + "<br><details><summary>+" + (services.size() - 5) + " more</summary>"
                + String.join("<br>", services.subList(5, services.size()))
                + "</details>";
    }

    private static String networkSummary(F5Report report) {
        if (report.networkInterfaces().isEmpty()) {
            return "none";
        }
        double maxGb = report.networkInterfaces().stream()
                .map(networkInterface -> networkInterface.split("\\|", -1))
                .mapToDouble(parts -> Math.max(doubleValue(part(parts, 2)), doubleValue(part(parts, 3))))
                .max()
                .orElse(0);
        return String.join("<br>", report.networkInterfaces().stream()
                .map(networkInterface -> compactNetworkInterface(networkInterface, maxGb))
                .toList());
    }

    private static String compactNetworkInterface(String networkInterface, double maxGb) {
        String[] parts = networkInterface.split("\\|", -1);
        String ipv4 = ipv4Only(part(parts, 1));
        double rxGb = doubleValue(part(parts, 2));
        double txGb = doubleValue(part(parts, 3));
        return "<small>" + escape(part(parts, 0)) + " ip " + escape(ipv4) + "</small><br>"
                + "<small>RX</small> " + gbBar(rxGb, maxGb) + "<br>"
                + "<small>TX</small> " + gbBar(txGb, maxGb);
    }

    private static String gbBar(double valueGb, double maxGb) {
        long width = maxGb <= 0 ? 0 : Math.round(valueGb * 100.0 / maxGb);
        return htmlBar(width, String.format("%.3f GB", valueGb));
    }

    private static double doubleValue(String value) {
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException exception) {
            return 0;
        }
    }

    private static int intValue(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            return 0;
        }
    }

    private static String ipv4Only(String ips) {
        for (String ip : ips.split(",")) {
            if (ip.contains(".") && !ip.contains(":")) {
                return ip;
            }
        }
        return "unknown";
    }

    private static boolean activeNonExitedService(String service) {
        String normalized = " " + service.strip().replaceAll("\\s+", " ") + " ";
        return normalized.contains(" loaded active ") && !normalized.contains(" exited ");
    }

    private static String serviceName(String service) {
        String trimmed = service.strip();
        int space = trimmed.indexOf(' ');
        return space < 0 ? trimmed : trimmed.substring(0, space);
    }

    private static int serviceRank(String service) {
        String normalized = " " + service.strip().replaceAll("\\s+", " ") + " ";
        return normalized.contains(" loaded active running ") ? 0 : 1;
    }

    private static void appendProcessTable(StringBuilder markdown, List<String> processes) {
        markdown.append("| PID | CPU % | Memory % | RSS MB | Command |\n");
        markdown.append("| ---: | ---: | ---: | ---: | --- |\n");
        for (String process : processes.stream().limit(10).toList()) {
            appendProcessRow(markdown, process);
        }
        markdown.append("\n");
        if (processes.size() > 10) {
            markdown.append("<details><summary>+")
                    .append(processes.size() - 10)
                    .append(" more</summary>\n\n");
            markdown.append("| PID | CPU % | Memory % | RSS MB | Command |\n");
            markdown.append("| ---: | ---: | ---: | ---: | --- |\n");
            for (String process : processes.subList(10, processes.size())) {
                appendProcessRow(markdown, process);
            }
            markdown.append("\n</details>\n\n");
        }
    }

    private static void appendProcessRow(StringBuilder markdown, String process) {
        String[] parts = process.split("\\|", -1);
        markdown.append("| ")
                .append(escape(part(parts, 0))).append(" | ")
                .append(escape(part(parts, 1))).append(" | ")
                .append(escape(part(parts, 2))).append(" | ")
                .append(escape(part(parts, 3))).append(" | ")
                .append(escape(part(parts, 4))).append(" |\n");
    }

    private static void appendSingleColumnTable(StringBuilder markdown, String header, List<String> values) {
        markdown.append("| ").append(escape(header)).append(" |\n");
        markdown.append("| --- |\n");
        for (String value : values.stream().limit(10).toList()) {
            markdown.append("| ").append(escape(value)).append(" |\n");
        }
        markdown.append("\n");
        if (values.size() > 10) {
            markdown.append("<details><summary>+")
                    .append(values.size() - 10)
                    .append(" more</summary>\n\n");
            markdown.append("| ").append(escape(header)).append(" |\n");
            markdown.append("| --- |\n");
            for (String value : values.subList(10, values.size())) {
                markdown.append("| ").append(escape(value)).append(" |\n");
            }
            markdown.append("\n</details>\n\n");
        }
    }

    private static String loadDetail(double load) {
        return format(load) + " load";
    }

    private static String format(double value) {
        return String.format("%.2f", value);
    }

    private static String diskAvailable(String[] parts) {
        return parts.length >= 6 ? parts[4] : part(parts, 3);
    }

    private static String diskUsedPercent(String[] parts) {
        return parts.length >= 6 ? parts[5] : part(parts, 4);
    }

    private static String networkTopology(List<F5Report> reports) {
        List<TopologyInterface> interfaces = new ArrayList<>();
        List<TopologyConnection> connections = new ArrayList<>();
        for (F5Report report : reports.stream().sorted(Comparator.comparing(F5Report::hostname)).toList()) {
            String hostLabel = displayLabel(report) + " / " + report.hostname();
            for (String networkInterface : report.networkInterfaces()) {
                String[] parts = networkInterface.split("\\|", -1);
                String interfaceName = part(parts, 0);
                if ("lo".equals(interfaceName)) {
                    continue;
                }
                for (String ip : ipv4Addresses(part(parts, 1))) {
                    String subnet = subnet(ip);
                    if (!subnet.isBlank()) {
                        interfaces.add(new TopologyInterface(hostLabel, interfaceName, ip, subnet, doubleValue(part(parts, 2)), doubleValue(part(parts, 3))));
                    }
                }
            }
            for (String connection : report.activeConnections()) {
                ActiveConnection parts = activeConnection(connection);
                connections.add(new TopologyConnection(hostLabel, parts.direction(), parts.protocol(), parts.peerIp(), parts.port(), parts.count()));
            }
        }
        if (interfaces.isEmpty() && connections.isEmpty()) {
            return "No IPv4 interface CIDR or active connection data was collected, so no topology could be inferred.\n";
        }

        StringBuilder markdown = new StringBuilder();
        markdown.append("Inferred from collected IPv4 interface CIDR values and active connection peer groups. Hosts sharing a subnet are drawn inside the same subnet band; arrows separate incoming and outgoing peer connections.\n\n");
        markdown.append(topologyHtml(interfaces, connections)).append("\n");
        return markdown.toString();
    }

    private static String topologyHtml(List<TopologyInterface> interfaces, List<TopologyConnection> connections) {
        List<String> hosts = new ArrayList<>();
        for (TopologyInterface link : interfaces) {
            if (!hosts.contains(link.host())) {
                hosts.add(link.host());
            }
        }
        for (TopologyConnection link : connections) {
            if (!hosts.contains(link.host())) {
                hosts.add(link.host());
            }
        }
        List<String> subnets = new ArrayList<>();
        for (TopologyInterface link : interfaces) {
            if (!subnets.contains(link.subnet())) {
                subnets.add(link.subnet());
            }
        }
        Map<String, String> hostSubnet = new LinkedHashMap<>();
        for (String host : hosts) {
            String subnet = interfaces.stream()
                    .filter(link -> link.host().equals(host))
                    .map(TopologyInterface::subnet)
                    .findFirst()
                    .orElse("no IPv4 subnet");
            hostSubnet.put(host, subnet);
        }
        StringBuilder html = new StringBuilder();
        html.append("<div style=\"border:1px solid #cbd5e1;background:#ffffff;padding:12px;max-width:1160px;color:#111827;font-family:Arial,sans-serif\">");
        html.append("<div style=\"font-weight:700;font-size:15px;margin-bottom:10px\">Inferred IPv4 network and directional active connections</div>");

        html.append("<div style=\"font-size:12px;font-weight:700;color:#475569;margin:8px 0 6px\">Shared IPv4 subnets</div>");
        html.append("<div style=\"display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px\">");
        if (subnets.isEmpty()) {
            topologyMuted(html, "no IPv4 subnet data");
        } else {
            for (String subnet : subnets) {
                List<TopologyInterface> subnetInterfaces = interfaces.stream()
                        .filter(link -> link.subnet().equals(subnet))
                        .toList();
                html.append("<div style=\"border:1px solid #2563eb;background:#dbeafe;border-radius:6px;padding:8px;min-width:260px;max-width:360px\">");
                html.append("<div style=\"font-weight:700\">").append(htmlEscape(subnet)).append("</div>");
                html.append("<div style=\"font-size:11px;color:#475569;margin-top:4px\">");
                for (TopologyInterface link : subnetInterfaces) {
                    html.append("<div><strong>").append(htmlEscape(link.host())).append("</strong> ")
                            .append(htmlEscape(link.interfaceName())).append(" ")
                            .append(htmlEscape(link.ip())).append(" RX ")
                            .append(format(link.rxGb())).append(" GB / TX ")
                            .append(format(link.txGb())).append(" GB</div>");
                }
                html.append("</div></div>");
            }
        }
        html.append("</div>");

        html.append("<div style=\"font-size:12px;font-weight:700;color:#475569;margin:8px 0 6px\">Directional connections by subnet and VM</div>");
        for (String subnet : orderedSubnetGroups(hostSubnet, subnets)) {
            List<String> subnetHosts = hosts.stream()
                    .filter(host -> hostSubnet.get(host).equals(subnet))
                    .toList();
            html.append("<div style=\"border:2px solid #93c5fd;background:#eff6ff;border-radius:8px;padding:8px;margin:0 0 10px 0\">");
            html.append("<div style=\"display:inline-block;border:1px solid #2563eb;background:#dbeafe;border-radius:999px;padding:3px 9px;font-weight:700;font-size:12px;margin-bottom:8px\">")
                    .append(htmlEscape(subnet)).append("</div>");
            html.append("<div style=\"display:grid;grid-template-columns:minmax(250px,1fr) 28px minmax(190px,0.8fr) 28px minmax(250px,1fr);gap:8px;align-items:stretch\">");
            topologyHeader(html, "Incoming peers");
            html.append("<div></div>");
            topologyHeader(html, "VM / host");
            html.append("<div></div>");
            topologyHeader(html, "Outgoing peers");

            for (String host : subnetHosts) {
                List<TopologyInterface> hostInterfaces = interfaces.stream()
                        .filter(link -> link.host().equals(host))
                        .toList();
                List<TopologyConnection> hostConnections = connections.stream()
                        .filter(link -> link.host().equals(host))
                        .toList();
                List<TopologyConnection> incoming = hostConnections.stream()
                        .filter(link -> "in".equals(link.direction()))
                        .toList();
                List<TopologyConnection> outgoing = hostConnections.stream()
                        .filter(link -> !"in".equals(link.direction()))
                        .toList();

                topologyBubbles(html, incoming, "no incoming groups");
                topologyArrow(html);

                html.append("<div style=\"border:1px solid #16a34a;background:#dcfce7;border-radius:6px;padding:8px;text-align:center\">");
                html.append("<div style=\"font-weight:700\">").append(htmlEscape(host)).append("</div>");
                html.append("<div style=\"font-size:11px;color:#475569;margin-top:3px\">")
                        .append(hostInterfaces.size()).append(" interface links, ")
                        .append(hostConnections.size()).append(" connection groups</div>");
                for (TopologyInterface link : hostInterfaces) {
                    html.append("<div style=\"font-size:10px;color:#166534;margin-top:3px\">")
                            .append(htmlEscape(link.interfaceName())).append(" ")
                            .append(htmlEscape(link.ip())).append("</div>");
                }
                html.append("</div>");

                topologyArrow(html);
                topologyBubbles(html, outgoing, "no outgoing groups");
            }
            html.append("</div></div>");
        }
        html.append("</div>");
        return html.toString();
    }

    private static void topologyHeader(StringBuilder html, String text) {
        html.append("<div style=\"font-size:12px;font-weight:700;color:#475569;margin-bottom:2px\">")
                .append(htmlEscape(text)).append("</div>");
    }

    private static void topologyMuted(StringBuilder html, String text) {
        html.append("<div style=\"border:1px dashed #cbd5e1;background:#f8fafc;border-radius:6px;padding:7px;color:#64748b;font-size:12px\">")
                .append(htmlEscape(text)).append("</div>");
    }

    private static List<String> orderedSubnetGroups(Map<String, String> hostSubnet, List<String> subnets) {
        List<String> ordered = new ArrayList<>(subnets);
        for (String subnet : hostSubnet.values()) {
            if (!ordered.contains(subnet)) {
                ordered.add(subnet);
            }
        }
        return ordered;
    }

    private static void topologyArrow(StringBuilder html) {
        html.append("<div style=\"display:flex;align-items:center;justify-content:center\">")
                .append("<svg width=\"28\" height=\"20\" viewBox=\"0 0 28 20\" xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" aria-label=\"connection direction\">")
                .append("<line x1=\"2\" y1=\"10\" x2=\"21\" y2=\"10\" stroke=\"#2563eb\" stroke-width=\"2.5\" stroke-linecap=\"round\"/>")
                .append("<polygon points=\"20,4 27,10 20,16\" fill=\"#2563eb\"/>")
                .append("</svg></div>");
    }

    private static void topologyBubbles(StringBuilder html, List<TopologyConnection> connections, String emptyText) {
        html.append("<div>");
        if (connections.isEmpty()) {
            topologyMuted(html, emptyText);
        } else {
            for (PeerHostBubble bubble : peerHostBubbles(connections)) {
                html.append("<div style=\"display:inline-block;vertical-align:top;min-width:118px;max-width:190px;margin:0 8px 8px 0;text-align:center\">");
                html.append("<div style=\"display:flex;align-items:center;justify-content:center;width:")
                        .append(bubbleSize(bubble.totalCount())).append("px;height:")
                        .append(bubbleSize(bubble.totalCount())).append("px;margin:0 auto 5px;border-radius:999px;border:2px solid #f97316;background:#ffedd5;color:#111827\">");
                html.append("<div><div style=\"font-weight:700;font-size:12px;line-height:1.15\">")
                        .append(htmlEscape(bubble.peerIp())).append("</div>");
                html.append("<div style=\"font-weight:700;font-size:18px;line-height:1.1\">")
                        .append(bubble.totalCount()).append("</div>");
                html.append("<div style=\"font-size:10px;color:#9a3412;line-height:1.1\">connections</div></div></div>");
                html.append("<div style=\"border:1px solid #fed7aa;background:#fff7ed;border-radius:6px;padding:5px;text-align:left;font-size:11px;color:#475569\">");
                for (TopologyConnection link : bubble.connections()) {
                    html.append("<div>")
                            .append(htmlEscape(link.protocol())).append(" :")
                            .append(htmlEscape(link.port())).append(" count ")
                            .append(htmlEscape(link.count())).append("</div>");
                }
                html.append("</div></div>");
            }
        }
        html.append("</div>");
    }

    private static List<PeerHostBubble> peerHostBubbles(List<TopologyConnection> connections) {
        Map<String, List<TopologyConnection>> grouped = new LinkedHashMap<>();
        for (TopologyConnection connection : connections) {
            grouped.computeIfAbsent(connection.peerIp(), ignored -> new ArrayList<>()).add(connection);
        }
        List<PeerHostBubble> bubbles = new ArrayList<>();
        for (Map.Entry<String, List<TopologyConnection>> entry : grouped.entrySet()) {
            int total = entry.getValue().stream().mapToInt(connection -> intValue(connection.count())).sum();
            bubbles.add(new PeerHostBubble(entry.getKey(), total, entry.getValue()));
        }
        bubbles.sort(Comparator.comparingInt(PeerHostBubble::totalCount).reversed().thenComparing(PeerHostBubble::peerIp));
        return bubbles;
    }

    private static int bubbleSize(int count) {
        return Math.max(74, Math.min(132, 66 + (int) Math.round(Math.sqrt(Math.max(1, count)) * 18)));
    }

    private static List<String> ipv4Addresses(String ips) {
        List<String> values = new ArrayList<>();
        for (String ip : ips.split(",")) {
            String trimmed = ip.strip();
            if (trimmed.contains(".") && !trimmed.contains(":")) {
                values.add(trimmed);
            }
        }
        return values;
    }

    private static String subnet(String cidr) {
        String[] parts = cidr.split("/", -1);
        if (parts.length != 2) {
            return "";
        }
        try {
            int prefix = Integer.parseInt(parts[1]);
            if (prefix < 0 || prefix > 32) {
                return "";
            }
            long address = ipv4ToLong(parts[0]);
            long mask = prefix == 0 ? 0 : (0xffffffffL << (32 - prefix)) & 0xffffffffL;
            return longToIpv4(address & mask) + "/" + prefix;
        } catch (RuntimeException exception) {
            return "";
        }
    }

    private static long ipv4ToLong(String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address");
        }
        long value = 0;
        for (String octet : octets) {
            int parsed = Integer.parseInt(octet);
            if (parsed < 0 || parsed > 255) {
                throw new IllegalArgumentException("Invalid IPv4 octet");
            }
            value = (value << 8) | parsed;
        }
        return value;
    }

    private static String longToIpv4(long value) {
        return ((value >> 24) & 255) + "."
                + ((value >> 16) & 255) + "."
                + ((value >> 8) & 255) + "."
                + (value & 255);
    }

    private static ActiveConnection activeConnection(String connection) {
        String[] parts = connection.split("\\|", -1);
        if (parts.length >= 5) {
            return new ActiveConnection(part(parts, 0), part(parts, 1), part(parts, 2), part(parts, 3), part(parts, 4));
        }
        return new ActiveConnection("peer", part(parts, 0), part(parts, 1), part(parts, 2), part(parts, 3));
    }

    private static String directionLabel(String direction) {
        return switch (direction) {
            case "in" -> "incoming";
            case "out" -> "outgoing";
            default -> "peer";
        };
    }

    private record ActiveConnection(String direction, String protocol, String peerIp, String port, String count) {
    }

    private record TopologyInterface(String host, String interfaceName, String ip, String subnet, double rxGb, double txGb) {
    }

    private record TopologyConnection(String host, String direction, String protocol, String peerIp, String port, String count) {
    }

    private record PeerHostBubble(String peerIp, int totalCount, List<TopologyConnection> connections) {
    }

    private static String htmlEscape(String value) {
        return value == null ? "" : value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
