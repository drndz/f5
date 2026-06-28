package org.qypp.f5;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class MarkdownReportWriter {
    private static final DateTimeFormatter HISTORY_TIME = DateTimeFormatter.ofPattern("MM-dd HH:mm").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter HISTORY_HOUR = DateTimeFormatter.ofPattern("MM-dd HH:00").withZone(ZoneOffset.UTC);
    private static final int HISTORY_GRAPH_POINTS = 96;
    private static final int HISTORY_GRAPH_STEP_PX = 6;
    private static final int HISTORY_GRAPH_HEIGHT_PX = 112;
    private static final int HISTORY_GRAPH_LABEL_WIDTH_PX = 70;
    private static final long HISTORY_AXIS_STEP_SECONDS = 6 * 3600L;

    private MarkdownReportWriter() {
    }

    public static String write(List<F5Report> reports) {
        return write(reports, false);
    }

    public static String write(List<F5Report> reports, boolean includeCommandDetails) {
        StringBuilder markdown = new StringBuilder();
        markdown.append("# Validation Report\n\n");
        markdown.append("Generated at: ").append(OffsetDateTime.now()).append("\n\n");
        markdown.append("## Summary\n\n");
        markdown.append("| Label | Host | Type | Status | Failed checks | Uptime | Privilege | Local users | Logged | CPU Core / Load | Processes by CPU | Memory | Processes by Memory | Disk | IP Connections | Active connection groups | Listener details | Network interfaces | Service details |\n");
        markdown.append("| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");

        reports.stream()
                .sorted(Comparator.comparing(F5Report::hostname))
                .forEach(report -> markdown.append("| ")
                        .append(escape(displayLabel(report))).append(" | ")
                        .append(escape(report.hostname())).append(" | ")
                        .append(escape(report.targetType())).append(" | ")
                        .append(statusCell(report.status())).append(" | ")
                        .append(report.checks().stream().filter(F5Check::failed).count()).append(" | ")
                        .append(emptyAsUnknown(report.uptime())).append(" | ")
                        .append(privilegeSummary(report)).append(" | ")
                        .append(userSummary(report)).append(" | ")
                        .append(loggedUserSummary(report)).append(" | ")
                        .append(cpuLoadSummary(report)).append(" | ")
                        .append(cpuProcessSummary(report.processesByCpu())).append(" | ")
                        .append(metricCell(report.memoryUsedPercent(), gb(report.memoryUsedKb()) + " / " + gb(report.memoryTotalKb()) + " GB")).append(" | ")
                        .append(memoryProcessSummary(report)).append(" | ")
                        .append(diskSummary(report)).append(" | ")
                        .append(ipConnectionCell(report)).append(" | ")
                        .append(activeConnectionSummary(report)).append(" | ")
                        .append(listenerSummary(report)).append(" | ")
                        .append(networkSummary(report)).append(" | ")
                        .append(serviceSummary(report)).append(" |\n"));

        markdown.append("\n## F5 RRD History\n\n");
        markdown.append(f5LoadHistorySummary(reports)).append("\n");

        markdown.append("\n## F5 Partitions And Pools\n\n");
        markdown.append(f5PartitionPoolSummary(reports)).append("\n");

        markdown.append("\n## Outbound Connectivity\n\n");
        markdown.append(outboundConnectivitySummary(reports)).append("\n");

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
            markdown.append("- Registered users listed: ").append(report.systemUsers().size()).append("\n");
            markdown.append("- Latest logged SSH user record: ").append(report.loggedUsers().isEmpty() ? 0 : 1).append("\n");
            markdown.append("- Running services listed: ").append(visibleServices(report).size()).append("\n");
            markdown.append("- Outbound connectivity checks: ").append(report.outboundChecks().size()).append("\n");
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
            appendDiskTable(markdown, report);
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
            if (!report.systemUsers().isEmpty()) {
                markdown.append("Local users and last login (")
                        .append(report.systemUsers().size())
                        .append("):\n\n");
                appendUserTable(markdown, report.systemUsers());
                markdown.append("\n");
            }
            if (!report.loggedUsers().isEmpty()) {
                markdown.append("Latest logged SSH user record:\n\n");
                appendLoggedUserTable(markdown, report.loggedUsers());
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
            if (!report.outboundChecks().isEmpty()) {
                markdown.append("Outbound connectivity checks (")
                        .append(report.outboundChecks().size())
                        .append("):\n\n");
                appendOutboundTable(markdown, report.outboundChecks(), true);
                markdown.append("\n");
            }
            appendRuntimeTimingTable(markdown, report, includeCommandDetails);
            markdown.append("| Check | Source CK | Status | Detail |\n");
            markdown.append("| --- | --- | --- | --- |\n");
            for (F5Check check : report.checks()) {
                if ("runtime_command".equals(check.name()) || "runtime_slowest".equals(check.name())) {
                    continue;
                }
                markdown.append("| ")
                        .append(escape(check.name())).append(" | ")
                        .append(escape(checkSourceIds(check.name()))).append(" | ")
                        .append(statusCell(check.status())).append(" | ")
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
        return value == null ? "" : value.replace("|", "\\|").replace("\r", " ").replace("\n", " ");
    }

    private static String displayLabel(F5Report report) {
        return report.label() == null || report.label().isBlank() ? report.hostname() : report.label();
    }

    private static String checkSourceIds(String checkName) {
        return switch (checkName == null ? "" : checkName) {
            case "ssh_connectivity" -> "SSH";
            case "target_detection" -> "CK01, CK04, CK05, CK06, CK07, CK08";
            case "critical_services" -> "CK17, CK18, CK19, CK22";
            case "external_listening_ports" -> "CK22, CK23, CK24";
            case "load_1m" -> "CK11, CK12";
            case "memory" -> "CK10";
            case "disk" -> "CK13";
            case "vmstat_sample" -> "CK26";
            case "f5_system_performance" -> "CK27";
            case "f5_connection_performance" -> "CK28";
            case "f5_load_history" -> "CK30";
            case "f5_partitions_pools" -> "CK33, CK35";
            case "outbound_connectivity" -> "CK31, CK34";
            case "runtime_total" -> "runtime";
            case "recent_logs" -> "CK25";
            default -> "";
        };
    }

    private static String privilegeSummary(F5Report report) {
        String mode = report.privilegeMode() == null || report.privilegeMode().isBlank() ? "login-user" : report.privilegeMode();
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
        return "<span style=\"display:block;box-sizing:border-box;width:124px;max-width:100%;height:14px;line-height:14px;background:linear-gradient(to right," + color + " 0%," + color + " " + bounded + "%,#e5e7eb " + bounded + "%,#e5e7eb 100%);border:1px solid #9ca3af;text-align:center;font-size:10px;color:#111827;vertical-align:top;overflow:hidden;white-space:nowrap\">" +
                escape(text) + "</span>";
    }

    private static String metricCell(long percent, String detail) {
        if (detail == null || detail.isBlank()) {
            return htmlBar(percent);
        }
        return htmlBar(percent) + "<br><small>" + detail + "</small>";
    }

    private static String metricCell(long percent, String barText, String detail) {
        if (detail == null || detail.isBlank()) {
            return htmlBar(percent, barText);
        }
        return htmlBar(percent, barText) + "<br><small>" + detail + "</small>";
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
        String background = switch (normalized) {
            case "PASS", "OK" -> "#bbf7d0";
            case "FAIL", "FAILED", "ERROR" -> "#fecaca";
            case "UNKNOWN", "WARN", "WARNING" -> "#fed7aa";
            default -> "#e2e8f0";
        };
        return backgroundBadge(status, background);
    }

    private static String outboundStatusCell(String status) {
        return statusCell(status);
    }

    private static String backgroundBadge(String value, String background) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return "<span style=\"display:inline-block;background:" + background
                + ";color:#111827;border:1px solid #94a3b8;font-weight:700;padding:2px 6px;border-radius:4px\">"
                + escape(value)
                + "</span>";
    }

    private static String certValidityCell(String value) {
        return certValidityCell(value, false);
    }

    private static String certValidityCell(String value, boolean blinkExpiring) {
        String normalized = value == null ? "" : value.strip();
        if (normalized.isBlank()) {
            return "";
        }
        String upper = normalized.toUpperCase();
        String color = "#15803d";
        String background = "#dcfce7";
        String border = "#86efac";
        boolean blink = false;
        if (upper.startsWith("NO CERTIFICATE") || upper.startsWith("CERT OBJECT NOT LISTED") || upper.startsWith("VALIDITY UNKNOWN")) {
            color = "#475569";
            background = "#f1f5f9";
            border = "#cbd5e1";
        } else if (upper.startsWith("EXPIRED")) {
            color = "#991b1b";
            background = "#fee2e2";
            border = "#fca5a5";
            blink = true;
        } else if (upper.startsWith("EXPIRING")) {
            int days = firstInteger(normalized);
            if (days < 30) {
                color = "#991b1b";
                background = "#fee2e2";
                border = "#fca5a5";
                blink = true;
            } else if (days < 90) {
                color = "#9a3412";
                background = "#ffedd5";
                border = "#fdba74";
                blink = blinkExpiring;
            }
        }
        String badgeText = certificateBadgeText(normalized);
        String badge = "<span style=\"display:inline-block;border:1px solid " + border
                + ";background:" + background
                + ";color:" + color
                + ";font-weight:700;padding:2px 6px;border-radius:4px"
                + (blink ? ";animation:cert-blink 1s step-end infinite" : "")
                + "\">" + escape(badgeText) + "</span>";
        if (!badgeText.equals(normalized)) {
            return "<details><summary style=\"cursor:pointer\">" + badge + "</summary>"
                    + "<div style=\"max-height:96px;overflow:auto;border:1px solid " + border
                    + ";background:" + background
                    + ";color:#111827;padding:4px 6px;border-radius:4px;margin-top:3px;max-width:760px\">"
                    + escape(normalized)
                    + "</div></details>";
        }
        return badge;
    }

    private static String certificateBadgeText(String value) {
        int separator = value == null ? -1 : value.indexOf(';');
        return separator > 0 ? value.substring(0, separator).strip() : value;
    }

    private static int firstInteger(String value) {
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("(\\d+)").matcher(value == null ? "" : value);
        return matcher.find() ? intValue(matcher.group(1)) : Integer.MAX_VALUE;
    }

    private static String miniMetric(String label, long percent, double load) {
        return miniBar(percent, label + " " + format(load));
    }

    private static String miniBar(long percent, String text) {
        long bounded = Math.max(0, Math.min(100, percent));
        String color = bounded >= 80 ? "#dc2626" : bounded >= 60 ? "#f59e0b" : "#16a34a";
        return "<span style=\"display:block;box-sizing:border-box;width:76px;max-width:100%;height:12px;line-height:12px;background:linear-gradient(to right," + color + " 0%," + color + " " + bounded + "%,#e5e7eb " + bounded + "%,#e5e7eb 100%);border:1px solid #9ca3af;text-align:center;font-size:9px;color:#111827;vertical-align:top;overflow:hidden;white-space:nowrap\">" +
                escape(text) + "</span>";
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
        List<String[]> rows = diskRowsByUsage(report);
        List<String> top = rows.stream()
                .limit(3)
                .map(MarkdownReportWriter::compactDiskMount)
                .toList();
        String header = "<strong>" + rows.size() + " mounts</strong>";
        if (rows.size() <= 3) {
            return header + "<br>" + String.join("<br>", top);
        }
        return header + "<br>" + String.join("<br>", top)
                + "<br><details><summary>+" + (rows.size() - 3) + " more</summary>"
                + String.join("<br>", rows.subList(3, rows.size()).stream()
                        .map(MarkdownReportWriter::compactDiskMount)
                        .toList())
                + "</details>";
    }

    private static String compactDiskMount(String[] parts) {
        long usedPercent = longValue(diskUsedPercent(parts));
        return "<small>" + escape(part(parts, 0)) + "</small><br>"
                + htmlBar(usedPercent, "used " + usedPercent + "%")
                + "<br><small>" + escape(part(parts, 2)) + " used / "
                + escape(part(parts, 1)) + " total GB, "
                + escape(diskAvailable(parts)) + " avail</small>";
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
        return "<small>" + escape(processCommand(parts)) + "</small><br>" + htmlBar(Math.round(cpu), String.format("%.1f%%", cpu));
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
        double gb = rssGbValue(part(parts, 3), totalGb);
        long width = totalGb <= 0 ? 0 : Math.round(gb * 100.0 / totalGb);
        double sharedGb = processSharedGb(parts);
        return "<small>" + escape(processCommand(parts)) + "</small><br>"
                + htmlBar(width, String.format("RSS %.3f GB", gb))
                + "<br><small>shared " + format(sharedGb) + " GB</small>";
    }

    private static double rssGbValue(String value, double totalGb) {
        try {
            double parsed = Double.parseDouble(value);
            return totalGb > 0 && parsed > totalGb * 1.5 ? parsed / 1024.0 : parsed;
        } catch (NumberFormatException exception) {
            return 0;
        }
    }

    private static String processCommand(String[] parts) {
        return parts.length >= 6 ? part(parts, 5) : part(parts, 4);
    }

    private static double processSharedGb(String[] parts) {
        return parts.length >= 6 ? rssGbValue(part(parts, 4), 0) : 0;
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

    private static String userSummary(F5Report report) {
        if (report.systemUsers().isEmpty()) {
            return "none";
        }
        List<String> users = report.systemUsers().stream()
                .map(MarkdownReportWriter::compactUser)
                .toList();
        String header = "<strong>" + users.size() + " users</strong>";
        List<String> top = users.stream().limit(5).toList();
        if (users.size() <= 5) {
            return header + "<br>" + String.join("<br>", top);
        }
        return header + "<br>" + String.join("<br>", top)
                + "<br><details><summary>+" + (users.size() - 5) + " more</summary>"
                + String.join("<br>", users.subList(5, users.size()))
                + "</details>";
    }

    private static String loggedUserSummary(F5Report report) {
        if (report.loggedUsers().isEmpty()) {
            return "none";
        }
        return compactLoggedUser(report.loggedUsers().get(0));
    }

    private static String compactUser(String user) {
        String[] parts = user.split("\\|", -1);
        return "<small>" + escape(part(parts, 0)) + " uid " + escape(part(parts, 1))
                + "<br>last: " + escape(shortLastLogin(part(parts, 3))) + "</small>";
    }

    private static String compactLoggedUser(String user) {
        String[] parts = user.split("\\|", -1);
        return "<small>" + escape(part(parts, 0)) + " " + escape(part(parts, 3))
                + "<br>" + escape(shortLastLogin(part(parts, 2))) + "</small>";
    }

    private static String shortLastLogin(String value) {
        String normalized = value == null || value.isBlank() ? "unknown" : value.strip();
        if (normalized.equalsIgnoreCase("Never logged in")) {
            return "never";
        }
        return normalized;
    }

    private static String f5LoadHistorySummary(List<F5Report> reports) {
        List<F5Report> f5Reports = reports.stream()
                .filter(report -> "f5".equalsIgnoreCase(report.targetType()))
                .filter(report -> !report.f5LoadHistory().isEmpty())
                .sorted(Comparator.comparing(F5Report::hostname))
                .toList();
        if (f5Reports.isEmpty()) {
            return "No F5 historical CPU, traffic, or connection time-series samples were collected. This requires local BIG-IP RRD files and `rrdtool` on the target.\n";
        }

        StringBuilder markdown = new StringBuilder();
        markdown.append("Read-only CPU, traffic, and connection-count RRD samples from the last 48 hours of BIG-IP local history. Raw entries are the unmerged RRD rows from the JSON artifact; aggregated points are per-timestamp metric values after grouping related RRD data sources. Each compact line graph draws up to ").append(HISTORY_GRAPH_POINTS).append(" evenly sampled points across the collected range and shows UTC hour labels every 6 hours positioned by actual elapsed time on the X axis. The row-max trend uses 0-100% of the highest value visible in that row so the shape is easy to compare. The fixed-scale trend uses actual 0-100% load: CPU/load counters above 100 are converted from milli-percent style values, traffic counters are throughput in bits/sec and are plotted against a 1 Gbps reference when they are not already percentages, and connection counters are plotted against the highest visible connection count.\n\n");
        markdown.append("| Label | Host | Metric | Raw entries | Aggregated points | Graph points | Trend (row max) | Trend (0-100%) |\n");
        markdown.append("| --- | --- | --- | ---: | ---: | ---: | --- | --- |\n");
        for (F5Report report : f5Reports) {
            Map<String, HistorySeries> series = historyCategorySeries(report.f5LoadHistory());
            for (Map.Entry<String, HistorySeries> entry : series.entrySet()) {
                HistorySeries history = entry.getValue();
                List<HistorySample> samples = history.samples();
                if (samples.isEmpty()) {
                    continue;
                }
                markdown.append("| ")
                        .append(escape(displayLabel(report))).append(" | ")
                        .append(escape(report.hostname())).append(" | ")
                        .append(escape(shortSourceName(entry.getKey()))).append(" | ")
                        .append(history.rawEntries()).append(" | ")
                        .append(samples.size()).append(" | ")
                        .append(graphSamples(samples).size()).append(" | ")
                        .append(historyGraph(entry.getKey(), samples, true)).append(" | ")
                        .append(historyGraph(entry.getKey(), samples, false)).append(" |\n");
            }
        }
        return markdown.toString();
    }

    private static String f5PartitionPoolSummary(List<F5Report> reports) {
        List<F5Report> f5Reports = reports.stream()
                .filter(report -> "f5".equalsIgnoreCase(report.targetType()))
                .filter(report -> !report.f5PartitionsPools().isEmpty())
                .sorted(Comparator.comparing(F5Report::hostname))
                .toList();
        if (f5Reports.isEmpty()) {
            return "No F5 partition or pool inventory was collected.\n";
        }
        StringBuilder markdown = new StringBuilder();
        markdown.append("| Label | Host | Partition | Type | Pool/VIP | VIP destination | Protocol | Inbound VIP stats | Inbound VIP client SSL profile | Inbound VIP cert | Inbound VIP cert validity | Inbound VIP chain | Partition traffic | Pool members | Remote pool member checks | Pool outbound server SSL profile | F5 outbound client cert | F5 outbound client cert validity | F5 outbound client chain | Detail |\n");
        markdown.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
        for (F5Report report : f5Reports) {
            for (String row : summaryPartitionPoolRows(report.f5PartitionsPools())) {
                PartitionPoolRow parts = partitionPoolRow(row);
                markdown.append("| ")
                        .append(escape(displayLabel(report))).append(" | ")
                        .append(escape(report.hostname())).append(" | ")
                        .append(escape(parts.partition())).append(" | ")
                        .append(escape(parts.type())).append(" | ")
                        .append(poolVipCell(parts)).append(" | ")
                        .append(escape(parts.destination())).append(" | ")
                        .append(escape(parts.protocol())).append(" | ")
                        .append(statsCell(parts.vipStats())).append(" | ")
                        .append(escape(parts.sslProfile())).append(" | ")
                        .append(escape(parts.certificate())).append(" | ")
                        .append(certValidityCell(parts.certValidity())).append(" | ")
                        .append(escape(parts.chain())).append(" | ")
                        .append(statsCell(parts.partitionTraffic())).append(" | ")
                        .append(parts.members()).append(" | ")
                        .append(poolMemberChecks(report, parts)).append(" | ")
                        .append(escape(parts.serverSslProfile())).append(" | ")
                        .append(escape(parts.serverCertificate())).append(" | ")
                        .append(certValidityCell(parts.serverCertValidity())).append(" | ")
                        .append(escape(parts.serverChain())).append(" | ")
                        .append(escape(parts.detail())).append(" |\n");
            }
        }
        return markdown.toString();
    }

    private static void appendPartitionPoolTable(StringBuilder markdown, List<String> rows, List<String> outboundChecks, boolean includeDetail) {
        List<String> visibleRows = visiblePartitionPoolRows(rows);
        markdown.append("| Partition | Type | Pool/VIP | VIP destination | Protocol | Inbound VIP stats | Inbound VIP client SSL profile | Inbound VIP cert | Inbound VIP cert validity | Inbound VIP chain | Partition traffic | Pool members | Remote pool member checks | Pool outbound server SSL profile | F5 outbound client cert | F5 outbound client cert validity | F5 outbound client chain | Detail |\n");
        markdown.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
        for (String row : visibleRows.stream().limit(10).toList()) {
            appendPartitionPoolRow(markdown, row, outboundChecks, includeDetail);
        }
        markdown.append("\n");
        if (visibleRows.size() > 10) {
            markdown.append("<details><summary>+")
                    .append(visibleRows.size() - 10)
                    .append(" more partition/pool rows</summary>\n\n");
            markdown.append("| Partition | Type | Pool/VIP | VIP destination | Protocol | Inbound VIP stats | Inbound VIP client SSL profile | Inbound VIP cert | Inbound VIP cert validity | Inbound VIP chain | Partition traffic | Pool members | Remote pool member checks | Pool outbound server SSL profile | F5 outbound client cert | F5 outbound client cert validity | F5 outbound client chain | Detail |\n");
            markdown.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
            for (String row : visibleRows.subList(10, visibleRows.size())) {
                appendPartitionPoolRow(markdown, row, outboundChecks, includeDetail);
            }
            markdown.append("\n</details>\n\n");
        }
    }

    private static List<String> visiblePartitionPoolRows(List<String> rows) {
        return rows.stream()
                .filter(row -> {
                    PartitionPoolRow parts = partitionPoolRow(row);
                    if ("pool".equals(parts.type())
                            && "(no pools)".equals(parts.name())
                            && parts.members().isBlank()
                            && parts.detail().isBlank()) {
                        return false;
                    }
                    if (!"server-ssl".equals(parts.type())) {
                        return true;
                    }
                    return !"Common".equals(parts.partition()) && !parts.serverCertificate().isBlank();
                })
                .toList();
    }

    private static List<String> summaryPartitionPoolRows(List<String> rows) {
        return visiblePartitionPoolRows(rows).stream()
                .filter(row -> "pool+vip".equals(partitionPoolRow(row).type()))
                .toList();
    }

    private static void appendPartitionPoolRow(StringBuilder markdown, String row, List<String> outboundChecks, boolean includeDetail) {
        PartitionPoolRow parts = partitionPoolRow(row);
        markdown.append("| ")
                .append(escape(parts.partition())).append(" | ")
                .append(escape(parts.type())).append(" | ")
                .append(poolVipCell(parts)).append(" | ")
                .append(escape(parts.destination())).append(" | ")
                .append(escape(parts.protocol())).append(" | ")
                .append(statsCell(parts.vipStats())).append(" | ")
                .append(escape(parts.sslProfile())).append(" | ")
                .append(escape(parts.certificate())).append(" | ")
                .append(certValidityCell(parts.certValidity())).append(" | ")
                .append(escape(parts.chain())).append(" | ")
                .append(statsCell(parts.partitionTraffic())).append(" | ")
                .append(parts.members()).append(" | ")
                .append(poolMemberChecks(outboundChecks, parts)).append(" | ")
                .append(escape(parts.serverSslProfile())).append(" | ")
                .append(escape(parts.serverCertificate())).append(" | ")
                .append(certValidityCell(parts.serverCertValidity())).append(" | ")
                .append(escape(parts.serverChain())).append(" | ")
                .append(includeDetail ? escape(parts.detail()) : "").append(" |\n");
    }

    private static String statsCell(String value) {
        if (value == null || value.isBlank()) {
            return "<small style=\"color:#64748b\">not reported by tmsh show ltm virtual</small>";
        }
        return value;
    }

    private static String poolVipCell(PartitionPoolRow parts) {
        String role = switch (parts.type()) {
            case "pool+vip" -> "F5 pool with VIP";
            case "pool" -> "F5 pool";
            case "server-ssl" -> "F5 server-side SSL profile";
            default -> "F5 " + parts.type();
        };
        StringBuilder cell = new StringBuilder();
        cell.append("<span style=\"display:inline-block;color:#475569;font-size:11px;font-weight:700\">")
                .append(htmlEscape(role))
                .append("</span><br>")
                .append(escape(parts.name()));
        if (!parts.destination().isBlank()) {
            cell.append("<br><small>VIP ").append(escape(parts.destination())).append("</small>");
        }
        return cell.toString();
    }

    private static PartitionPoolRow partitionPoolRow(String row) {
        String[] parts = row.split("\\|", -1);
        if (parts.length >= 17) {
            return new PartitionPoolRow(
                    part(parts, 0),
                    part(parts, 1),
                    part(parts, 2),
                    part(parts, 3),
                    part(parts, 4),
                    escape(part(parts, 5)).replace("&lt;br&gt;", "<br>"),
                    escape(part(parts, 6)).replace("&lt;br&gt;", "<br>"),
                    escape(part(parts, 7)).replace("&lt;br&gt;", "<br>"),
                    part(parts, 8),
                    part(parts, 9),
                    part(parts, 10),
                    part(parts, 11),
                    part(parts, 12),
                    part(parts, 13),
                    part(parts, 14),
                    part(parts, 15),
                    part(parts, 16)
            );
        }
        if (parts.length >= 13) {
            return new PartitionPoolRow(
                    part(parts, 0),
                    part(parts, 1),
                    part(parts, 2),
                    part(parts, 3),
                    part(parts, 4),
                    escape(part(parts, 5)).replace("&lt;br&gt;", "<br>"),
                    escape(part(parts, 6)).replace("&lt;br&gt;", "<br>"),
                    escape(part(parts, 7)).replace("&lt;br&gt;", "<br>"),
                    part(parts, 8),
                    part(parts, 9),
                    part(parts, 10),
                    part(parts, 11),
                    "",
                    "",
                    "",
                    "",
                    part(parts, 12)
            );
        }
        if (parts.length >= 12) {
            return new PartitionPoolRow(
                    part(parts, 0),
                    part(parts, 1),
                    part(parts, 2),
                    part(parts, 3),
                    part(parts, 4),
                    "",
                    escape(part(parts, 5)).replace("&lt;br&gt;", "<br>"),
                    escape(part(parts, 6)).replace("&lt;br&gt;", "<br>"),
                    part(parts, 7),
                    part(parts, 8),
                    part(parts, 9),
                    part(parts, 10),
                    part(parts, 11),
                    "",
                    "",
                    "",
                    ""
            );
        }
        if (parts.length >= 11) {
            return new PartitionPoolRow(part(parts, 0), part(parts, 1), part(parts, 2), part(parts, 3), part(parts, 4), "", escape(part(parts, 5)).replace("&lt;br&gt;", "<br>"), "", part(parts, 6), part(parts, 7), part(parts, 8), part(parts, 9), "", "", "", "", part(parts, 10));
        }
        return new PartitionPoolRow(part(parts, 0), "pool", part(parts, 1), "", "", "", "", "", "", "", "", "", "", "", "", "", part(parts, 2));
    }

    private static String outboundConnectivitySummary(List<F5Report> reports) {
        List<F5Report> withChecks = reports.stream()
                .filter(report -> !report.outboundChecks().isEmpty())
                .sorted(Comparator.comparing(F5Report::hostname))
                .toList();
        if (withChecks.isEmpty()) {
            return "No outbound connectivity checks were configured or collected. Add `<effective-config>/vm_outbound_checks.csv` to enable this table.\n";
        }

        List<OutboundSummaryRow> rows = new ArrayList<>();
        for (F5Report report : withChecks) {
            for (String rawCheck : report.outboundChecks()) {
                OutboundResult check = outboundResult(rawCheck);
                rows.add(new OutboundSummaryRow(report, check));
            }
        }
        rows.sort(Comparator
                .comparing(OutboundSummaryRow::checkKey)
                .thenComparing(row -> row.report().hostname()));

        StringBuilder markdown = new StringBuilder();
        markdown.append("| Check | Host | Port | Protocol | VM label | VM host | Resolved IP | Status | Elapsed | Cert expires | Detail |\n");
        markdown.append("| --- | --- | ---: | --- | --- | --- | --- | --- | ---: | --- | --- |\n");
        for (OutboundSummaryRow row : rows) {
            OutboundResult check = row.result();
            F5Report report = row.report();
            markdown.append("| ")
                    .append(escape(check.name())).append(" | ")
                    .append(escape(check.host())).append(" | ")
                    .append(escape(check.port())).append(" | ")
                    .append(escape(check.protocol())).append(" | ")
                    .append(escape(displayLabel(report))).append(" | ")
                    .append(escape(report.hostname())).append(" | ")
                    .append(escape(check.resolvedIp())).append(" | ")
                    .append(outboundStatusCell(check.status())).append(" | ")
                    .append(elapsedCell(check.detail())).append(" | ")
                    .append(escape(markerValue(check.detail(), "TLS_CERT_NOT_AFTER"))).append(" | ")
                    .append(outboundDetailCell(check, true)).append(" |\n");
        }
        return markdown.toString();
    }

    private static String shortDetail(String detail) {
        if (detail == null || detail.isBlank()) {
            return "";
        }
        return detail.strip();
    }

    private static void appendOutboundTable(StringBuilder markdown, List<String> checks, boolean includeDetail) {
        markdown.append("| Check | Host | Resolved IP | Port | Protocol | Status | Elapsed | Cert expires | Detail |\n");
        markdown.append("| --- | --- | --- | ---: | --- | --- | ---: | --- | --- |\n");
        for (String rawCheck : checks) {
            OutboundResult check = outboundResult(rawCheck);
            markdown.append("| ")
                    .append(escape(check.name())).append(" | ")
                    .append(escape(check.host())).append(" | ")
                    .append(escape(check.resolvedIp())).append(" | ")
                    .append(escape(check.port())).append(" | ")
                    .append(escape(check.protocol())).append(" | ")
                    .append(outboundStatusCell(check.status())).append(" | ")
                    .append(elapsedCell(check.detail())).append(" | ")
                    .append(escape(markerValue(check.detail(), "TLS_CERT_NOT_AFTER"))).append(" | ")
                    .append(includeDetail ? outboundDetailCell(check, true) : "").append(" |\n");
        }
    }

    private static String outboundDetailCell(OutboundResult check, boolean full) {
        String detail = full ? check.detail() : shortDetail(check.detail());
        if (!"TLS".equalsIgnoreCase(check.protocol())) {
            return escape(detail);
        }
        List<String> values = new ArrayList<>(remoteTlsCertificateSummary(check.detail()));
        if (!detail.isBlank()) {
            values.add(escape(detail));
        }
        return String.join("<br>", values);
    }

    private static List<String> remoteTlsCertificateSummary(String detail) {
        List<String> values = new ArrayList<>();
        String validity = markerValue(detail, "TLS_CERT_VALIDITY");
        if (!validity.isBlank()) {
            values.add(certValidityCell(validity, true));
        }
        String subject = markerValue(detail, "TLS_CERT_SUBJECT");
        String cn = markerValue(detail, "TLS_CERT_CN");
        String issuer = markerValue(detail, "TLS_CERT_ISSUER");
        String notBefore = markerValue(detail, "TLS_CERT_NOT_BEFORE");
        String notAfter = markerValue(detail, "TLS_CERT_NOT_AFTER");
        String fingerprint = markerValue(detail, "TLS_CERT_FINGERPRINT");
        List<String> leafDetails = new ArrayList<>();
        if (!cn.isBlank()) {
            leafDetails.add("CN " + cn);
        }
        if (!subject.isBlank()) {
            leafDetails.add("subject " + subject);
        }
        if (!issuer.isBlank()) {
            leafDetails.add("issuer " + issuer);
        }
        if (!notBefore.isBlank()) {
            leafDetails.add("valid from " + notBefore);
        }
        if (!notAfter.isBlank()) {
            leafDetails.add("expires " + notAfter);
        }
        if (!fingerprint.isBlank()) {
            leafDetails.add("fingerprint " + fingerprint);
        }
        List<String> detailBlocks = new ArrayList<>();
        if (!leafDetails.isEmpty()) {
            detailBlocks.add("<small>" + escape(String.join("; ", leafDetails)) + "</small>");
        }

        String chainCount = markerValue(detail, "TLS_CHAIN_CERTS");
        int count = (int) longValue(chainCount);
        if (count > 1) {
            List<String> chainDetails = new ArrayList<>();
            for (int index = 2; index <= count; index++) {
                List<String> certDetails = new ArrayList<>();
                String chainSubject = markerValue(detail, "TLS_CHAIN_" + index + "_SUBJECT");
                String chainIssuer = markerValue(detail, "TLS_CHAIN_" + index + "_ISSUER");
                String chainNotBefore = markerValue(detail, "TLS_CHAIN_" + index + "_NOT_BEFORE");
                String chainNotAfter = markerValue(detail, "TLS_CHAIN_" + index + "_NOT_AFTER");
                String chainFingerprint = markerValue(detail, "TLS_CHAIN_" + index + "_FINGERPRINT");
                if (!chainSubject.isBlank()) {
                    certDetails.add("subject " + chainSubject);
                }
                if (!chainIssuer.isBlank()) {
                    certDetails.add("issuer " + chainIssuer);
                }
                if (!chainNotBefore.isBlank()) {
                    certDetails.add("valid from " + chainNotBefore);
                }
                if (!chainNotAfter.isBlank()) {
                    certDetails.add("expires " + chainNotAfter);
                }
                if (!chainFingerprint.isBlank()) {
                    certDetails.add("fingerprint " + chainFingerprint);
                }
                chainDetails.add("CA #" + (index - 1) + (certDetails.isEmpty() ? " details not returned" : ": " + String.join("; ", certDetails)));
            }
            detailBlocks.add("<small>Presented CA chain (" + (count - 1) + "): " + escape(String.join("<br>", chainDetails)) + "</small>");
        } else if ("1".equals(chainCount)) {
            detailBlocks.add("<small>Presented CA chain: none returned by peer</small>");
        } else if (!chainCount.isBlank()) {
            detailBlocks.add("<small>Presented chain certs " + escape(chainCount) + "</small>");
        }
        if (!detailBlocks.isEmpty()) {
            values.add(collapsibleCertDetailBlock(validity, "remote TLS certificate details", String.join("<br>", detailBlocks)));
        }
        return values;
    }

    private static String collapsibleCertDetailBlock(String validity, String summary, String content) {
        String upper = validity == null ? "" : validity.toUpperCase();
        String background = "#f8fafc";
        String border = "#cbd5e1";
        if (upper.startsWith("EXPIRED")) {
            background = "#fee2e2";
            border = "#fca5a5";
        } else if (upper.startsWith("EXPIRING")) {
            background = "#ffedd5";
            border = "#fdba74";
        } else if (upper.startsWith("VALID")) {
            background = "#dcfce7";
            border = "#86efac";
        }
        return "<details><summary style=\"cursor:pointer\"><small>" + escape(summary) + "</small></summary>"
                + "<div style=\"max-height:110px;overflow:auto;border:1px solid " + border
                + ";background:" + background
                + ";color:#111827;padding:4px 6px;border-radius:4px;max-width:760px;margin-top:3px\">"
                + content
                + "</div></details>";
    }

    private static String elapsedCell(String detail) {
        String elapsed = markerValue(detail, "ELAPSED_MS");
        if (elapsed.isBlank()) {
            return "";
        }
        long millis = longValue(elapsed);
        String text = elapsed + " ms";
        return millis > 1000 ? backgroundBadge(text, "#fed7aa") : escape(text);
    }

    private static String timingCell(String elapsedMillis) {
        if (elapsedMillis == null || elapsedMillis.isBlank()) {
            return "";
        }
        String text = elapsedMillis + " ms";
        return longValue(elapsedMillis) > 1000 ? backgroundBadge(text, "#fed7aa") : escape(text);
    }

    private static void appendRuntimeTimingTable(StringBuilder markdown, F5Report report, boolean includeCommandDetails) {
        List<F5Check> timingRows = report.checks().stream()
                .filter(check -> "runtime_command".equals(check.name()))
                .sorted((left, right) -> Long.compare(runtimeMillis(right.detail()), runtimeMillis(left.detail())))
                .toList();
        if (timingRows.isEmpty()) {
            return;
        }
        markdown.append("Runtime timings (slowest command attempts):\n\n");
        if (includeCommandDetails) {
            markdown.append("| Command ID | Description | Arguments | Elapsed | Exit | Command |\n");
            markdown.append("| --- | --- | --- | ---: | ---: | --- |\n");
        } else {
            markdown.append("| Command ID | Description | Arguments | Elapsed | Exit |\n");
            markdown.append("| --- | --- | --- | ---: | ---: |\n");
        }
        Map<String, String> descriptions = commandDescriptions();
        for (F5Check check : timingRows) {
            String[] parts = check.detail().split("\\|", 4);
            String id = part(parts, 0);
            String fallbackDescription = descriptions.getOrDefault(id, "");
            RuntimeTimingDetail detail = runtimeTimingDetail(part(parts, 3), fallbackDescription);
            markdown.append("| ")
                    .append(escape(id)).append(" | ")
                    .append(escape(detail.description())).append(" | ")
                    .append(escape(commandArguments(detail.command()))).append(" | ")
                    .append(timingCell(part(parts, 1))).append(" | ")
                    .append(escape(part(parts, 2)));
            if (includeCommandDetails) {
                markdown.append(" | ").append(escape(detail.command()));
            }
            markdown.append(" |\n");
        }
        markdown.append("\n");
    }

    private static String commandArguments(String command) {
        if (command == null || command.isBlank()) {
            return "";
        }
        List<String> values = new ArrayList<>();
        for (String key : List.of("check_name", "host", "port", "protocol", "timeout_seconds")) {
            String value = shellAssignment(command, key);
            if (!value.isBlank()) {
                values.add(key + "=" + value);
            }
        }
        return String.join("; ", values);
    }

    private static String shellAssignment(String command, String key) {
        if ("protocol".equals(key)) {
            java.util.regex.Matcher protocolMatcher = java.util.regex.Pattern
                    .compile("protocol=\\$\\(printf '%s' '([^']+)'")
                    .matcher(command == null ? "" : command);
            if (protocolMatcher.find()) {
                return protocolMatcher.group(1);
            }
        }
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("(?<![A-Za-z0-9_])" + java.util.regex.Pattern.quote(key) + "=('([^']*)'|\"([^\"]*)\"|([^\\s;]+))")
                .matcher(command == null ? "" : command);
        if (!matcher.find()) {
            return "";
        }
        for (int i = 2; i <= 4; i++) {
            String value = matcher.group(i);
            if (value != null) {
                return value;
            }
        }
        return "";
    }

    private static RuntimeTimingDetail runtimeTimingDetail(String rawDetail, String fallbackDescription) {
        String detail = rawDetail == null ? "" : rawDetail;
        if (!fallbackDescription.isBlank() && detail.startsWith(fallbackDescription + "|")) {
            return new RuntimeTimingDetail(fallbackDescription, detail.substring(fallbackDescription.length() + 1));
        }
        return new RuntimeTimingDetail(fallbackDescription, detail);
    }

    private static Map<String, String> commandDescriptions() {
        Map<String, String> descriptions = new LinkedHashMap<>();
        for (Path path : List.of(
                Path.of("scripts", "validation-common.sh"),
                Path.of("scripts", "validation-commands-f5.sh"),
                Path.of("scripts", "validation-commands-vm.sh"))) {
            if (!Files.isRegularFile(path)) {
                continue;
            }
            try {
                for (String line : Files.readAllLines(path)) {
                    java.util.regex.Matcher matcher = java.util.regex.Pattern
                            .compile("^##(CK\\d{2,3})(?:\\s+#\\s*(.*))?\\s*$")
                            .matcher(line.strip());
                    if (matcher.matches()) {
                        descriptions.put(matcher.group(1), matcher.group(2) == null ? "" : matcher.group(2).strip());
                    }
                }
            } catch (IOException ignored) {
            }
        }
        return descriptions;
    }

    private record RuntimeTimingDetail(String description, String command) {
    }

    private static long runtimeMillis(String detail) {
        String[] parts = detail.split("\\|", 4);
        try {
            return Long.parseLong(part(parts, 1));
        } catch (RuntimeException exception) {
            return 0;
        }
    }

    private static OutboundResult outboundResult(String rawCheck) {
        String[] parts = rawCheck.split("\\|", 7);
        if (parts.length >= 7) {
            return new OutboundResult(
                    part(parts, 0),
                    part(parts, 1),
                    part(parts, 2),
                    part(parts, 3),
                    part(parts, 4),
                    part(parts, 5),
                    part(parts, 6)
            );
        }
        String[] oldParts = rawCheck.split("\\|", 6);
        return new OutboundResult(
                part(oldParts, 0),
                part(oldParts, 1),
                part(oldParts, 1),
                part(oldParts, 2),
                part(oldParts, 3),
                part(oldParts, 4),
                part(oldParts, 5)
        );
    }

    private static String poolMemberChecks(F5Report report, PartitionPoolRow parts) {
        return poolMemberChecks(report.outboundChecks(), parts);
    }

    private static String poolMemberChecks(List<String> outboundChecks, PartitionPoolRow parts) {
        if (outboundChecks.isEmpty() || parts.partition().isBlank() || parts.name().isBlank()) {
            return "";
        }
        String prefix = "pool:" + parts.partition() + "/" + parts.name() + ":";
        List<String> values = new ArrayList<>();
        for (String rawCheck : outboundChecks) {
            OutboundResult check = outboundResult(rawCheck);
            if (!check.name().startsWith(prefix)) {
                continue;
            }
            StringBuilder cell = new StringBuilder();
            cell.append("<small>")
                    .append(escape(check.host())).append(":").append(escape(check.port()))
                    .append(" ").append(escape(check.protocol()))
                    .append(" ").append(outboundStatusCell(check.status())).append("</small>");
            if ("TLS".equalsIgnoreCase(check.protocol())) {
                List<String> tlsSummary = remoteTlsCertificateSummary(check.detail());
                if (!tlsSummary.isEmpty()) {
                    cell.append("<br><small>Remote TLS cert</small><br>").append(String.join("<br>", tlsSummary));
                }
            }
            values.add(cell.toString());
        }
        return values.isEmpty() ? "" : String.join("<br>", values);
    }

    private static String markerValue(String value, String key) {
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile(java.util.regex.Pattern.quote(key) + "=([^;\\n]+?)(?=\\s+[A-Z0-9_]+=|;|$)")
                .matcher(value == null ? "" : value);
        return matcher.find() ? matcher.group(1).strip() : "";
    }

    private static Map<String, HistorySeries> historyCategorySeries(List<String> rawSamples) {
        Map<String, Map<Long, Double>> grouped = new LinkedHashMap<>();
        Map<String, Integer> rawCounts = new LinkedHashMap<>();
        for (String raw : rawSamples) {
            String[] parts = raw.split("\\|", -1);
            if (parts.length < 3) {
                continue;
            }
            try {
                String source = part(parts, 0).isBlank() ? "unknown RRD source" : part(parts, 0);
                String category = historyCategory(source);
                if (category.isBlank()) {
                    continue;
                }
                long timestamp = Long.parseLong(part(parts, 1));
                double value = Double.parseDouble(part(parts, 2));
                rawCounts.merge(category, 1, Integer::sum);
                grouped.computeIfAbsent(category, ignored -> new LinkedHashMap<>())
                        .merge(timestamp, value, Double::sum);
            } catch (NumberFormatException ignored) {
            }
        }
        Map<String, HistorySeries> series = new LinkedHashMap<>();
        for (Map.Entry<String, Map<Long, Double>> entry : grouped.entrySet()) {
            List<HistorySample> samples = entry.getValue().entrySet().stream()
                    .map(sample -> new HistorySample(sample.getKey(), sample.getValue()))
                    .sorted(Comparator.comparingLong(HistorySample::epochSecond))
                    .toList();
            series.put(entry.getKey(), new HistorySeries(rawCounts.getOrDefault(entry.getKey(), samples.size()), samples));
        }
        return series;
    }

    private static String historyCategory(String source) {
        String lower = source.toLowerCase();
        if (lower.contains("cpu") || lower.contains("load")) {
            return "CPU";
        }
        if (lower.contains("throughput") || lower.contains("traffic") || lower.contains("bwgain")) {
            return "Traffic";
        }
        if (lower.contains("connection")) {
            return "Connections";
        }
        return "";
    }

    private static String historyRange(List<HistorySample> samples) {
        HistorySample first = samples.get(0);
        HistorySample last = samples.get(samples.size() - 1);
        return HISTORY_TIME.format(Instant.ofEpochSecond(first.epochSecond())) + " to "
                + HISTORY_TIME.format(Instant.ofEpochSecond(last.epochSecond()));
    }

    private static String historyGraph(String metric, List<HistorySample> samples, boolean scaleToRowMax) {
        List<HistorySample> plotted = graphSamples(samples);
        double max = plotted.stream().mapToDouble(sample -> historyScaleValue(metric, sample.value())).max().orElse(0);
        double min = plotted.stream().mapToDouble(sample -> historyScaleValue(metric, sample.value())).min().orElse(0);
        double axisMax = scaleToRowMax ? max : fixedAxisMax(metric, max);
        if (axisMax <= 0) {
            axisMax = max;
        }
        HistoryDisplayUnit displayUnit = historyDisplayUnit(metric, axisMax);
        int graphWidth = Math.max(390, plotted.size() * HISTORY_GRAPH_STEP_PX);
        int svgWidth = graphWidth + HISTORY_GRAPH_LABEL_WIDTH_PX;
        long start = plotted.get(0).epochSecond();
        long end = plotted.get(plotted.size() - 1).epochSecond();
        StringBuilder html = new StringBuilder();
        html.append("<div style=\"display:inline-block;border:1px solid #cbd5e1;background:#f8fafc;padding:5px;min-width:")
                .append(svgWidth).append("px\">");
        html.append("<div style=\"display:flex;justify-content:space-between;gap:12px;font-size:10px;color:#475569;margin-bottom:3px\">")
                .append("<span>start ").append(escape(HISTORY_TIME.format(Instant.ofEpochSecond(plotted.get(0).epochSecond())))).append("</span>")
                .append("<span>end ").append(escape(HISTORY_TIME.format(Instant.ofEpochSecond(plotted.get(plotted.size() - 1).epochSecond())))).append("</span>")
                .append("</div>");
        if (scaleToRowMax) {
            html.append("<div style=\"font-size:10px;color:#475569;margin-bottom:3px\">Y axis: 0 to ")
                    .append(escape(formatHistoryDisplayValue(metric, axisMax, displayUnit)))
                    .append(" (row max); unit ").append(escape(displayUnit.label())).append("</div>");
        } else {
            html.append("<div style=\"font-size:10px;color:#475569;margin-bottom:3px\">Y axis: fixed 0 to ")
                    .append(escape(formatHistoryDisplayValue(metric, axisMax, displayUnit)))
                    .append("; unit ").append(escape(displayUnit.label())).append("</div>");
        }
        html.append("<svg width=\"").append(svgWidth).append("\" height=\"").append(HISTORY_GRAPH_HEIGHT_PX)
                .append("\" viewBox=\"0 0 ").append(svgWidth).append(" ").append(HISTORY_GRAPH_HEIGHT_PX)
                .append("\" xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" aria-label=\"")
                .append(escape(metric)).append(" history line graph\">")
                .append("<rect x=\"0\" y=\"0\" width=\"").append(svgWidth).append("\" height=\"").append(HISTORY_GRAPH_HEIGHT_PX)
                .append("\" fill=\"#eef2f7\"/>")
                .append("<text x=\"2\" y=\"10\" font-size=\"9\" fill=\"#334155\">").append(escape(formatHistoryDisplayValue(metric, axisMax, displayUnit))).append("</text>")
                .append("<text x=\"2\" y=\"").append(HISTORY_GRAPH_HEIGHT_PX / 2 + 3).append("\" font-size=\"9\" fill=\"#334155\">").append(escape(formatHistoryDisplayValue(metric, axisMax / 2.0, displayUnit))).append("</text>")
                .append("<text x=\"2\" y=\"").append(HISTORY_GRAPH_HEIGHT_PX - 3).append("\" font-size=\"9\" fill=\"#334155\">").append(escape(formatHistoryDisplayValue(metric, 0, displayUnit))).append("</text>")
                .append("<line x1=\"").append(HISTORY_GRAPH_LABEL_WIDTH_PX).append("\" y1=\"").append(HISTORY_GRAPH_HEIGHT_PX - 1).append("\" x2=\"").append(svgWidth)
                .append("\" y2=\"").append(HISTORY_GRAPH_HEIGHT_PX - 1).append("\" stroke=\"#cbd5e1\" stroke-width=\"1\"/>")
                .append("<line x1=\"").append(HISTORY_GRAPH_LABEL_WIDTH_PX).append("\" y1=\"").append(HISTORY_GRAPH_HEIGHT_PX / 2).append("\" x2=\"").append(svgWidth)
                .append("\" y2=\"").append(HISTORY_GRAPH_HEIGHT_PX / 2).append("\" stroke=\"#dbe4ef\" stroke-width=\"1\"/>");
        StringBuilder points = new StringBuilder();
        String color = "#2563eb";
        for (HistorySample sample : plotted) {
            double value = historyScaleValue(metric, sample.value());
            long pct = axisMax <= 0 ? 0 : Math.round(value * 100.0 / axisMax);
            pct = Math.max(0, Math.min(100, pct));
            color = pct >= 80 ? "#dc2626" : pct >= 60 ? "#f59e0b" : color;
            double x = HISTORY_GRAPH_LABEL_WIDTH_PX + (timePositionPercent(start, end, sample.epochSecond()) * graphWidth / 100.0);
            double y = HISTORY_GRAPH_HEIGHT_PX - 4 - (pct * (HISTORY_GRAPH_HEIGHT_PX - 8) / 100.0);
            if (!points.isEmpty()) {
                points.append(' ');
            }
            points.append(String.format(java.util.Locale.ROOT, "%.1f,%.1f", x, y));
        }
        html.append("<polyline points=\"").append(points).append("\" fill=\"none\" stroke=\"").append(color)
                .append("\" stroke-width=\"2\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/>")
                .append("</svg>")
                .append(hourAxis(plotted, svgWidth, HISTORY_GRAPH_LABEL_WIDTH_PX, graphWidth))
                .append("<div style=\"display:flex;justify-content:space-between;gap:12px;font-size:10px;color:#475569;margin-top:3px\">")
                .append("<span>low ").append(escape(formatHistoryDisplayValue(metric, min, displayUnit))).append("</span>")
                .append("<span>high ").append(escape(formatHistoryDisplayValue(metric, max, displayUnit))).append("</span>")
                .append("</div></div>");
        return html.toString();
    }

    private static List<HistorySample> graphSamples(List<HistorySample> samples) {
        if (samples.size() <= HISTORY_GRAPH_POINTS) {
            return samples;
        }
        List<HistorySample> selected = new ArrayList<>();
        int lastIndex = samples.size() - 1;
        int previous = -1;
        for (int i = 0; i < HISTORY_GRAPH_POINTS; i++) {
            int index = (int) Math.round(i * lastIndex / (double) (HISTORY_GRAPH_POINTS - 1));
            if (index != previous) {
                selected.add(samples.get(index));
                previous = index;
            }
        }
        return selected;
    }

    private static String hourAxis(List<HistorySample> samples, int axisWidth, int plotOffset, int plotWidth) {
        if (samples.isEmpty()) {
            return "";
        }
        long start = samples.get(0).epochSecond();
        long end = samples.get(samples.size() - 1).epochSecond();
        long step = HISTORY_AXIS_STEP_SECONDS;
        long tick = ((start + step - 1) / step) * step;
        List<HistoryTick> ticks = new ArrayList<>();
        while (tick <= end) {
            ticks.add(new HistoryTick(timePositionPercent(start, end, tick), HISTORY_HOUR.format(Instant.ofEpochSecond(tick))));
            tick += step;
        }
        if (ticks.isEmpty()) {
            ticks.add(new HistoryTick(0, HISTORY_HOUR.format(Instant.ofEpochSecond(start))));
            if (end != start) {
                ticks.add(new HistoryTick(100, HISTORY_HOUR.format(Instant.ofEpochSecond(end))));
            }
        }
        StringBuilder html = new StringBuilder();
        html.append("<div style=\"font-size:10px;color:#475569;margin-top:3px\">X axis UTC hours every 6h</div>");
        html.append("<div style=\"position:relative;width:").append(axisWidth)
                .append("px;height:34px;border-top:1px solid #cbd5e1;margin-top:2px\">");
        for (HistoryTick historyTick : ticks) {
            double left = plotOffset + (historyTick.leftPercent() * plotWidth / 100.0);
            html.append("<span style=\"position:absolute;left:").append(String.format(java.util.Locale.ROOT, "%.1f", left))
                    .append("px;top:0;height:6px;border-left:1px solid #64748b\"></span>");
            html.append("<span style=\"position:absolute;left:").append(String.format(java.util.Locale.ROOT, "%.1f", left))
                    .append("px;top:8px;transform:translateX(-50%) rotate(-45deg);transform-origin:top center;white-space:nowrap;color:#475569\">")
                    .append(escape(historyTick.label()))
                    .append("</span>");
        }
        html.append("</div>");
        return html.toString();
    }

    private static double timePositionPercent(long start, long end, long value) {
        if (end <= start) {
            return 0;
        }
        double pct = (value - start) * 100.0 / (end - start);
        return Math.max(0, Math.min(100, pct));
    }

    private static double historyScaleValue(String metric, double value) {
        if ("CPU".equalsIgnoreCase(metric)) {
            return value <= 100 ? value : value / 1000.0;
        }
        return value;
    }

    private static double fixedAxisMax(String metric, double rowMax) {
        if ("CPU".equalsIgnoreCase(metric)) {
            return 100.0;
        }
        if ("Traffic".equalsIgnoreCase(metric)) {
            return 1_000_000_000.0;
        }
        return rowMax;
    }

    private static HistoryDisplayUnit historyDisplayUnit(String metric, double axisMax) {
        if ("Traffic".equalsIgnoreCase(metric)) {
            double abs = Math.abs(axisMax);
            if (abs >= 1_000_000_000.0) {
                return new HistoryDisplayUnit("Gbps", 1_000_000_000.0);
            }
            if (abs >= 1_000_000.0) {
                return new HistoryDisplayUnit("Mbps", 1_000_000.0);
            }
            if (abs >= 1_000.0) {
                return new HistoryDisplayUnit("Kbps", 1_000.0);
            }
            return new HistoryDisplayUnit("bps", 1.0);
        }
        if ("CPU".equalsIgnoreCase(metric)) {
            return new HistoryDisplayUnit("%", 1.0);
        }
        if ("Connections".equalsIgnoreCase(metric)) {
            return new HistoryDisplayUnit("conn", 1.0);
        }
        return new HistoryDisplayUnit("raw", 1.0);
    }

    private static String formatHistoryDisplayValue(String metric, double value, HistoryDisplayUnit displayUnit) {
        if ("CPU".equalsIgnoreCase(metric)) {
            return format(value) + "%";
        }
        if ("Connections".equalsIgnoreCase(metric)) {
            return formatCount(value) + " conn";
        }
        if ("Traffic".equalsIgnoreCase(metric)) {
            return format(value / displayUnit.divisor()) + " " + displayUnit.label();
        }
        return format(value) + " " + displayUnit.label();
    }

    private static String formatCount(double value) {
        if (value == Math.rint(value)) {
            return Long.toString(Math.round(value));
        }
        return format(value);
    }

    private static String shortSourceName(String source) {
        String normalized = source == null ? "" : source.replace("\\", "/");
        String suffix = "";
        int hash = normalized.lastIndexOf('#');
        if (hash >= 0 && hash < normalized.length() - 1) {
            suffix = " " + normalized.substring(hash + 1);
            normalized = normalized.substring(0, hash);
        }
        int slash = normalized.lastIndexOf('/');
        String name = slash >= 0 && slash < normalized.length() - 1 ? normalized.substring(slash + 1) : normalized;
        return name + suffix;
    }

    private record HistorySeries(int rawEntries, List<HistorySample> samples) {
    }

    private record HistoryTick(double leftPercent, String label) {
    }

    private record HistoryDisplayUnit(String label, double divisor) {
    }

    private record HistorySample(long epochSecond, double value) {
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
        String ips = compactIpList(part(parts, 1));
        double rxGb = doubleValue(part(parts, 2));
        double txGb = doubleValue(part(parts, 3));
        return "<div style=\"border:1px solid #cbd5e1;background:#f8fafc;padding:4px;margin:0 0 4px 0\">"
                + "<small><strong>" + escape(part(parts, 0)) + "</strong> " + escape(ips) + "</small><br>"
                + "<small>RX</small>" + gbBar(rxGb, maxGb) + "<br>"
                + "<small>TX</small>" + gbBar(txGb, maxGb)
                + "</div>";
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

    private static long longValue(String value) {
        try {
            return Long.parseLong(value == null ? "0" : value.replace("%", "").strip());
        } catch (NumberFormatException exception) {
            return 0;
        }
    }

    private static String compactIpList(String ips) {
        List<String> values = new ArrayList<>();
        for (String ip : ips.split(",")) {
            String trimmed = ip.strip();
            if (!trimmed.isBlank()) {
                values.add(trimmed);
            }
        }
        if (values.isEmpty()) {
            return "ip unknown";
        }
        List<String> visible = values.stream().limit(2).toList();
        String suffix = values.size() > 2 ? " +" + (values.size() - 2) + " more" : "";
        return "ip " + String.join(", ", visible) + suffix;
    }

    private static boolean activeNonExitedService(String service) {
        String normalized = " " + service.strip().replaceAll("\\s+", " ") + " ";
        return (normalized.contains(" loaded active ") && !normalized.contains(" exited "))
                || normalized.matches(" .+ run \\(pid \\d+\\).*");
    }

    private static String serviceName(String service) {
        String trimmed = service.strip();
        int space = trimmed.indexOf(' ');
        return space < 0 ? trimmed : trimmed.substring(0, space);
    }

    private static int serviceRank(String service) {
        String normalized = " " + service.strip().replaceAll("\\s+", " ") + " ";
        return normalized.contains(" loaded active running ") || normalized.matches(" .+ run \\(pid \\d+\\).*") ? 0 : 1;
    }

    private static void appendProcessTable(StringBuilder markdown, List<String> processes) {
        markdown.append("| PID | CPU % | Memory % | RSS GB | Shared GB | Command |\n");
        markdown.append("| ---: | ---: | ---: | ---: | ---: | --- |\n");
        for (String process : processes.stream().limit(10).toList()) {
            appendProcessRow(markdown, process);
        }
        markdown.append("\n");
        if (processes.size() > 10) {
            markdown.append("<details><summary>+")
                    .append(processes.size() - 10)
                    .append(" more</summary>\n\n");
            markdown.append("| PID | CPU % | Memory % | RSS GB | Shared GB | Command |\n");
            markdown.append("| ---: | ---: | ---: | ---: | ---: | --- |\n");
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
                .append(escape(parts.length >= 6 ? part(parts, 4) : "0.00")).append(" | ")
                .append(escape(processCommand(parts))).append(" |\n");
    }

    private static void appendDiskTable(StringBuilder markdown, F5Report report) {
        if (report.diskMounts().isEmpty()) {
            return;
        }
        List<String[]> rows = diskRowsByUsage(report);
        markdown.append("Disk mounts (")
                .append(rows.size())
                .append(", sorted by used percent):\n\n");
        markdown.append("| Mount | Used | Used GB | Available GB | Total GB |\n");
        markdown.append("| --- | ---: | ---: | ---: | ---: |\n");
        for (String[] parts : rows.stream().limit(10).toList()) {
            appendDiskRow(markdown, parts);
        }
        markdown.append("\n");
        if (rows.size() > 10) {
            markdown.append("<details><summary>+")
                    .append(rows.size() - 10)
                    .append(" more mounts</summary>\n\n");
            markdown.append("| Mount | Used | Used GB | Available GB | Total GB |\n");
            markdown.append("| --- | ---: | ---: | ---: | ---: |\n");
            for (String[] parts : rows.subList(10, rows.size())) {
                appendDiskRow(markdown, parts);
            }
            markdown.append("\n</details>\n\n");
        }
    }

    private static void appendDiskRow(StringBuilder markdown, String[] parts) {
        long usedPercent = longValue(diskUsedPercent(parts));
        markdown.append("| ")
                .append(escape(part(parts, 0))).append(" | ")
                .append(htmlBar(usedPercent, "used " + usedPercent + "%")).append(" | ")
                .append(escape(part(parts, 2))).append(" | ")
                .append(escape(diskAvailable(parts))).append(" | ")
                .append(escape(part(parts, 1))).append(" |\n");
    }

    private static List<String[]> diskRowsByUsage(F5Report report) {
        return report.diskMounts().stream()
                .map(mount -> mount.split("\\|", -1))
                .sorted(Comparator
                        .comparingLong((String[] parts) -> longValue(diskUsedPercent(parts))).reversed()
                        .thenComparing(parts -> part(parts, 0)))
                .toList();
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

    private static void appendUserTable(StringBuilder markdown, List<String> users) {
        markdown.append("| User | UID | Shell | Last login |\n");
        markdown.append("| --- | ---: | --- | --- |\n");
        for (String user : users.stream().limit(10).toList()) {
            appendUserRow(markdown, user);
        }
        markdown.append("\n");
        if (users.size() > 10) {
            markdown.append("<details><summary>+")
                    .append(users.size() - 10)
                    .append(" more users</summary>\n\n");
            markdown.append("| User | UID | Shell | Last login |\n");
            markdown.append("| --- | ---: | --- | --- |\n");
            for (String user : users.subList(10, users.size())) {
                appendUserRow(markdown, user);
            }
            markdown.append("\n</details>\n\n");
        }
    }

    private static void appendUserRow(StringBuilder markdown, String user) {
        String[] parts = user.split("\\|", -1);
        markdown.append("| ")
                .append(escape(part(parts, 0))).append(" | ")
                .append(escape(part(parts, 1))).append(" | ")
                .append(escape(part(parts, 2))).append(" | ")
                .append(escape(part(parts, 3))).append(" |\n");
    }

    private static void appendLoggedUserTable(StringBuilder markdown, List<String> users) {
        markdown.append("| User | Last login | Event |\n");
        markdown.append("| --- | --- | --- |\n");
        for (String user : users.stream().limit(1).toList()) {
            appendLoggedUserRow(markdown, user);
        }
    }

    private static void appendLoggedUserRow(StringBuilder markdown, String user) {
        String[] parts = user.split("\\|", -1);
        markdown.append("| ")
                .append(escape(part(parts, 0))).append(" | ")
                .append(escape(part(parts, 2))).append(" | ")
                .append(escape(part(parts, 3))).append(" |\n");
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
                    if (isLoopbackIpv4Cidr(ip)) {
                        continue;
                    }
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

    private static boolean isLoopbackIpv4Cidr(String cidr) {
        String address = cidr == null ? "" : cidr.split("/", 2)[0].strip();
        return address.equals("localhost") || address.startsWith("127.");
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

    private record OutboundResult(String name, String host, String resolvedIp, String port, String protocol, String status, String detail) {
    }

    private record OutboundSummaryRow(F5Report report, OutboundResult result) {
        private String checkKey() {
            return result.name() + "|" + result.host() + "|" + result.port() + "|" + result.protocol();
        }
    }

    private record PartitionPoolRow(
            String partition,
            String type,
            String name,
            String destination,
            String protocol,
            String partitionTraffic,
            String members,
            String vipStats,
            String sslProfile,
            String certificate,
            String certValidity,
            String chain,
            String serverSslProfile,
            String serverCertificate,
            String serverCertValidity,
            String serverChain,
            String detail) {
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
