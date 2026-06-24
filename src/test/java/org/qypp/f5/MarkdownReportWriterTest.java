package org.qypp.f5;

import java.util.List;

class MarkdownReportWriterTest {
    void writesUnifiedMarkdownForMultipleDevices() {
        F5Report first = new F5Report(
                "edge-a",
                "f5",
                "f5-a",
                "2026-06-24T09:00:00Z",
                "PASS",
                "root",
                true,
                "BIG-IP",
                "1 day",
                100,
                2,
                10,
                0.2,
                0.1,
                0.05,
                10,
                5,
                3,
                20,
                10,
                1,
                100,
                200,
                List.of("/|1.00|0.50|0.50|0.50|50%"),
                2,
                100,
                List.of("in|tcp|10.0.0.10|22|2"),
                List.of(),
                List.of(443),
                List.of("tcp|0.0.0.0|443|nginx"),
                List.of("10|7.5|1.0|20.00|nginx"),
                List.of("10|7.5|1.0|20.00|nginx"),
                List.of("nginx.service loaded active running"),
                List.of("eth0|10.0.0.4/24,fe80::1/64|1.250|0.750"),
                List.of(),
                List.of(new F5Check("external_listening_ports", "PASS", "Only 443"))
        );
        F5Report second = new F5Report(
                "app-a",
                "vm",
                "f5-b",
                "2026-06-24T09:01:00Z",
                "WARN",
                "standard",
                false,
                "Ubuntu",
                "2 days",
                120,
                4,
                90,
                3.6,
                2.0,
                1.0,
                90,
                50,
                25,
                95,
                10,
                2,
                180,
                200,
                List.of("/|2.00|1.80|0.20|0.20|90%"),
                4,
                100,
                List.of("out|tcp|10.0.0.20|443|3", "in|tcp|10.0.0.30|22|1"),
                List.of("tmm"),
                List.of(22, 443),
                List.of(
                        "tcp|0.0.0.0|22|sshd",
                        "tcp|10.0.0.4|443|nginx",
                        "tcp|10.0.0.4|8001|svc1",
                        "tcp|10.0.0.4|8002|svc2",
                        "tcp|10.0.0.4|8003|svc3",
                        "tcp|10.0.0.4|8004|svc4",
                        "tcp|10.0.0.4|8005|svc5",
                        "tcp|10.0.0.4|8006|svc6",
                        "tcp|10.0.0.4|8007|svc7",
                        "tcp|10.0.0.4|8008|svc8",
                        "tcp|10.0.0.4|8009|svc9"
                ),
                processRows("java"),
                processRows("postgres"),
                List.of(
                        "ssh.service loaded active running",
                        "postgres.service loaded active running",
                        "nginx.service loaded active running",
                        "cron.service loaded active running",
                        "dbus.service loaded active running",
                        "systemd-journald.service loaded active running",
                        "svc1.service loaded active running",
                        "svc2.service loaded active running",
                        "svc3.service loaded active running",
                        "svc4.service loaded active running",
                        "svc5.service loaded active running",
                        "svc6.service loaded active running",
                        "cloud-init.service loaded active exited"
                ),
                List.of("eth0|10.0.0.5/24|2.500|1.125", "lo|127.0.0.1/8,::1/128|0.001|0.001"),
                List.of("fatal sample"),
                List.of(new F5Check("critical_services", "FAIL", "tmm down"))
        );

        String markdown = MarkdownReportWriter.write(List.of(second, first));

        TestSupport.assertTrue(markdown.contains("| edge-a | f5-a | f5 | <strong style=\"color:#15803d\">PASS</strong> | 0 | root read-only |"), "Report should include edge-a.");
        TestSupport.assertTrue(markdown.contains("| app-a | f5-b | vm | <strong style=\"color:#f97316\">WARN</strong> | 1 | standard |"), "Report should include app-a.");
        TestSupport.assertTrue(markdown.contains("- Command mode: read-only diagnostics"), "Report should document non-destructive command mode.");
        TestSupport.assertTrue(markdown.contains("Resource graphs:"), "Report should include resource graphs.");
        TestSupport.assertTrue(markdown.contains("# Validation Report"), "Report title should not mention SSH.");
        TestSupport.assertTrue(markdown.contains("| Label | Host | Type | Status | Failed checks | Privilege | CPU Core / Load | Processes by CPU | Memory | Processes by Memory |"), "Summary should place CPU and memory process columns next to their resource columns.");
        TestSupport.assertTrue(!markdown.contains("| Services | Listeners |"), "Summary should not have separate services/listeners count columns.");
        TestSupport.assertTrue(markdown.contains("<strong style=\"color:#f97316\">WARN</strong>"), "Summary should color warning status values orange.");
        TestSupport.assertTrue(markdown.contains("Active connection groups"), "Report should include active connection group summary.");
        TestSupport.assertTrue(markdown.contains(">1m 0.20</span>"), "Load summary should include 1m label inside graph.");
        TestSupport.assertTrue(markdown.contains(">5m 0.10</span>"), "Load summary should include 5m label inside graph.");
        TestSupport.assertTrue(markdown.contains(">15m 0.05</span>"), "Load summary should include 15m label inside graph.");
        TestSupport.assertTrue(markdown.contains("background:#16a34a"), "Report should include colored percentage bars.");
        TestSupport.assertTrue(markdown.contains(">50%</span>"), "Report should include percentage inside bars.");
        TestSupport.assertTrue(markdown.contains("Processes by CPU"), "Report should include process CPU summary.");
        TestSupport.assertTrue(markdown.contains("Processes by Memory"), "Report should include process memory summary.");
        TestSupport.assertTrue(markdown.contains("Listener details"), "Report should include listener summary.");
        TestSupport.assertTrue(markdown.contains("Network interfaces"), "Report should include network summary.");
        TestSupport.assertTrue(markdown.contains("## Network Topology"), "Report should include inferred network topology.");
        TestSupport.assertTrue(markdown.contains("display:grid;grid-template-columns"), "Network topology should use an HTML layout.");
        TestSupport.assertTrue(markdown.contains("Shared IPv4 subnets"), "Network topology should show shared subnet grouping.");
        TestSupport.assertTrue(markdown.contains("Incoming peers"), "Network topology should label incoming connection peers.");
        TestSupport.assertTrue(markdown.contains("Outgoing peers"), "Network topology should label outgoing connection peers.");
        TestSupport.assertTrue(markdown.contains("connection direction"), "Network topology should render graphical arrows.");
        TestSupport.assertTrue(!markdown.contains("bubbles"), "Report should avoid the word bubbles.");
        TestSupport.assertTrue(markdown.contains("tcp :443 count 3"), "Network topology should show per-port active connection counts.");
        TestSupport.assertTrue(markdown.contains("10.0.0.0/24"), "Network topology should group shared IPv4 subnets.");
        TestSupport.assertTrue(markdown.contains("Service details"), "Report should include service summary.");
        TestSupport.assertTrue(markdown.contains("Processes sorted by CPU (12):"), "Report should include process CPU detail counter.");
        TestSupport.assertTrue(markdown.contains("Processes sorted by memory (12):"), "Report should include process memory detail counter.");
        TestSupport.assertTrue(markdown.contains("<details><summary>+2 more</summary>"), "Report should collapse detail tables after ten rows.");
        TestSupport.assertTrue(markdown.contains("<small>java</small> <span"), "CPU summary should include process name with a graph bar.");
        TestSupport.assertTrue(markdown.contains("90.0%</span>"), "CPU summary should show CPU percent inside graph bar.");
        TestSupport.assertTrue(markdown.contains("<small>postgres</small> <span"), "Memory summary should include process name with a graph bar.");
        TestSupport.assertTrue(markdown.contains("0.039 GB</span>"), "Memory summary should show GB inside graph bar.");
        TestSupport.assertTrue(markdown.contains("| 20 | 90.0 | 2.0 | 40.00 | java |"), "Report should include process table row.");
        TestSupport.assertTrue(markdown.contains("<small>postgres.service</small>"), "Service summary should include active service names.");
        TestSupport.assertTrue(markdown.contains("<details><summary>+1 more</summary>"), "Service summary should collapse services after the top five.");
        TestSupport.assertTrue(markdown.contains("Running services (12):"), "Running service details should include a counter.");
        TestSupport.assertTrue(!markdown.contains("cloud-init.service"), "Report should exclude active exited services.");
        TestSupport.assertTrue(markdown.contains("| eth0 | 10.0.0.4/24,fe80::1/64 | 1.250 | 0.750 |"), "Report should include network interface details.");
        TestSupport.assertTrue(markdown.contains("<small>eth0 ip 10.0.0.5/24</small>"), "Network summary should show IPv4 only.");
        TestSupport.assertTrue(markdown.contains("2.500 GB</span>"), "Network summary should show RX/TX GB inside graph bars.");
        TestSupport.assertTrue(markdown.contains("<strong>11 listeners</strong>"), "Listener summary should include total listener count.");
        TestSupport.assertTrue(markdown.contains("<details><summary>+1 more</summary><small>tcp 10.0.0.4:8009 svc9</small></details>"), "Listener summary should collapse after ten listeners.");
        TestSupport.assertTrue(markdown.contains("| tcp | <strong style=\"color:#dc2626\">0.0.0.0</strong> | 443 | <strong style=\"color:#dc2626\">nginx</strong> |"), "Report should highlight wildcard listener details.");
        TestSupport.assertTrue(markdown.contains("| outgoing | tcp | 10.0.0.20 | 443 | 3 |"), "Report should include grouped active connection details.");
        TestSupport.assertTrue(markdown.contains("<small>outgoing tcp 10.0.0.20:443 count 3</small>"), "Report should include active connection counts in summary.");
        TestSupport.assertTrue(markdown.contains("fatal sample"), "Report should include log findings.");
    }

    private static List<String> processRows(String commandPrefix) {
        return List.of(
                "20|90.0|2.0|40.00|" + commandPrefix,
                "21|10.0|1.0|10.00|" + commandPrefix + "-1",
                "22|9.0|5.0|80.00|" + commandPrefix + "-2",
                "23|8.0|4.0|70.00|" + commandPrefix + "-3",
                "24|7.0|3.0|60.00|" + commandPrefix + "-4",
                "25|6.0|2.0|50.00|" + commandPrefix + "-5",
                "26|5.0|1.0|40.00|" + commandPrefix + "-6",
                "27|4.0|1.0|30.00|" + commandPrefix + "-7",
                "28|3.0|1.0|20.00|" + commandPrefix + "-8",
                "29|2.0|1.0|10.00|" + commandPrefix + "-9",
                "30|1.0|1.0|9.00|" + commandPrefix + "-10",
                "31|0.5|1.0|8.00|" + commandPrefix + "-11"
        );
    }
}
