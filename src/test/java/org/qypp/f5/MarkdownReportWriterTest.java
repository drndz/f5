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
                "login-user",
                false,
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
                List.of("10|7.5|1.0|20.00|5.00|nginx"),
                List.of("10|7.5|1.0|20.00|5.00|nginx"),
                List.of("nginx.service loaded active running"),
                List.of("eth0|10.0.0.4/24,fe80::1/64|1.250|0.750"),
                List.of("root|0|/bin/bash|pts/0 10.0.0.1 Thu Jun 25 10:00:00 +0000 2026"),
                List.of("root|10.0.0.1|Jun 25 10:00:00|accepted"),
                List.of("/var/rrd/cpu.rrd#user|1782410400|1.500000", "/var/rrd/cpu.rrd#user|1782414000|3.000000", "/var/rrd/throughput#bitsIn|1782410400|1000.000000"),
                List.of(
                        "Common|pool+vip|web_pool|192.0.2.10:443|tcp|bits in/out 1000 / 2000<br>bytes in/out 125 / 250|10.0.1.10:8443 state up<br>10.0.1.11:8443 state up|current connections 12<br>bits in/out 1000 / 2000<br>bytes in/out 125 / 250|clientssl|web.crt|expires Jan 1 00:00:00 2027 GMT; subject CN=web.example.com; issuer CN=Example CA|ca-chain.crt expires Jan 1 00:00:00 2030 GMT; subject CN=Example CA; issuer CN=Root CA|VIP web_vs; ltm pool /Common/web_pool { members ... }",
                        String.join("|", List.of("TenantA", "server-ssl", "backendssl", "", "", "", "", "", "", "", "", "", "backendssl", "backend.crt", "EXPIRING in 45 days; expires Aug 10 00:00:00 2026 GMT; subject CN=backend.example.com; issuer CN=Example CA", "backend-chain.crt VALID for 365 days; subject CN=Example CA; issuer CN=Root CA", "F5 server-side outbound SSL profile")),
                        "TenantA|(no pools)|"
                ),
                List.of(
                        "api|api.example.com|203.0.113.10|443|TCP|PASS|OUTBOUND_CHECK_PASS",
                        "api:TLS|api.example.com|203.0.113.10|443|TLS|PASS|OUTBOUND_CHECK_PASS RESOLVED_IP=203.0.113.10 TLS_CERT_PRESENT=1; TLS_CHAIN_CERTS=3; TLS_CERT_SUBJECT=CN=api.example.com; TLS_CERT_CN=api.example.com; TLS_CERT_ISSUER=CN=Public CA; TLS_CERT_NOT_BEFORE=Jun 26 00:00:00 2026 GMT; TLS_CERT_NOT_AFTER=Dec 23 00:00:00 2026 GMT; TLS_CERT_FINGERPRINT=SHA256/AA:BB; TLS_CERT_VALIDITY=VALID for 180 days; TLS_CHAIN_2_SUBJECT=CN=Public CA; TLS_CHAIN_2_ISSUER=CN=Root CA; TLS_CHAIN_2_NOT_BEFORE=Jan 1 00:00:00 2020 GMT; TLS_CHAIN_2_NOT_AFTER=Jan 1 00:00:00 2030 GMT; TLS_CHAIN_2_FINGERPRINT=SHA256/CC:DD; TLS_CHAIN_3_SUBJECT=CN=Root CA; TLS_CHAIN_3_ISSUER=CN=Root CA; TLS_CHAIN_3_NOT_BEFORE=Jan 1 00:00:00 2015 GMT; TLS_CHAIN_3_NOT_AFTER=Jan 1 00:00:00 2035 GMT; TLS_CHAIN_3_FINGERPRINT=SHA256/EE:FF",
                        "pool:Common/web_pool:TCP:10.0.1.10:8443|10.0.1.10|10.0.1.10|8443|TCP|PASS|OUTBOUND_CHECK_PASS",
                        "pool:Common/web_pool:TCP:10.0.1.11:8443|10.0.1.11|10.0.1.11|8443|TCP|FAIL|OUTBOUND_CHECK_FAIL Connection timed out",
                        "pool:Common/web_pool:TLS:10.0.1.10:8443|10.0.1.10|10.0.1.10|8443|TLS|PASS|OUTBOUND_CHECK_PASS RESOLVED_IP=10.0.1.10 TLS_CERT_PRESENT=1; TLS_CHAIN_CERTS=2; TLS_CERT_SUBJECT=CN=pool.example.com; TLS_CERT_CN=pool.example.com; TLS_CERT_ISSUER=CN=Example CA; TLS_CERT_NOT_BEFORE=Jun 26 00:00:00 2026 GMT; TLS_CERT_NOT_AFTER=Oct 24 00:00:00 2026 GMT; TLS_CERT_FINGERPRINT=SHA256/11:22; TLS_CERT_VALIDITY=VALID for 120 days; TLS_CHAIN_2_SUBJECT=CN=Example CA; TLS_CHAIN_2_ISSUER=CN=Root CA; TLS_CHAIN_2_NOT_BEFORE=Jan 1 00:00:00 2020 GMT; TLS_CHAIN_2_NOT_AFTER=Jan 1 00:00:00 2030 GMT; TLS_CHAIN_2_FINGERPRINT=SHA256/33:44"
                ),
                List.of(),
                List.of(new F5Check("external_listening_ports", "PASS", "Only 443"))
        );
        F5Report second = new F5Report(
                "app-a",
                "vm",
                "f5-b",
                "2026-06-24T09:01:00Z",
                "WARN",
                "login-user",
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
                List.of("root|0|/bin/bash|Never logged in", "admin|1000|/bin/bash|pts/1 10.0.0.2 Thu Jun 25 11:00:00 +0000 2026"),
                List.of("admin|10.0.0.2|Thu Jun 25 11:00:00|login"),
                List.of(),
                List.of(),
                List.of(
                        "api|api.example.com|203.0.113.20|443|TCP|FAIL|OUTBOUND_CHECK_FAIL Connection timed out",
                        "dns|dns.example.com|203.0.113.53|53|UDP|UNKNOWN|OUTBOUND_CHECK_UNKNOWN Generic UDP reachability cannot be validated reliably"
                ),
                List.of("fatal sample"),
                List.of(new F5Check("critical_services", "FAIL", "tmm down"))
        );

        String markdown = MarkdownReportWriter.write(List.of(second, first));

        TestSupport.assertTrue(markdown.contains("| edge-a | f5-a | f5 | <span style=\"display:inline-block;background:#bbf7d0;color:#111827"), "Report should include edge-a.");
        TestSupport.assertTrue(markdown.contains("| app-a | f5-b | vm | <span style=\"display:inline-block;background:#fed7aa;color:#111827"), "Report should include app-a.");
        TestSupport.assertTrue(markdown.contains("- Command mode: read-only diagnostics"), "Report should document non-destructive command mode.");
        TestSupport.assertTrue(markdown.contains("Resource graphs:"), "Report should include resource graphs.");
        TestSupport.assertTrue(markdown.contains("# Validation Report"), "Report title should not mention SSH.");
        TestSupport.assertTrue(markdown.contains("| Label | Host | Type | Status | Failed checks | Uptime | Privilege | Local users | Logged | CPU Core / Load | Processes by CPU | Memory | Processes by Memory |"), "Summary should include local/logged users and place CPU and memory process columns next to their resource columns.");
        TestSupport.assertTrue(markdown.contains("<strong>2 users</strong>"), "Summary should include registered user count.");
        TestSupport.assertTrue(markdown.contains("<small>admin login<br>Thu Jun 25 11:00:00</small>"), "Summary should include the latest logged user without login IP.");
        TestSupport.assertTrue(markdown.contains("Local users and last login (2):"), "Details should include local users and last login.");
        TestSupport.assertTrue(markdown.contains("Latest logged SSH user record:"), "Details should include only the latest logged SSH user record.");
        TestSupport.assertTrue(markdown.contains("| admin | 1000 | /bin/bash | pts/1 10.0.0.2 Thu Jun 25 11:00:00 +0000 2026 |"), "User details should include last login timestamp.");
        TestSupport.assertTrue(markdown.contains("| admin | Thu Jun 25 11:00:00 | login |"), "Logged user details should include timestamp without login IP.");
        TestSupport.assertTrue(!markdown.contains("| admin | 10.0.0.2 | Thu Jun 25 11:00:00 | login |"), "Logged user details should not include login IP.");
        TestSupport.assertTrue(markdown.contains("## F5 RRD History"), "Report should include F5 RRD history section.");
        TestSupport.assertTrue(markdown.contains("| edge-a | f5-a | CPU | 2 | 2 | 2 |"), "F5 RRD history should show raw, aggregated, and graphed CPU sample counts.");
        TestSupport.assertTrue(markdown.contains("| edge-a | f5-a | Traffic | 1 | 1 | 1 |"), "F5 RRD history should show raw, aggregated, and graphed traffic sample counts.");
        TestSupport.assertTrue(markdown.contains("| Label | Host | Metric | Raw entries | Aggregated points | Graph points | Trend (row max) | Trend (0-100%) |"), "F5 load history should include raw, aggregated, graph point, row-max, and fixed-scale trend columns.");
        TestSupport.assertTrue(markdown.contains("X axis UTC hours every 6h"), "F5 load history should show six-hour labels on the X axis.");
        TestSupport.assertTrue(markdown.contains("Y axis: 0 to"), "F5 load history should show actual row-max Y-axis values.");
        TestSupport.assertTrue(markdown.contains("Y axis: fixed 0 to"), "F5 load history should show actual fixed-scale Y-axis values.");
        TestSupport.assertTrue(markdown.contains("<polyline"), "F5 load history should render line graphs.");
        TestSupport.assertTrue(!markdown.contains("| Values |"), "F5 load history should not include a separate values column.");
        TestSupport.assertTrue(markdown.contains("## F5 Partitions And Pools"), "Report should include F5 partition and pool section.");
        TestSupport.assertTrue(markdown.contains("| Label | Host | Partition | Type | Pool/VIP | VIP destination | Protocol | Inbound VIP stats | Inbound VIP client SSL profile | Inbound VIP cert | Inbound VIP cert validity | Inbound VIP chain | Partition traffic | Pool members | Remote pool member checks | Pool outbound server SSL profile | F5 outbound client cert | F5 outbound client cert validity | F5 outbound client chain | Detail |"), "F5 partition/pool summary should separate inbound VIP certificates from pool outbound certificates.");
        TestSupport.assertTrue(markdown.contains("bits in/out 1000 / 2000<br>bytes in/out 125 / 250 | 10.0.1.10:8443 state up<br>10.0.1.11:8443 state up"), "F5 partition/pool summary should include partition traffic before pool members.");
        TestSupport.assertTrue(markdown.contains("F5 pool with VIP</span><br>web_pool<br><small>VIP 192.0.2.10:443</small>"), "F5 partition/pool summary should make pool and VIP labels self-describing.");
        TestSupport.assertTrue(markdown.contains("<span style=\"display:inline-block;border:1px solid"), "F5 partition/pool summary should render certificate validity as a colored badge.");
        TestSupport.assertTrue(markdown.contains("10.0.1.10:8443 TLS <span style=\"display:inline-block;background:#bbf7d0"), "F5 partition/pool summary should include TLS checks for discovered pool members.");
        TestSupport.assertTrue(markdown.contains("<small>Remote TLS cert</small>"), "F5 partition/pool summary should label returned pool member TLS certificate validity.");
        TestSupport.assertTrue(markdown.contains("CN pool.example.com; subject CN=pool.example.com; issuer CN=Example CA; valid from Jun 26 00:00:00 2026 GMT; expires Oct 24 00:00:00 2026 GMT; fingerprint SHA256/11:22"), "F5 partition/pool summary should include returned TLS leaf certificate details.");
        TestSupport.assertTrue(markdown.contains("Presented CA chain (1): CA #1: subject CN=Example CA; issuer CN=Root CA; valid from Jan 1 00:00:00 2020 GMT; expires Jan 1 00:00:00 2030 GMT; fingerprint SHA256/33:44"), "F5 partition/pool summary should include returned TLS CA chain details.");
        TestSupport.assertTrue(!markdown.contains("F5 server-side SSL profile</span><br>backendssl"), "F5 partition/pool summary should omit standalone server SSL rows when no VIP references them.");
        TestSupport.assertTrue(!markdown.contains("backend.crt | <span style=\"display:inline-block;border:1px solid #fdba74"), "F5 partition/pool summary should avoid duplicate standalone outbound certificate rows.");
        TestSupport.assertTrue(!markdown.contains("<br>(no pools) |"), "F5 partition/pool details should omit empty partition placeholders.");
        TestSupport.assertTrue(markdown.contains("## Outbound Connectivity"), "Report should include outbound connectivity section.");
        TestSupport.assertTrue(markdown.contains("| Check | Host | Port | Protocol | VM label | VM host | Resolved IP | Status | Elapsed | Cert expires | Detail |"), "Outbound summary should group comparable VM rows in one table.");
        int edgeApi = markdown.indexOf("| api | api.example.com | 443 | TCP | edge-a | f5-a | 203.0.113.10 | <span style=\"display:inline-block;background:#bbf7d0;color:#111827");
        int appApi = markdown.indexOf("| api | api.example.com | 443 | TCP | app-a | f5-b | 203.0.113.20 | <span style=\"display:inline-block;background:#fecaca;color:#111827");
        int appDns = markdown.indexOf("| dns | dns.example.com | 53 | UDP | app-a | f5-b | 203.0.113.53 | <span style=\"display:inline-block;background:#fed7aa;color:#111827");
        TestSupport.assertTrue(edgeApi >= 0 && appApi > edgeApi && appDns > appApi, "Outbound summary should keep comparable api rows adjacent before dns rows.");
        TestSupport.assertTrue(markdown.contains("| api:TLS | api.example.com | 443 | TLS |"), "Outbound summary should include TLS certificate probes for configured TCP checks.");
        TestSupport.assertTrue(markdown.contains("CN api.example.com; subject CN=api.example.com; issuer CN=Public CA; valid from Jun 26 00:00:00 2026 GMT; expires Dec 23 00:00:00 2026 GMT; fingerprint SHA256/AA:BB"), "Outbound summary should show configured TCP TLS leaf certificate details.");
        TestSupport.assertTrue(markdown.contains("Presented CA chain (2): CA #1: subject CN=Public CA; issuer CN=Root CA; valid from Jan 1 00:00:00 2020 GMT; expires Jan 1 00:00:00 2030 GMT; fingerprint SHA256/CC:DD<br>CA #2: subject CN=Root CA; issuer CN=Root CA; valid from Jan 1 00:00:00 2015 GMT; expires Jan 1 00:00:00 2035 GMT; fingerprint SHA256/EE:FF"), "Outbound summary should show every returned CA certificate.");
        TestSupport.assertTrue(markdown.contains("Outbound connectivity checks (5):"), "Device details should include outbound checks.");
        TestSupport.assertTrue(!markdown.contains("| Services | Listeners |"), "Summary should not have separate services/listeners count columns.");
        TestSupport.assertTrue(markdown.contains("background:#fed7aa;color:#111827"), "Summary should color warning status values with an orange background.");
        TestSupport.assertTrue(markdown.contains("Active connection groups"), "Report should include active connection group summary.");
        TestSupport.assertTrue(markdown.contains(">1m 0.20</span>"), "Load summary should include 1m label inside graph.");
        TestSupport.assertTrue(markdown.contains(">5m 0.10</span>"), "Load summary should include 5m label inside graph.");
        TestSupport.assertTrue(markdown.contains(">15m 0.05</span>"), "Load summary should include 15m label inside graph.");
        TestSupport.assertTrue(markdown.contains("background:linear-gradient(to right,#16a34a"), "Report should include colored percentage bars.");
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
        TestSupport.assertTrue(!topologySection(markdown).contains("127.0.0.0/8"), "Network topology should omit loopback subnet bands.");
        TestSupport.assertTrue(markdown.contains("Service details"), "Report should include service summary.");
        TestSupport.assertTrue(markdown.contains("Processes sorted by CPU (12):"), "Report should include process CPU detail counter.");
        TestSupport.assertTrue(markdown.contains("Processes sorted by memory (12):"), "Report should include process memory detail counter.");
        TestSupport.assertTrue(markdown.contains("<details><summary>+2 more</summary>"), "Report should collapse detail tables after ten rows.");
        TestSupport.assertTrue(markdown.contains("<small>java</small><br><span"), "CPU summary should include process name with a graph bar.");
        TestSupport.assertTrue(markdown.contains("90.0%</span>"), "CPU summary should show CPU percent inside graph bar.");
        TestSupport.assertTrue(markdown.contains("<small>postgres</small><br><span"), "Memory summary should include process name with a graph bar.");
        TestSupport.assertTrue(markdown.contains("RSS 0.039 GB</span>"), "Memory summary should show RSS GB inside graph bar.");
        TestSupport.assertTrue(markdown.contains("shared 8.00 GB"), "Memory summary should show shared memory.");
        TestSupport.assertTrue(markdown.contains("| 20 | 90.0 | 2.0 | 40.00 | 8.00 | java |"), "Report should include process table row.");
        TestSupport.assertTrue(markdown.contains("<small>postgres.service</small>"), "Service summary should include active service names.");
        TestSupport.assertTrue(markdown.contains("<details><summary>+1 more</summary>"), "Service summary should collapse services after the top five.");
        TestSupport.assertTrue(markdown.contains("Running services (12):"), "Running service details should include a counter.");
        TestSupport.assertTrue(!markdown.contains("cloud-init.service"), "Report should exclude active exited services.");
        TestSupport.assertTrue(markdown.contains("| eth0 | 10.0.0.4/24,fe80::1/64 | 1.250 | 0.750 |"), "Report should include network interface details.");
        TestSupport.assertTrue(markdown.contains("<small><strong>eth0</strong> ip 10.0.0.5/24</small>"), "Network summary should show boxed interface IP details.");
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
                "20|90.0|2.0|40.00|8.00|" + commandPrefix,
                "21|10.0|1.0|10.00|2.00|" + commandPrefix + "-1",
                "22|9.0|5.0|80.00|3.00|" + commandPrefix + "-2",
                "23|8.0|4.0|70.00|3.00|" + commandPrefix + "-3",
                "24|7.0|3.0|60.00|3.00|" + commandPrefix + "-4",
                "25|6.0|2.0|50.00|3.00|" + commandPrefix + "-5",
                "26|5.0|1.0|40.00|3.00|" + commandPrefix + "-6",
                "27|4.0|1.0|30.00|3.00|" + commandPrefix + "-7",
                "28|3.0|1.0|20.00|3.00|" + commandPrefix + "-8",
                "29|2.0|1.0|10.00|3.00|" + commandPrefix + "-9",
                "30|1.0|1.0|9.00|3.00|" + commandPrefix + "-10",
                "31|0.5|1.0|8.00|3.00|" + commandPrefix + "-11"
        );
    }

    private static String topologySection(String markdown) {
        int start = markdown.indexOf("## Network Topology");
        int end = markdown.indexOf("## Device Details");
        return start >= 0 && end > start ? markdown.substring(start, end) : "";
    }
}
