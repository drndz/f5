package org.qypp.f5;

class F5ReportParserTest {
    void parsesCollectorOutput() {
        String json = """
                {
                  "hostname": "f5-a",
                  "label": "edge-a",
                  "target_type": "f5",
                  "collected_at": "2026-06-24T09:00:00Z",
                  "status": "FAIL",
                  "privilege_mode": "login-user",
                  "privileged_collection": false,
                  "os": "BIG-IP",
                  "uptime": "1 day",
                  "process_count": 123,
                  "cpu_core_count": 4,
                  "cpu_load_percent": 25,
                  "load_average_1m": 1.0,
                  "load_average_5m": 0.5,
                  "load_average_15m": 0.25,
                  "load_average_1m_percent": 25,
                  "load_average_5m_percent": 13,
                  "load_average_15m_percent": 6,
                  "disk_used_percent": 40,
                  "service_count": 12,
                  "listener_count": 2,
                  "memory_used_kb": 512,
                  "memory_total_kb": 1024,
                  "disk_mounts": ["/|10.00|4.00|6.00|6.00|40%"],
                  "ip_connection_count": 12,
                  "ip_connection_max": 100,
                  "active_connections": ["tcp|10.0.0.10|443|3"],
                  "critical_services_down": ["mcpd"],
                  "external_listening_ports": [22,443],
                  "listening_endpoints": ["tcp|0.0.0.0|443|nginx"],
                  "processes_by_cpu": ["10|7.5|1.0|20.00|5.00|nginx"],
                  "processes_by_memory": ["20|1.0|8.0|120.00|10.00|java"],
                  "running_services": ["nginx.service loaded active running nginx"],
                  "network_interfaces": ["eth0|10.0.0.4/24|1.250|0.750"],
                  "system_users": ["root|0|/bin/bash|pts/0 10.0.0.1 Thu Jun 25 10:00:00 +0000 2026"],
                  "logged_users": ["root|10.0.0.1|Jun 25 10:00:00|accepted"],
                  "f5_load_history": ["/var/rrd/cpu.rrd|1782410400|1.500000"],
                  "f5_partitions_pools": ["Common|web_pool|ltm pool /Common/web_pool { members none }"],
                  "outbound_checks": ["dns|dns.example.com|10.0.0.53|53|UDP|PASS|OUTBOUND_CHECK_PASS"],
                  "recent_log_errors": ["Jun 24 error example"],
                  "checks": [
                    {"name":"critical_services","status":"FAIL","detail":"mcpd down"},
                    {"name":"memory","status":"PASS","detail":"Memory usage is 50%."}
                  ]
                }
                """;

        F5Report report = F5ReportParser.parse(json);

        TestSupport.assertEquals("f5-a", report.hostname());
        TestSupport.assertEquals("edge-a", report.label());
        TestSupport.assertEquals("f5", report.targetType());
        TestSupport.assertEquals("FAIL", report.status());
        TestSupport.assertEquals("login-user", report.privilegeMode());
        TestSupport.assertTrue(!report.privilegedCollection(), "Report should parse login-user collection mode.");
        TestSupport.assertEquals(25L, report.cpuLoadPercent());
        TestSupport.assertEquals(4L, report.cpuCoreCount());
        TestSupport.assertEquals(40L, report.diskUsedPercent());
        TestSupport.assertEquals(50L, report.memoryUsedPercent());
        TestSupport.assertEquals(1, report.diskMounts().size());
        TestSupport.assertEquals(1.0, report.loadAverage1m());
        TestSupport.assertEquals(25L, report.loadAverage1mPercent());
        TestSupport.assertEquals(12L, report.ipConnectionCount());
        TestSupport.assertEquals("tcp|10.0.0.10|443|3", report.activeConnections().get(0));
        TestSupport.assertEquals(2, report.externalListeningPorts().size());
        TestSupport.assertEquals("tcp|0.0.0.0|443|nginx", report.listeningEndpoints().get(0));
        TestSupport.assertEquals("10|7.5|1.0|20.00|5.00|nginx", report.processesByCpu().get(0));
        TestSupport.assertEquals("20|1.0|8.0|120.00|10.00|java", report.processesByMemory().get(0));
        TestSupport.assertEquals("nginx.service loaded active running nginx", report.runningServices().get(0));
        TestSupport.assertEquals("eth0|10.0.0.4/24|1.250|0.750", report.networkInterfaces().get(0));
        TestSupport.assertEquals("root|0|/bin/bash|pts/0 10.0.0.1 Thu Jun 25 10:00:00 +0000 2026", report.systemUsers().get(0));
        TestSupport.assertEquals("root|10.0.0.1|Jun 25 10:00:00|accepted", report.loggedUsers().get(0));
        TestSupport.assertEquals("/var/rrd/cpu.rrd|1782410400|1.500000", report.f5LoadHistory().get(0));
        TestSupport.assertEquals("Common|web_pool|ltm pool /Common/web_pool { members none }", report.f5PartitionsPools().get(0));
        TestSupport.assertEquals("dns|dns.example.com|10.0.0.53|53|UDP|PASS|OUTBOUND_CHECK_PASS", report.outboundChecks().get(0));
        TestSupport.assertEquals("mcpd", report.criticalServices().get(0));
        TestSupport.assertTrue(report.checks().get(0).failed(), "First check should be failed.");
    }
}
