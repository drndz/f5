package org.qypp.f5;

import java.util.List;

public record F5Report(
        String label,
        String targetType,
        String hostname,
        String collectedAt,
        String status,
        String privilegeMode,
        boolean privilegedCollection,
        String os,
        String uptime,
        int processCount,
        long cpuCoreCount,
        long cpuLoadPercent,
        double loadAverage1m,
        double loadAverage5m,
        double loadAverage15m,
        long loadAverage1mPercent,
        long loadAverage5mPercent,
        long loadAverage15mPercent,
        long diskUsedPercent,
        int serviceCount,
        int listenerCount,
        long memoryUsedKb,
        long memoryTotalKb,
        List<String> diskMounts,
        long ipConnectionCount,
        long ipConnectionMax,
        List<String> activeConnections,
        List<String> criticalServices,
        List<Integer> externalListeningPorts,
        List<String> listeningEndpoints,
        List<String> processesByCpu,
        List<String> processesByMemory,
        List<String> runningServices,
        List<String> networkInterfaces,
        List<String> systemUsers,
        List<String> loggedUsers,
        List<String> f5LoadHistory,
        List<String> f5PartitionsPools,
        List<String> outboundChecks,
        List<String> recentLogErrors,
        List<F5Check> checks
) {
    public long memoryUsedPercent() {
        if (memoryTotalKb <= 0) {
            return 0;
        }
        return Math.round(memoryUsedKb * 100.0 / memoryTotalKb);
    }
}
