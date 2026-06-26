package org.qypp.fleet;

record FleetTarget(String name, String host, String username, String encryptedPassword, String targetType) {
    static FleetTarget parse(String line) {
        String[] parts = line.split(",", -1);
        if (parts.length < 4) {
            throw new IllegalArgumentException("Expected CSV columns: name,mgmt_ip,username,password,target_type");
        }
        String type = parts.length >= 5 && !parts[4].isBlank() ? parts[4].trim() : "auto";
        return new FleetTarget(parts[0].trim(), parts[1].trim(), parts[2].trim(), parts[3].trim(), type);
    }
}
