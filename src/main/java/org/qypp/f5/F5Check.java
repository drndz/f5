package org.qypp.f5;

public record F5Check(String name, String status, String detail) {
    public boolean failed() {
        return "FAIL".equalsIgnoreCase(status);
    }

    public boolean warning() {
        return "WARN".equalsIgnoreCase(status);
    }
}
