package org.qypp.fleet;

record ValidationCommand(String id, String command, String description) {
    ValidationCommand(String id, String command) {
        this(id, command, "");
    }

    String label() {
        return id;
    }
}
