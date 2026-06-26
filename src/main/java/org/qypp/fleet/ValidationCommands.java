package org.qypp.fleet;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ValidationCommands {
    private static final Pattern CHECK_MARKER = Pattern.compile("^##(CK\\d{2,3})(?:\\s+#\\s*(.*))?\\s*$");
    private final Map<String, ValidationCommand> commands;

    private ValidationCommands(Map<String, ValidationCommand> commands) {
        this.commands = Map.copyOf(commands);
    }

    static ValidationCommands load(Path targetsFile, String targetType) throws IOException {
        Map<String, ValidationCommand> commands = new HashMap<>();
        for (Path configured : configuredPaths(targetsFile, targetType)) {
            loadFile(configured, commands);
        }
        return new ValidationCommands(commands);
    }

    boolean hasCommand(String id) {
        ValidationCommand command = commands.get(id);
        return command != null && !command.command().isBlank();
    }

    private static void loadFile(Path configured, Map<String, ValidationCommand> commands) throws IOException {
        PendingCheck pending = null;
        for (String line : Files.readAllLines(configured)) {
            pending = parseLine(line, pending, commands);
        }
        flushPending(pending, commands);
    }

    ValidationCommand command(String id) {
        ValidationCommand command = commands.get(id);
        if (command == null || command.command().isBlank()) {
            throw new IllegalArgumentException("Validation command is not defined: " + id);
        }
        return command;
    }

    ValidationCommand command(String id, Map<String, String> values) {
        ValidationCommand base = command(id);
        String command = base.command();
        for (Map.Entry<String, String> entry : values.entrySet()) {
            command = command.replace("${" + entry.getKey() + "}", entry.getValue());
        }
        return new ValidationCommand(base.id(), command, base.description());
    }

    private static List<Path> configuredPaths(Path targetsFile, String targetType) {
        String explicit = System.getenv("VALIDATION_COMMANDS_FILE");
        if (explicit != null && !explicit.isBlank()) {
            return List.of(Path.of(explicit));
        }
        Path root = repositoryRoot(targetsFile);
        Path scripts = root.resolve("scripts");
        String normalizedType = targetType == null ? "" : targetType.strip().toLowerCase();
        Path common = scripts.resolve("validation-common.sh");
        Path f5 = scripts.resolve("validation-commands-f5.sh");
        Path vm = vmCommandsPath(scripts);
        if ("f5".equals(normalizedType)) {
            return List.of(common, f5);
        }
        if ("vm".equals(normalizedType)) {
            return List.of(common, vm);
        }
        return List.of(common, f5, vm);
    }

    private static Path vmCommandsPath(Path scripts) {
        Path normal = scripts.resolve("validation-commands-vm.sh");
        if (Files.exists(normal)) {
            return normal;
        }
        return scripts.resolve("validation-commnd-vm.sh");
    }

    private static Path repositoryRoot(Path targetsFile) {
        Path current = targetsFile.toAbsolutePath().getParent();
        while (current != null) {
            if (Files.isDirectory(current.resolve("scripts"))) {
                return current;
            }
            current = current.getParent();
        }
        return Path.of(".").toAbsolutePath();
    }

    private static PendingCheck parseLine(String line, PendingCheck pending, Map<String, ValidationCommand> commands) {
        String trimmed = line.trim();
        Matcher matcher = CHECK_MARKER.matcher(trimmed);
        if (matcher.matches()) {
            flushPending(pending, commands);
            return new PendingCheck(matcher.group(1), matcher.group(2) == null ? "" : matcher.group(2).strip(), new StringBuilder());
        }
        if (pending == null || trimmed.startsWith("#!")) {
            return pending;
        }
        if (trimmed.startsWith("#")) {
            return pending;
        }
        if (trimmed.isEmpty() && pending.command().isEmpty()) {
            return pending;
        }
        if (!pending.command().isEmpty()) {
            pending.command().append('\n');
        }
        pending.command().append(line);
        return pending;
    }

    private static void flushPending(PendingCheck pending, Map<String, ValidationCommand> commands) {
        if (pending == null) {
            return;
        }
        String command = pending.command().toString().strip();
        if (!command.isBlank()) {
            commands.put(pending.id(), new ValidationCommand(pending.id(), command, pending.description()));
        }
    }

    private record PendingCheck(String id, String description, StringBuilder command) {
    }
}
