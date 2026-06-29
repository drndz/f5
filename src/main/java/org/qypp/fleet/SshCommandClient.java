package org.qypp.fleet;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

import java.io.ByteArrayOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

final class SshCommandClient implements AutoCloseable {
    private final Session session;
    private final String host;
    private final String username;
    private final int commandTimeoutMillis;
    private final boolean allowTmshFallback;
    private final BufferedReader confirmationReader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    private final boolean approveAllCommands = Boolean.parseBoolean(System.getenv().getOrDefault("SSH_APPROVE_ALL_COMMANDS", "false"));
    private final boolean logCommandOutput = Boolean.parseBoolean(System.getenv().getOrDefault("SSH_LOG_COMMAND_OUTPUT", "false"));
    private final boolean logCommandBody;
    private final List<String> commandTimingRows = new ArrayList<>();
    private boolean preferTmshBash;

    SshCommandClient(String host, String username, String password, int connectTimeoutMillis, int commandTimeoutMillis, boolean allowTmshFallback, boolean logCommandBody) {
        try {
            JSch jsch = new JSch();
            this.host = host;
            this.username = username;
            this.allowTmshFallback = allowTmshFallback;
            this.logCommandBody = logCommandBody;
            this.session = jsch.getSession(username, host, 22);
            this.session.setPassword(password);
            Properties config = new Properties();
            config.put("StrictHostKeyChecking", System.getenv().getOrDefault("SSH_STRICT_HOST_KEY_CHECKING", "no"));
            this.session.setConfig(config);
            this.session.connect(connectTimeoutMillis);
            this.commandTimeoutMillis = commandTimeoutMillis;
        } catch (JSchException exception) {
            throw new IllegalStateException("Could not connect over SSH: " + exception.getMessage(), exception);
        }
    }

    String run(String command) {
        return run(command, "");
    }

    String run(ValidationCommand command) {
        return run(command, "");
    }

    String run(ValidationCommand command, String input) {
        CommandResult result = runResult(command, input);
        if (!result.stdout().isBlank()) {
            return result.stdout().strip();
        }
        return result.stderr().strip();
    }

    String run(String command, String input) {
        CommandResult result = runResult(new ValidationCommand("ADHOC", command), input);
        if (!result.stdout().isBlank()) {
            return result.stdout().strip();
        }
        return result.stderr().strip();
    }

    boolean succeeds(ValidationCommand command, String input) {
        return runResult(command, input).exitStatus() == 0;
    }

    boolean succeeds(String command, String input) {
        return runResult(new ValidationCommand("ADHOC", command), input).exitStatus() == 0;
    }

    List<String> commandTimingRows() {
        return List.copyOf(commandTimingRows);
    }

    boolean detectF5TmshShell(ValidationCommand probeCommand) {
        if (!allowTmshFallback) {
            return false;
        }
        CommandResult viaTmsh = runResultDirect(tmshBashCommand(probeCommand, "run util bash"), probeCommand.command(), probeCommand.command());
        if (looksLikeBigIp(viaTmsh.stdout())) {
            preferTmshBash = true;
            return true;
        }
        CommandResult viaSlashTmsh = runResultDirect(tmshBashCommand(probeCommand, "run /util bash"), probeCommand.command(), probeCommand.command());
        if (looksLikeBigIp(viaSlashTmsh.stdout())) {
            preferTmshBash = true;
            return true;
        }
        return false;
    }

    private CommandResult runResult(ValidationCommand command, String input) {
        if (allowTmshFallback && preferTmshBash && !isTmshBashCommand(command.command())) {
            CommandResult preferred = runViaTmshBash(command, input);
            if (hasUsableOutput(preferred)) {
                return preferred;
            }
            CommandResult direct = runResultDirect(command, input);
            if (!direct.stdout().isBlank() || direct.exitStatus() == 0) {
                return direct;
            }
            if (preferred.exitStatus() == 0) {
                return preferred;
            }
            return direct;
        }
        CommandResult direct = runResultDirect(command, input);
        if (allowTmshFallback && shouldTryTmshBash(command.command(), direct)) {
            CommandResult viaTmsh = runViaTmshBash(command, input);
            if (hasUsableOutput(viaTmsh)) {
                return viaTmsh;
            }
            CommandResult viaLegacyTmsh = runResultDirect(tmshBashCommand(command, "run /util bash"), stdinScript(command.command(), input), command.command());
            if (hasUsableOutput(viaLegacyTmsh)) {
                preferTmshBash = true;
                return viaLegacyTmsh;
            }
        }
        return direct;
    }

    private CommandResult runViaTmshBash(ValidationCommand command, String input) {
        CommandResult viaTmsh = runResultDirect(tmshBashCommand(command, "run util bash"), stdinScript(command.command(), input), command.command());
        if (hasUsableOutput(viaTmsh)) {
            preferTmshBash = true;
            return viaTmsh;
        }
        CommandResult viaSlashTmsh = runResultDirect(tmshBashCommand(command, "run /util bash"), stdinScript(command.command(), input), command.command());
        if (hasUsableOutput(viaSlashTmsh)) {
            preferTmshBash = true;
            return viaSlashTmsh;
        }
        return viaTmsh;
    }

    private CommandResult runResultDirect(ValidationCommand command, String input) {
        return runResultDirect(command, input, command.command());
    }

    private CommandResult runResultDirect(ValidationCommand command, String input, String previewCommand) {
        ChannelExec channel = null;
        long started = System.nanoTime();
        try {
            confirmCommand(command, previewCommand);
            channel = (ChannelExec) session.openChannel("exec");
            channel.setCommand(command.command());
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            ByteArrayOutputStream error = new ByteArrayOutputStream();
            channel.setOutputStream(output);
            channel.setErrStream(error);
            OutputStream stdin = channel.getOutputStream();
            channel.connect(commandTimeoutMillis);
            if (input != null && !input.isEmpty()) {
                stdin.write(input.getBytes(StandardCharsets.UTF_8));
            }
            stdin.close();
            while (!channel.isClosed()) {
                Thread.sleep(50);
            }
            CommandResult result = new CommandResult(
                    output.toString(StandardCharsets.UTF_8),
                    error.toString(StandardCharsets.UTF_8),
                    channel.getExitStatus()
            );
            recordCommandTiming(command, result, started);
            printCommandResult(command, previewCommand, result);
            return result;
        } catch (JSchException | InterruptedException exception) {
            if (exception instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            CommandResult result = new CommandResult("", exception.getMessage(), -1);
            recordCommandTiming(command, result, started);
            printCommandResult(command, previewCommand, result);
            return result;
        } catch (IOException exception) {
            CommandResult result = new CommandResult("", exception.getMessage(), -1);
            recordCommandTiming(command, result, started);
            printCommandResult(command, previewCommand, result);
            return result;
        } finally {
            if (channel != null) {
                channel.disconnect();
            }
        }
    }

    private void recordCommandTiming(ValidationCommand command, CommandResult result, long started) {
        long elapsedMillis = Math.max(0, (System.nanoTime() - started) / 1_000_000L);
        commandTimingRows.add(command.label() + "|" + elapsedMillis + "|" + result.exitStatus() + "|" + oneLine(command.description()) + "|" + oneLine(command.command()));
    }

    private void confirmCommand(ValidationCommand command, String previewCommand) throws IOException {
        System.err.println();
        System.err.println("About to run SSH command [" + command.label() + "] on " + username + "@" + host + ":");
        System.err.println(commandSummary(command));
        if (logCommandBody || !approveAllCommands) {
            System.err.println(previewCommand);
        }
        if (approveAllCommands) {
            System.err.println("Auto-approved by SSH_APPROVE_ALL_COMMANDS=true.");
            return;
        }
        System.err.print("Type Y to run this command: ");
        String answer = confirmationReader.readLine();
        if (!"Y".equals(answer) && !"YES".equals(answer)) {
            throw new IllegalStateException("SSH command was not confirmed by operator.");
        }
    }

    private void printCommandResult(ValidationCommand command, String previewCommand, CommandResult result) {
        System.err.println("SSH command [" + command.label() + "] completed on " + username + "@" + host + " with exit status " + result.exitStatus() + ".");
        if (!logCommandOutput && !logCommandBody) {
            return;
        }
        if (logCommandBody) {
            System.err.println("--- command ---");
            System.err.println(previewCommand);
            if (!previewCommand.equals(command.command())) {
                System.err.println("--- ssh wrapper ---");
                System.err.println(command.command());
            }
        } else {
            System.err.println(commandSummary(command));
        }
        if (!result.stdout().isBlank()) {
            System.err.println("--- stdout ---");
            System.err.println(result.stdout().strip());
        }
        if (!result.stderr().isBlank()) {
            System.err.println("--- stderr ---");
            System.err.println(result.stderr().strip());
        }
        if (result.stdout().isBlank() && result.stderr().isBlank()) {
            System.err.println("--- no output ---");
        }
    }

    private static String commandSummary(ValidationCommand command) {
        List<String> values = new ArrayList<>();
        if (command.description() != null && !command.description().isBlank()) {
            values.add(command.description());
        }
        String arguments = commandArguments(command.command());
        if (!arguments.isBlank()) {
            values.add("arguments: " + arguments);
        }
        return values.isEmpty() ? "(no description)" : String.join("; ", values);
    }

    private static String commandArguments(String command) {
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

    private static boolean shouldTryTmshBash(String command, CommandResult result) {
        if (isTmshBashCommand(command)) {
            return false;
        }
        if (result.exitStatus() == 0 && !looksLikeTmshError(result.stdout()) && !looksLikeTmshError(result.stderr())) {
            return false;
        }
        return result.exitStatus() != 0 || looksLikeTmshError(result.stdout()) || looksLikeTmshError(result.stderr());
    }

    private static boolean isTmshBashCommand(String command) {
        return command.startsWith("run util bash ") || command.startsWith("run /util bash ");
    }

    private static boolean hasUsableOutput(CommandResult result) {
        return result.exitStatus() == 0
                && !result.stdout().isBlank()
                && !looksLikeTmshError(result.stdout())
                && !looksLikeTmshError(result.stderr());
    }

    private static boolean looksLikeTmshError(String output) {
        String normalized = output == null ? "" : output.toLowerCase();
        return normalized.contains("syntax error")
                || normalized.contains("unexpected argument")
                || normalized.contains("invalid command")
                || normalized.contains("valid commands")
                || normalized.contains("use tmos shell utility")
                || normalized.contains("system configuration")
                || normalized.contains("syntax error:");
    }

    private static boolean looksLikeBigIp(String output) {
        return output != null && output.toLowerCase().contains("big-ip");
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    private static String stdinScript(String command, String input) {
        if (input == null || input.isEmpty()) {
            return command + "\n";
        }
        return command + "\n" + input;
    }

    private static ValidationCommand tmshBashCommand(ValidationCommand command, String tmshRunPrefix) {
        return new ValidationCommand(command.id(), tmshRunPrefix + " -c " + shellQuote("bash -s"), command.description());
    }

    private static String oneLine(String value) {
        String normalized = value == null ? "" : value.replace("\r", " ").replace("\n", " ").strip();
        return normalized;
    }

    @Override
    public void close() throws IOException {
        session.disconnect();
    }

    private record CommandResult(String stdout, String stderr, int exitStatus) {
    }
}
