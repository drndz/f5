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
import java.util.Properties;

final class SshCommandClient implements AutoCloseable {
    private final Session session;
    private final String host;
    private final String username;
    private final int commandTimeoutMillis;
    private final boolean allowTmshFallback;
    private final BufferedReader confirmationReader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    private final boolean approveAllCommands = Boolean.parseBoolean(System.getenv().getOrDefault("SSH_APPROVE_ALL_COMMANDS", "false"));
    private boolean preferTmshBash;

    SshCommandClient(String host, String username, String password, int connectTimeoutMillis, int commandTimeoutMillis, boolean allowTmshFallback) {
        try {
            JSch jsch = new JSch();
            this.host = host;
            this.username = username;
            this.allowTmshFallback = allowTmshFallback;
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

    String run(String command, String input) {
        CommandResult result = runResult(command, input);
        if (!result.stdout().isBlank()) {
            return result.stdout().strip();
        }
        return result.stderr().strip();
    }

    boolean succeeds(String command, String input) {
        return runResult(command, input).exitStatus() == 0;
    }

    boolean detectF5TmshShell() {
        if (!allowTmshFallback) {
            return false;
        }
        CommandResult viaTmsh = runResultDirect("run util bash -c " + tmshDoubleQuote("cat /etc/issue 2>/dev/null || true"), "");
        if (looksLikeBigIp(viaTmsh.stdout())) {
            preferTmshBash = true;
            return true;
        }
        CommandResult viaSlashTmsh = runResultDirect("run /util bash -c " + tmshDoubleQuote("cat /etc/issue 2>/dev/null || true"), "");
        if (looksLikeBigIp(viaSlashTmsh.stdout())) {
            preferTmshBash = true;
            return true;
        }
        return false;
    }

    private CommandResult runResult(String command, String input) {
        if (allowTmshFallback && preferTmshBash && !isTmshBashCommand(command)) {
            CommandResult preferred = runViaTmshBash(command, input);
            if (preferred.exitStatus() == 0 || !preferred.stdout().isBlank()) {
                return preferred;
            }
        }
        CommandResult direct = runResultDirect(command, input);
        if (allowTmshFallback && shouldTryTmshBash(command, direct)) {
            CommandResult viaTmsh = runViaTmshBash(command, input);
            if (viaTmsh.exitStatus() == 0 || (!viaTmsh.stdout().isBlank() && direct.stdout().isBlank())) {
                return viaTmsh;
            }
            CommandResult viaLegacyTmsh = runResultDirect("run util bash -c " + shellQuote(command), input);
            if (viaLegacyTmsh.exitStatus() == 0 || (!viaLegacyTmsh.stdout().isBlank() && direct.stdout().isBlank())) {
                preferTmshBash = true;
                return viaLegacyTmsh;
            }
        }
        return direct;
    }

    private CommandResult runViaTmshBash(String command, String input) {
        CommandResult viaTmsh = runResultDirect("run util bash -c " + shellQuote(command), input);
        if (viaTmsh.exitStatus() == 0 || !viaTmsh.stdout().isBlank()) {
            preferTmshBash = true;
            return viaTmsh;
        }
        CommandResult viaSlashTmsh = runResultDirect("run /util bash -c " + shellQuote(command), input);
        if (viaSlashTmsh.exitStatus() == 0 || !viaSlashTmsh.stdout().isBlank()) {
            preferTmshBash = true;
            return viaSlashTmsh;
        }
        CommandResult viaDoubleQuotedTmsh = runResultDirect("run util bash -c " + tmshDoubleQuote(command), input);
        if (viaDoubleQuotedTmsh.exitStatus() == 0 || !viaDoubleQuotedTmsh.stdout().isBlank()) {
            preferTmshBash = true;
            return viaDoubleQuotedTmsh;
        }
        return viaTmsh;
    }

    private CommandResult runResultDirect(String command, String input) {
        ChannelExec channel = null;
        try {
            confirmCommand(command);
            channel = (ChannelExec) session.openChannel("exec");
            channel.setCommand(command);
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
            printCommandResult(command, result);
            return result;
        } catch (JSchException | InterruptedException exception) {
            if (exception instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            CommandResult result = new CommandResult("", exception.getMessage(), -1);
            printCommandResult(command, result);
            return result;
        } catch (IOException exception) {
            CommandResult result = new CommandResult("", exception.getMessage(), -1);
            printCommandResult(command, result);
            return result;
        } finally {
            if (channel != null) {
                channel.disconnect();
            }
        }
    }

    private void confirmCommand(String command) throws IOException {
        System.err.println();
        System.err.println("About to run SSH command on " + username + "@" + host + ":");
        System.err.println(command);
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

    private void printCommandResult(String command, CommandResult result) {
        System.err.println("SSH command completed on " + username + "@" + host + " with exit status " + result.exitStatus() + ":");
        System.err.println(command);
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

    private static boolean looksLikeTmshError(String output) {
        String normalized = output == null ? "" : output.toLowerCase();
        return normalized.contains("syntax error")
                || normalized.contains("unexpected argument")
                || normalized.contains("invalid command")
                || normalized.contains("valid commands")
                || normalized.contains("use tmos shell utility")
                || normalized.contains("system configuration")
                || normalized.contains("tmsh");
    }

    private static boolean looksLikeBigIp(String output) {
        return output != null && output.toLowerCase().contains("big-ip");
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    private static String tmshDoubleQuote(String value) {
        return "\"" + value
                .replace("\"", "\\\"")
                .replace("\n", " ")
                .replace("\r", " ")
                + "\"";
    }

    @Override
    public void close() throws IOException {
        session.disconnect();
    }

    private record CommandResult(String stdout, String stderr, int exitStatus) {
    }
}
