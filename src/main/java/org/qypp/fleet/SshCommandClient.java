package org.qypp.fleet;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

final class SshCommandClient implements AutoCloseable {
    private final Session session;
    private final int commandTimeoutMillis;

    SshCommandClient(String host, String username, String password, int connectTimeoutMillis, int commandTimeoutMillis) {
        try {
            JSch jsch = new JSch();
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

    private CommandResult runResult(String command, String input) {
        CommandResult direct = runResultDirect(command, input);
        if (shouldTryTmshBash(command, direct)) {
            CommandResult viaTmsh = runResultDirect("run util bash -c " + shellQuote(command), input);
            if (viaTmsh.exitStatus() == 0 || (!viaTmsh.stdout().isBlank() && direct.stdout().isBlank())) {
                return viaTmsh;
            }
            CommandResult viaSlashTmsh = runResultDirect("run /util bash -c " + shellQuote(command), input);
            if (viaSlashTmsh.exitStatus() == 0 || (!viaSlashTmsh.stdout().isBlank() && direct.stdout().isBlank())) {
                return viaSlashTmsh;
            }
        }
        return direct;
    }

    private CommandResult runResultDirect(String command, String input) {
        ChannelExec channel = null;
        try {
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
            return new CommandResult(
                    output.toString(StandardCharsets.UTF_8),
                    error.toString(StandardCharsets.UTF_8),
                    channel.getExitStatus()
            );
        } catch (JSchException | InterruptedException exception) {
            if (exception instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return new CommandResult("", "", -1);
        } catch (IOException exception) {
            return new CommandResult("", exception.getMessage(), -1);
        } finally {
            if (channel != null) {
                channel.disconnect();
            }
        }
    }

    private static boolean shouldTryTmshBash(String command, CommandResult result) {
        if (command.startsWith("run util bash ") || command.startsWith("run /util bash ")) {
            return false;
        }
        if (result.exitStatus() == 0 && !looksLikeTmshError(result.stdout()) && !looksLikeTmshError(result.stderr())) {
            return false;
        }
        return result.exitStatus() != 0 || looksLikeTmshError(result.stdout()) || looksLikeTmshError(result.stderr());
    }

    private static boolean looksLikeTmshError(String output) {
        String normalized = output == null ? "" : output.toLowerCase();
        return normalized.contains("syntax error")
                || normalized.contains("unexpected argument")
                || normalized.contains("invalid command")
                || normalized.contains("valid commands")
                || normalized.contains("tmsh");
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    @Override
    public void close() throws IOException {
        session.disconnect();
    }

    private record CommandResult(String stdout, String stderr, int exitStatus) {
    }
}
