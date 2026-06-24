package org.qypp;

import org.qypp.f5.F5Report;
import org.qypp.f5.F5ReportParser;
import org.qypp.f5.ReportArtifactWriter;
import org.qypp.fleet.FleetSshValidator;
import org.qypp.fleet.PasswordCrypto;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class Main {
    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            usage();
            System.exit(2);
        }

        switch (args[0]) {
            case "report" -> generateReport(args);
            case "fleet" -> runFleet(args);
            case "encrypt-password" -> encryptPassword(args);
            case "decrypt-password" -> decryptPassword(args);
            default -> {
                if (args[0].equals("--input-dir")) {
                    generateReport(args);
                } else {
                    usage();
                    System.exit(2);
                }
            }
        }
    }

    private static void runFleet(String[] args) throws IOException {
        if (args.length < 2) {
            usage();
            System.exit(2);
        }
        Path targetsFile = Path.of(args[1]);
        Path outputDir = args.length >= 3 ? Path.of(args[2]) : Path.of("f5-validation-results");
        FleetSshValidator.run(targetsFile, outputDir, masterKey());
    }

    private static void generateReport(String[] args) throws IOException {
        int inputIndex = args[0].equals("report") ? 1 : 0;
        if (args.length < inputIndex + 2 || !args[inputIndex].equals("--input-dir")) {
            usage();
            System.exit(2);
        }

        Path inputDir = Path.of(args[inputIndex + 1]);
        Path output = Path.of("validation-report-" + safeTimestamp(Instant.now().toString()) + ".md");
        for (int i = inputIndex + 2; i < args.length; i++) {
            if (args[i].equals("--output") && i + 1 < args.length) {
                output = Path.of(args[++i]);
            }
        }

        List<F5Report> reports = new ArrayList<>();
        try (Stream<Path> files = Files.list(inputDir)) {
            for (Path file : files.filter(path -> path.getFileName().toString().endsWith(".json")).toList()) {
                reports.add(F5ReportParser.parse(Files.readString(file)));
            }
        }

        ReportArtifactWriter.write(output, reports);
        System.out.println("Wrote " + output.toAbsolutePath());
    }

    private static void encryptPassword(String[] args) {
        if (args.length != 1 && args.length != 2) {
            usage();
            System.exit(2);
        }
        String plainPassword;
        if (args.length == 2) {
            plainPassword = args[1];
        } else {
            Console console = System.console();
            if (console == null) {
                throw new IllegalStateException("No interactive console is available. Pass the password as an argument for non-interactive use.");
            }
            plainPassword = new String(console.readPassword("Password to encrypt: "));
        }
        System.out.println(PasswordCrypto.encrypt(plainPassword, masterKey()));
    }

    private static void decryptPassword(String[] args) {
        if (args.length != 2) {
            usage();
            System.exit(2);
        }
        System.out.println(PasswordCrypto.decrypt(args[1], masterKey()));
    }

    private static String masterKey() {
        String masterKey = System.getenv("F5_MASTER_KEY");
        if (masterKey != null && !masterKey.isBlank()) {
            return masterKey.strip();
        }
        Path keyFile = Path.of("config", ".F5_MASTER_KEY");
        if (Files.isRegularFile(keyFile)) {
            try {
                masterKey = Files.readString(keyFile).strip();
            } catch (IOException exception) {
                throw new IllegalStateException("Could not read " + keyFile + ".", exception);
            }
            if (!masterKey.isBlank()) {
                return masterKey;
            }
        }
        throw new IllegalStateException("Master key is required. Create config/.F5_MASTER_KEY locally; it is ignored by git and must not be committed.");
    }

    private static void usage() {
        System.err.println("""
                Usage:
                  java -cp build/classes org.qypp.Main report --input-dir <json-dir> [--output report.md]
                  java -cp build/classes:lib/* org.qypp.Main fleet <targets.csv> [output-dir]
                  java -cp build/classes org.qypp.Main encrypt-password [plain-password]
                  java -cp build/classes org.qypp.Main decrypt-password <encrypted-password>
                """);
    }

    private static String safeTimestamp(String value) {
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
    }
}
