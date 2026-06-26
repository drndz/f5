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
        Path targetsFile = null;
        Path outputDir = null;
        boolean detailsSsh = false;
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("--details-ssh")) {
                detailsSsh = true;
            } else if (targetsFile == null) {
                targetsFile = Path.of(args[i]);
            } else if (outputDir == null) {
                outputDir = Path.of(args[i]);
            } else {
                usage();
                System.exit(2);
            }
        }
        if (targetsFile == null) {
            targetsFile = effectiveConfigDir().resolve("f5-targets.csv");
        }
        if (outputDir == null) {
            outputDir = Path.of("f5-validation-results");
        }
        FleetSshValidator.run(targetsFile, outputDir, optionalMasterKey(), detailsSsh);
    }

    private static void generateReport(String[] args) throws IOException {
        int inputIndex = args[0].equals("report") ? 1 : 0;
        if (args.length < inputIndex + 2 || !args[inputIndex].equals("--input-dir")) {
            usage();
            System.exit(2);
        }

        Path inputDir = Path.of(args[inputIndex + 1]);
        Path output = Path.of("validation-report-" + safeTimestamp(Instant.now().toString()) + ".md");
        boolean details = false;
        for (int i = inputIndex + 2; i < args.length; i++) {
            if (args[i].equals("--output") && i + 1 < args.length) {
                output = Path.of(args[++i]);
            } else if (args[i].equals("--details-report")) {
                details = true;
            } else {
                usage();
                System.exit(2);
            }
        }

        List<F5Report> reports = new ArrayList<>();
        try (Stream<Path> files = Files.list(inputDir)) {
            for (Path file : files.filter(path -> path.getFileName().toString().endsWith(".json")).toList()) {
                reports.add(F5ReportParser.parse(Files.readString(file)));
            }
        }

        ReportArtifactWriter.write(output, reports, details);
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
        return masterKey(true);
    }

    private static String optionalMasterKey() {
        return masterKey(false);
    }

    private static String masterKey(boolean required) {
        String masterKey = System.getenv("MASTER_KEY");
        if (masterKey != null && !masterKey.isBlank()) {
            return masterKey.strip();
        }
        Path configDir = effectiveConfigDir();
        Path keyFile = configDir.resolve(".MASTER_KEY");
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
        if (!required) {
            return "";
        }
        throw new IllegalStateException("Master key is required. Create " + configDir.resolve(".MASTER_KEY") + " locally; it is ignored by git and must not be committed.");
    }

    private static Path effectiveConfigDir() {
        Path selectorFile = Path.of("config", ".conf_effective");
        String selected = "real";
        if (Files.isRegularFile(selectorFile)) {
            try (Stream<String> lines = Files.lines(selectorFile)) {
                selected = lines
                        .map(String::strip)
                        .filter(line -> !line.isBlank())
                        .filter(line -> !line.startsWith("#"))
                        .findFirst()
                        .orElse("real");
            } catch (IOException exception) {
                throw new IllegalStateException("Could not read " + selectorFile + ".", exception);
            }
        }
        Path selectedPath = Path.of(selected);
        if (selectedPath.isAbsolute()) {
            return selectedPath;
        }
        return Path.of("config").resolve(selectedPath);
    }

    private static void usage() {
        System.err.println("""
                Usage:
                  java -cp build/classes org.qypp.Main report --input-dir <json-dir> [--output report.md] [--details-report]
                  java -cp build/classes:lib/* org.qypp.Main fleet [targets.csv] [output-dir] [--details-ssh]
                  java -cp build/classes org.qypp.Main encrypt-password [plain-password]
                  java -cp build/classes org.qypp.Main decrypt-password <encrypted-password>
                """);
    }

    private static String safeTimestamp(String value) {
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
    }
}
