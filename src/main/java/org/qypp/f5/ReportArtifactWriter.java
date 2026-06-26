package org.qypp.f5;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class ReportArtifactWriter {
    private static final List<String> DEFAULT_BROWSERS = List.of(
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
    );

    private ReportArtifactWriter() {
    }

    public static void write(Path markdownFile, List<F5Report> reports) throws IOException {
        write(markdownFile, reports, false);
    }

    public static void write(Path markdownFile, List<F5Report> reports, boolean includeCommandDetails) throws IOException {
        String markdown = MarkdownReportWriter.write(reports, includeCommandDetails);
        Files.writeString(markdownFile, markdown);

        Path htmlFile = sibling(markdownFile, ".html");
        Files.writeString(htmlFile, toHtml(markdown));

        Path pdfFile = sibling(markdownFile, ".pdf");
        try {
            printPdf(htmlFile, pdfFile);
            System.out.println("Wrote " + pdfFile.toAbsolutePath());
        } catch (IOException exception) {
            System.out.println("PDF report was not generated: " + exception.getMessage());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            System.out.println("PDF report was not generated: browser print was interrupted.");
        }
    }

    private static Path sibling(Path file, String extension) {
        String name = file.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String base = dot < 0 ? name : name.substring(0, dot);
        return file.resolveSibling(base + extension);
    }

    private static void printPdf(Path htmlFile, Path pdfFile) throws IOException, InterruptedException {
        String browser = browserPath();
        if (browser.isBlank()) {
            throw new IOException("No Chrome or Edge executable found. Set VALIDATION_PDF_BROWSER to enable PDF output.");
        }
        Files.deleteIfExists(pdfFile);
        Process process = new ProcessBuilder(
                browser,
                "--headless",
                "--disable-gpu",
                "--no-pdf-header-footer",
                "--print-to-pdf=" + pdfFile.toAbsolutePath(),
                htmlFile.toAbsolutePath().toUri().toString()
        ).redirectErrorStream(true).start();
        int exitCode = process.waitFor();
        if (exitCode != 0 || !Files.exists(pdfFile)) {
            throw new IOException("Browser PDF print failed with exit code " + exitCode + ".");
        }
    }

    private static String browserPath() {
        String configured = System.getenv("VALIDATION_PDF_BROWSER");
        if (configured != null && !configured.isBlank() && Files.isRegularFile(Path.of(configured))) {
            return configured;
        }
        for (String browser : DEFAULT_BROWSERS) {
            if (Files.isRegularFile(Path.of(browser))) {
                return browser;
            }
        }
        return "";
    }

    private static String toHtml(String markdown) {
        StringBuilder html = new StringBuilder();
        html.append("""
                <!doctype html>
                <html>
                <head>
                  <meta charset="utf-8">
                  <title>Validation Report</title>
                  <style>
                    body { font-family: Arial, sans-serif; color: #111827; margin: 24px; font-size: 12px; background: #f8fafc; }
                    body > h1, body > h2, body > h3, body > p, body > ul { max-width: 1600px; }
                    h1 { font-size: 24px; margin: 0 0 16px; }
                    h2 { font-size: 18px; margin: 22px 0 10px; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; color: #0f172a; }
                    h3 { font-size: 15px; margin: 18px 0 8px; }
                    p { margin: 6px 0; }
                    ul { margin: 6px 0 12px 18px; padding: 0; }
                    li { margin: 3px 0; }
                    .table-wrap { width: 100%; overflow-x: auto; margin: 8px 0 14px; background: #fff; border: 1px solid #cbd5e1; box-shadow: 0 1px 2px rgba(15,23,42,.06); }
                    table { border-collapse: collapse; width: max-content; min-width: 100%; table-layout: auto; }
                    th, td { border: 1px solid #e2e8f0; padding: 0; vertical-align: top; min-width: 72px; max-width: 360px; }
                    .cell-scroll { box-sizing: border-box; max-width: 360px; overflow-x: auto; overflow-y: visible; padding: 6px 8px; white-space: normal; overflow-wrap: anywhere; }
                    th .cell-scroll { max-height: none; white-space: nowrap; }
                    tbody tr:nth-child(even) { background: #f8fafc; }
                    th { background: #e2e8f0; font-weight: 700; position: sticky; top: 0; z-index: 1; }
                    small { font-size: 10px; }
                    code { font-family: Consolas, monospace; background: #f8fafc; padding: 1px 3px; }
                    details { display: block; }
                    @keyframes cert-blink { 50% { opacity: .35; } }
                    @page { size: A4 landscape; margin: 10mm; }
                  </style>
                </head>
                <body>
                """);

        List<String> lines = List.of(markdown.split("\\R", -1));
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank()) {
                continue;
            }
            if (line.startsWith("| ")) {
                List<String> tableLines = new ArrayList<>();
                while (i < lines.size() && lines.get(i).startsWith("| ")) {
                    tableLines.add(lines.get(i++));
                }
                i--;
                appendTable(html, tableLines);
            } else if (line.startsWith("### ")) {
                html.append("<h3>").append(escapeHtml(line.substring(4))).append("</h3>\n");
            } else if (line.startsWith("## ")) {
                html.append("<h2>").append(escapeHtml(line.substring(3))).append("</h2>\n");
            } else if (line.startsWith("# ")) {
                html.append("<h1>").append(escapeHtml(line.substring(2))).append("</h1>\n");
            } else if (line.startsWith("- ")) {
                html.append("<ul>\n");
                while (i < lines.size() && lines.get(i).startsWith("- ")) {
                    html.append("<li>").append(inlineMarkdown(lines.get(i).substring(2))).append("</li>\n");
                    i++;
                }
                i--;
                html.append("</ul>\n");
            } else if (line.startsWith("<")) {
                html.append(line).append("\n");
            } else {
                html.append("<p>").append(inlineMarkdown(line)).append("</p>\n");
            }
        }

        html.append("</body>\n</html>\n");
        return html.toString();
    }

    private static void appendTable(StringBuilder html, List<String> tableLines) {
        if (tableLines.isEmpty()) {
            return;
        }
        html.append("<div class=\"table-wrap\"><table>\n");
        List<String> headers = tableCells(tableLines.get(0));
        html.append("<thead><tr>");
        for (String header : headers) {
            html.append("<th><div class=\"cell-scroll\">").append(inlineMarkdown(header)).append("</div></th>");
        }
        html.append("</tr></thead>\n<tbody>\n");
        for (int i = 2; i < tableLines.size(); i++) {
            html.append("<tr>");
            for (String cell : tableCells(tableLines.get(i))) {
                html.append("<td><div class=\"cell-scroll\">").append(inlineMarkdown(cell)).append("</div></td>");
            }
            html.append("</tr>\n");
        }
        html.append("</tbody>\n</table></div>\n");
    }

    private static List<String> tableCells(String line) {
        String trimmed = line.strip();
        if (trimmed.startsWith("|")) {
            trimmed = trimmed.substring(1);
        }
        if (trimmed.endsWith("|")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        List<String> cells = new ArrayList<>();
        for (String cell : trimmed.split("(?<!\\\\)\\|", -1)) {
            cells.add(cell.strip().replace("\\|", "|"));
        }
        return cells;
    }

    private static String inlineMarkdown(String value) {
        if (value.contains("<span") || value.contains("<small") || value.contains("<strong") || value.contains("<br")
                || value.contains("<details") || value.contains("<div") || value.contains("<svg")) {
            return value;
        }
        return escapeHtml(value).replace("`", "");
    }

    private static String escapeHtml(String value) {
        return value == null ? "" : value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
