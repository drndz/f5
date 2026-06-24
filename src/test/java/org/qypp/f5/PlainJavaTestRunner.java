package org.qypp.f5;

public class PlainJavaTestRunner {
    public static void main(String[] args) {
        new F5ReportParserTest().parsesCollectorOutput();
        new MarkdownReportWriterTest().writesUnifiedMarkdownForMultipleDevices();
        org.qypp.fleet.PasswordCryptoTest.encryptsAndDecryptsPassword();
        System.out.println("All plain Java tests passed.");
    }
}
