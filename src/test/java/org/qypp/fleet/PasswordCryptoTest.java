package org.qypp.fleet;

public final class PasswordCryptoTest {
    private PasswordCryptoTest() {
    }

    public static void encryptsAndDecryptsPassword() {
        String masterKey = "long-test-master-key";
        String encrypted = PasswordCrypto.encrypt("secret-password", masterKey);
        if (!encrypted.startsWith("v1:")) {
            throw new AssertionError("Encrypted value should include version prefix.");
        }
        String decrypted = PasswordCrypto.decrypt(encrypted, masterKey);
        if (!"secret-password".equals(decrypted)) {
            throw new AssertionError("Password did not decrypt to original value.");
        }
        if (!"plain-password".equals(PasswordCrypto.decryptOrPlain("plain-password", ""))) {
            throw new AssertionError("Plain password values should be used without a master key.");
        }
        if (!"secret-password".equals(PasswordCrypto.decryptOrPlain(encrypted, masterKey))) {
            throw new AssertionError("Encrypted password values should decrypt through decryptOrPlain.");
        }
    }
}
