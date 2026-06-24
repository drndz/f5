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
    }
}
