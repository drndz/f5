package org.qypp.fleet;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

public final class PasswordCrypto {
    private static final String PREFIX = "v1:";
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int KEY_BITS = 256;
    private static final int PBKDF2_ITERATIONS = 210_000;

    private PasswordCrypto() {
    }

    public static String encrypt(String plainText, String masterKey) {
        requireMasterKey(masterKey);
        try {
            SecureRandom random = new SecureRandom();
            byte[] salt = randomBytes(random, SALT_BYTES);
            byte[] iv = randomBytes(random, IV_BYTES);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key(masterKey, salt), new GCMParameterSpec(TAG_BITS, iv));
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            ByteBuffer buffer = ByteBuffer.allocate(salt.length + iv.length + cipherText.length);
            buffer.put(salt);
            buffer.put(iv);
            buffer.put(cipherText);
            return PREFIX + Base64.getEncoder().encodeToString(buffer.array());
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Could not encrypt password.", exception);
        }
    }

    public static String decrypt(String encryptedText, String masterKey) {
        requireMasterKey(masterKey);
        if (!encryptedText.startsWith(PREFIX)) {
            throw new IllegalArgumentException("Unsupported encrypted password format.");
        }
        try {
            byte[] payload = Base64.getDecoder().decode(encryptedText.substring(PREFIX.length()));
            if (payload.length <= SALT_BYTES + IV_BYTES) {
                throw new IllegalArgumentException("Encrypted password payload is too short.");
            }
            byte[] salt = new byte[SALT_BYTES];
            byte[] iv = new byte[IV_BYTES];
            byte[] cipherText = new byte[payload.length - SALT_BYTES - IV_BYTES];
            ByteBuffer buffer = ByteBuffer.wrap(payload);
            buffer.get(salt);
            buffer.get(iv);
            buffer.get(cipherText);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(masterKey, salt), new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException("Could not decrypt password. Check the master key and encrypted value.", exception);
        }
    }

    public static String decryptOrPlain(String value, String masterKey) {
        if (value == null || !value.startsWith(PREFIX)) {
            return value == null ? "" : value;
        }
        if (masterKey == null || masterKey.isBlank()) {
            throw new IllegalArgumentException("Master key is required only for encrypted password values with the v1: prefix.");
        }
        return decrypt(value, masterKey);
    }

    private static SecretKeySpec key(String masterKey, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(masterKey.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_BITS);
        byte[] encoded = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }

    private static byte[] randomBytes(SecureRandom random, int count) {
        byte[] bytes = new byte[count];
        random.nextBytes(bytes);
        return bytes;
    }

    private static void requireMasterKey(String masterKey) {
        if (masterKey == null || masterKey.length() < 12) {
            throw new IllegalArgumentException("Master key must be at least 12 characters.");
        }
    }
}
