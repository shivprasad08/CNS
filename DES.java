import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

/**
 * A menu-driven Java program to demonstrate DES encryption and decryption.
 * This program uses the Java Cryptography Extension (JCE).
 */
public class DES {

    // Define the algorithm and transformation for DES.
    // ECB (Electronic Codebook) is a simple mode, good for demonstration.
    // PKCS5Padding is used to handle blocks of data that are not a multiple of 8
    // bytes.
    private static final String ALGORITHM = "DES";
    private static final String TRANSFORMATION = "DES/ECB/PKCS5Padding";

    /**
     * Encrypts a given plaintext string using a key.
     * 
     * @param value The string to be encrypted.
     * @param key   The encryption key (must be 8 characters long).
     * @return The Base64 encoded encrypted string.
     * @throws Exception if encryption fails.
     */
    public static String encrypt(String value, String key) throws Exception {
        // DES key must be 8 bytes (64 bits).
        if (key.length() != 8) {
            throw new IllegalArgumentException("Invalid key size. Key must be 8 characters long.");
        }

        // Create a secret key specification from the key bytes.
        SecretKey secretKey = new SecretKeySpec(key.getBytes("UTF-8"), ALGORITHM);

        // Get a Cipher instance for the specified transformation.
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        // Initialize the cipher for encryption mode with the secret key.
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Perform the encryption.
        byte[] encryptedByteValue = cipher.doFinal(value.getBytes("UTF-8"));

        // Encode the encrypted bytes to a Base64 string for easy transport.
        return Base64.getEncoder().encodeToString(encryptedByteValue);
    }

    /**
     * Decrypts a given Base64 encoded string using a key.
     * 
     * @param value The Base64 encoded string to be decrypted.
     * @param key   The decryption key (must be 8 characters long).
     * @return The original decrypted string.
     * @throws Exception if decryption fails.
     */
    public static String decrypt(String value, String key) throws Exception {
        // DES key must be 8 bytes (64 bits).
        if (key.length() != 8) {
            throw new IllegalArgumentException("Invalid key size. Key must be 8 characters long.");
        }

        // Create a secret key specification from the key bytes.
        SecretKey secretKey = new SecretKeySpec(key.getBytes("UTF-8"), ALGORITHM);

        // Get a Cipher instance for the specified transformation.
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        // Initialize the cipher for decryption mode with the secret key.
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        // Decode the Base64 string to get the encrypted bytes.
        byte[] decryptedByteValue = Base64.getDecoder().decode(value);

        // Perform the decryption.
        byte[] originalByteValue = cipher.doFinal(decryptedByteValue);

        // Convert the decrypted bytes back to a string.
        return new String(originalByteValue, "UTF-8");
    }

    /**
     * The main method to run the menu-driven application.
     * 
     * @param args Command line arguments (not used).
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        int choice = 0;

        do {
            System.out.println("\n--- DES Encryption/Decryption Menu ---");
            System.out.println("1. Encrypt a message");
            System.out.println("2. Decrypt a message");
            System.out.println("3. Exit");
            System.out.print("Enter your choice: ");

            try {
                // Read the whole line and parse it to an integer to avoid scanner issues.
                choice = Integer.parseInt(scanner.nextLine());
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter a number.");
                continue; // Skip the rest of the loop and show the menu again.
            }

            switch (choice) {
                case 1:
                    try {
                        System.out.print("Enter the message to encrypt: ");
                        String plainText = scanner.nextLine();
                        System.out.print("Enter an 8-character key: ");
                        String key = scanner.nextLine();

                        String encryptedText = encrypt(plainText, key);
                        System.out.println("Encrypted Message: " + encryptedText);
                    } catch (Exception e) {
                        System.err.println("Encryption failed: " + e.getMessage());
                    }
                    break;
                case 2:
                    try {
                        System.out.print("Enter the Base64 encrypted message to decrypt: ");
                        String encryptedText = scanner.nextLine();
                        System.out.print("Enter the 8-character key: ");
                        String key = scanner.nextLine();

                        String decryptedText = decrypt(encryptedText, key);
                        System.out.println("Decrypted Message: " + decryptedText);
                    } catch (Exception e) {
                        System.err.println("Decryption failed: " + e.getMessage());
                    }
                    break;
                case 3:
                    System.out.println("Exiting...");
                    break;
                default:
                    System.out.println("Invalid choice. Please enter 1, 2, or 3.");
                    break;
            }
        } while (choice != 3);

        scanner.close();
    }
}
