import java.io.*;
import java.sql.*;
import java.sql.Date;
import java.text.SimpleDateFormat;
import java.util.*;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import java.security.SecureRandom;
import java.security.MessageDigest;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;

import db.DatabaseManager;
import db.WalletRepository;
import wallet.Wallet;
import wallet.BitcoinWallet;
import wallet.MnemonicService;

public class MainApp {
    private static final Logger logger = LogManager.getLogger(MainApp.class);
    
    private static void register(String email, char[] password) {
        String hashed = hashPassword(new String(password));
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        Date date = new Date(timestamp.getTime());
        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy' 'HH:mm:ss");
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE email = ?")) {
            pstmt.setString(1, email);
            ResultSet rs = pstmt.executeQuery();
            if (!rs.next()) {
                try (PreparedStatement pstmt_ = conn.prepareStatement(
                        "INSERT INTO users(email, password_hash, created_date) VALUES (?, ?, ?)",
                        Statement.RETURN_GENERATED_KEYS)) {
                    pstmt_.setString(1, email);
                    pstmt_.setString(2, hashed);
                    pstmt_.setString(3, sdf.format(date));
                    pstmt_.executeUpdate();

                    ResultSet rs_ = pstmt_.getGeneratedKeys();
                    if (rs_.next()) {
                        int userId = rs_.getInt(1);
                        BitcoinWallet btcWallet = new BitcoinWallet(hashed);
                        String seedPhrase = btcWallet.getSeedPhrase();
                        byte[] encryptedPrivKeyBytes = btcWallet.getEncryptedBytes();
                        byte[] encryptedPrivKeyIvector = btcWallet.getEncryptedIvector();
                        WalletRepository.saveWallet(userId, btcWallet, seedPhrase,
                        encryptedPrivKeyBytes,encryptedPrivKeyIvector);
                        logger.info("Registration successful!");
                        logger.info("Seed phrase for account recovery: " + seedPhrase);
                    }
                } catch (SQLException e) {
                    logger.error("Error: " + e.getMessage());
                }
            } else {
                logger.warn("Email is already registered!");
            }
        } catch (SQLException e) {
            logger.error("Error: " + e.getMessage());
        }
    }

    private static Integer loginCred(String email) {
        Console cnsl = System.console();
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt = conn
                        .prepareStatement("SELECT id, password_hash FROM users WHERE email = ?")) {
            pstmt.setString(1, email);
            ResultSet rs = pstmt.executeQuery();
            if (!rs.next()) {
                logger.warn("Invalid user, either you entered wrong email or the user is not registered");
                return null;
            }
            int userId = rs.getInt("id");
            for (int attempt = 1; attempt <= 3; attempt++) {
                char[] password = cnsl.readPassword("Password: ");
                String storedHash = rs.getString("password_hash");
                if (validatePassword(new String(password), storedHash)) {
                    logger.info("Login successful.");
                    return userId;
                } else {
                    logger.warn("Invalid credentials. Attempt[" + attempt + "/3]");
                }
            }
            logger.warn("Exceeded number of password attempts...");
            return null;
        } catch (SQLException e) {
            logger.error("Error: " + e.getMessage());
            return null;
        }
    }

    private static Integer loginSeed(String seedPhrase) {
        if (!MnemonicService.validateMnemonic(seedPhrase)) {
            logger.warn("Seed Phrase is not linked to any wallet");
            return null;
        }
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt = conn.prepareStatement("SELECT user_id FROM wallets WHERE seed_phrase = ?")) {
            pstmt.setString(1, seedPhrase);
            ResultSet rs = pstmt.executeQuery();
            int userId = rs.getInt("user_id");
            if (rs.next()) {
                logger.info("Account successfully recovered!");
                return userId;
            }
            return null;
        } catch (SQLException exc) {
            logger.error("Error detected: " + exc.getMessage());
            return null;
        }
    }

    private static String hashPassword(String password) {
        try {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Hashing error: " + e.getMessage());
        }
    }

    private static boolean validatePassword(String password, String stored) {
        try {
            String[] parts = stored.split(":");
            byte[] salt = Base64.getDecoder().decode(parts[0]);
            byte[] hash = Base64.getDecoder().decode(parts[1]);

            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] testHash = skf.generateSecret(spec).getEncoded();

            return MessageDigest.isEqual(hash, testHash);
        } catch (Exception e) {
            logger.error("Password validation error: " + e.getMessage());
            return false;
        }
    }

    private static void userWallet(String userId) {
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt = conn
                        .prepareStatement("SELECT currency, balance FROM wallets WHERE user_id = ?")) {
            pstmt.setString(1, userId);
            ResultSet rs = pstmt.executeQuery();
            logger.info("\n----- Wallet Balances -----");
            boolean foundWallet = false;
            if (rs.next()) {
                foundWallet = true;
                String currency = rs.getString("currency");
                double balance = rs.getDouble("balance");
                logger.info(currency + ":" + balance);
            }
            if (!foundWallet) {
                logger.info("No wallets found");
            }
        } catch (SQLException e) {
            logger.error("Error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        DatabaseManager.init();
        Console cnsl = System.console();
        if (cnsl == null) {
            logger.error("No console available");
            return;
        }
        Scanner scanner = new Scanner(System.in);
        System.out.println("""
                ==========================================
                        Welcome to Bitcoin Wallet
                ==========================================
                """);
        System.out.println("1. Register\n2. Login");
        System.out.print("Enter your choice: ");
        int choice = Integer.parseInt(scanner.nextLine());

        if (choice == 1) {
            System.out.println("""
                    \n====================================
                            Registering New user
                    ====================================
                    """);
            System.out.print("Email: ");
            String email = scanner.nextLine().toLowerCase();
            char[] password = cnsl.readPassword("Password: ");
            register(email, password);
        } else {
            System.out.println("""
                    \n======================================
                                User Login
                    ======================================
                    """);
            System.out.println("1. Login using user credentials\n2. Recover account using Seed Phrase");
            System.out.print("Enter your choice: ");
            int loginChoice = Integer.parseInt(scanner.nextLine());
            if (loginChoice == 1) {
                System.out.print("\nEmail: ");
                String email = scanner.nextLine();
                Integer userId = loginCred(email);
                if (userId != null) {
                    userWallet(String.valueOf(userId));
                } else {
                    logger.error("Login failed!");
                }
            } else {
                logger.info("Seed Phrase: ");
                String seedPhrase = scanner.nextLine().trim().toLowerCase();
                Integer seedUserID = loginSeed(seedPhrase);
                if (seedUserID != null) {
                    userWallet(String.valueOf(seedUserID));
                } else {
                    logger.error("Failed to recover account!");
                }
            }
        }
        scanner.close();
    }
}
