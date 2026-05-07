package db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DatabaseManager {
    private static final Logger logger = LogManager.getLogger(DatabaseManager.class);
    private static final String DB_URL = "jdbc:sqlite:crypto_wallet_db.db";

    public static Connection connect() {
        try {
            Connection con = DriverManager.getConnection(DB_URL);
            return con;
        } catch (Exception exc) {
            System.out.println("Database connection failed due to: " + exc.getMessage());
            return null;
        }
    }

    public static void init() {
        try (Connection con = connect(); Statement stm = con.createStatement()) {
            stm.execute("""
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_date TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL)
            """);
            stm.execute("""
                CREATE TABLE IF NOT EXISTS wallets(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    scrypt_param_bytes BLOB NOT NULL,
                    public_key_bytes BLOB NOT NULL,
                    encrypted_private_key_bytes BLOB NOT NULL,
                    encrypted_private_key_ivector BLOB NOT NULL,
                    currency TEXT NOT NULL,
                    address TEXT NOT NULL,
                    balance REAL DEFAULT 0.0,
                    FOREIGN KEY(user_id) REFERENCES users(id))
            """);
            stm.execute("""
                CREATE TABLE IF NOT EXISTS transactions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    send_wallet_id INTEGER NOT NULL,
                    receive_wallet_id INTEGER NOT NULL,
                    transaction_amount REAL,
                    currency TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )    
            """);
            logger.debug("Database created successfully!");
        } catch (Exception exc) {
            logger.error("Database init error: " + exc.getMessage());
            exc.printStackTrace(System.out);
        }
    }
}
