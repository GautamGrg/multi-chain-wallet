package db;

import java.sql.*;
import wallet.Wallet;
import wallet.BitcoinWallet;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

public class WalletRepository {
    private static final Logger logger = LogManager.getLogger(WalletRepository.class);
    public static void saveWallet(int userId, BitcoinWallet btcWallet, String seedPhrase, 
    byte[] encryptedPrivKeyBytes,byte[] encryptedPrivKeyIvector) {
        String sql = """
                    INSERT INTO wallets (user_id, seed_phrase, encrypted_private_bytes, encrypted_private_ivector, currency, address, balance)
                    VALUES (?,?,?,?,?,?,?)
                """;
        try (Connection con = DatabaseManager.connect();
                PreparedStatement ptm = con.prepareStatement(sql)) {
            ptm.setInt(1, userId);
            ptm.setString(2, seedPhrase);
            ptm.setBytes(3, encryptedPrivKeyBytes);
            ptm.setBytes(4, encryptedPrivKeyIvector);
            ptm.setString(5, btcWallet.getCurrency());
            ptm.setString(6, btcWallet.getAddress());
            ptm.setDouble(7, btcWallet.getBalance());
            ptm.executeUpdate();
        } catch (SQLException e) {
            logger.error("Error " + e.getMessage());
        }
    }
}
