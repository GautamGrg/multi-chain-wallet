package db;

import java.sql.*;
import wallet.Wallet;
import wallet.BitcoinWallet;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

public class WalletRepository {
    private static final Logger logger = LogManager.getLogger(WalletRepository.class);
    public static void saveWallet(int userId, BitcoinWallet btcWallet, String seedPhrase, 
    byte[] scryptParamBytes, byte[] encryptedPrivKeyBytes, byte[] encryptedPrivKeyIvector, byte[] pubKeyBytes) {
        String sql = """
                    INSERT INTO wallets (user_id, seed_phrase, scrypt_param_bytes, encrypted_private_key_bytes, encrypted_private_key_ivector, public_key_bytes, currency, address, balance)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """;
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement ptm = conn.prepareStatement(sql)) {
            ptm.setInt(1, userId);
            ptm.setString(2, seedPhrase);
            ptm.setBytes(3, scryptParamBytes);
            ptm.setBytes(4, encryptedPrivKeyBytes);
            ptm.setBytes(5, encryptedPrivKeyIvector);
            ptm.setBytes(6, pubKeyBytes);
            ptm.setString(7, btcWallet.getCurrency());
            ptm.setString(8, btcWallet.getAddress());
            ptm.setDouble(9, btcWallet.getBalance());
            ptm.executeUpdate();
        } catch (SQLException e) {
            logger.error("Error " + e.getMessage());
        }
    }
}
