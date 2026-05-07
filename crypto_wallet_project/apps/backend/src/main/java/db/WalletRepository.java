/* (C)2026 */
package db;

import java.sql.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import wallet.BitcoinWallet;

public class WalletRepository {
    private static final Logger logger = LogManager.getLogger(WalletRepository.class);

    public static void saveWallet(int userId, BitcoinWallet btcWallet) {
        String sql =
                """
                    INSERT INTO wallets (user_id, scrypt_param_bytes, encrypted_private_key_bytes, encrypted_private_key_ivector, public_key_bytes, currency, address, balance)
                    VALUES (?,?,?,?,?,?,?,?)
                """;
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement ptm = conn.prepareStatement(sql)) {
            ptm.setInt(1, userId);
            ptm.setBytes(2, btcWallet.getScryptParamBytes());
            ptm.setBytes(3, btcWallet.getEncryptedPrivKeyBytes());
            ptm.setBytes(4, btcWallet.getEncryptedPrivKeyIvector());
            ptm.setBytes(5, btcWallet.getPubKeyBytes());
            ptm.setString(6, btcWallet.getCurrency());
            ptm.setString(7, btcWallet.getAddress());
            ptm.setDouble(8, btcWallet.getBalance());
            ptm.executeUpdate();
        } catch (SQLException e) {
            logger.error("Error " + e.getMessage());
        }
    }
}
