package wallet;

public interface Wallet {
    String getSeedPhrase();
    String getAddress();
    String getCurrency();
    byte[] getEncryptedPrivKeyBytes();
    byte[] getEncryptedPrivKeyIvector();
    byte[] getPubKeyBytes();
    double getBalance();
}
