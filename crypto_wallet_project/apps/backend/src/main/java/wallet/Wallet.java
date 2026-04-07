package wallet;

public interface Wallet {
    String getSeedPhrase();
    String getAddress();
    String getCurrency();
    byte[] getEncryptedBytes();
    byte[] getEncryptedIvector();
    double getBalance();
}
