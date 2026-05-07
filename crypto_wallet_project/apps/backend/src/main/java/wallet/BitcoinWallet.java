/* (C)2026 */
package wallet;

import java.util.List;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicHierarchy;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.EncryptedData;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.HDPath;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.wallet.Protos.ScryptParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BitcoinWallet implements Wallet {
    private static final Logger logger = LogManager.getLogger(BitcoinWallet.class);

    private final String seedPhrase;
    private final String address;
    private final byte[] pubKeyBytes;
    private final byte[] encryptedPrivKeyBytes;
    private final byte[] encryptedPrivKeyIvector;
    private final byte[] kcsParamBytes;
    private final double balance = 0.0;

    // private final String transactionSignKey;

    public BitcoinWallet(String userPassword, String oldSeedPhrase) {
        // Using entropy of 32 random bytes, we use it to generate our seed phrase
        // consisting of 24 words
        if (oldSeedPhrase != null) {
            this.seedPhrase = oldSeedPhrase;
        } else {
            this.seedPhrase = MnemonicService.generateMnemonic();
        }
        List<String> words = List.of(seedPhrase.split(" "));

        // We now input our seed phrase into BIP-39's derivation algorithm
        // (PBKDF2-HMAC-SHA512) to get our 64-byte seed
        byte[] seedBytes = MnemonicCode.toSeed(words, "");

        // We obtain our master private key from the 64-byte seed using HMAC-SHA512
        // (BIP-32)
        DeterministicKey masterKey = HDKeyDerivation.createMasterPrivateKey(seedBytes);

        ChildNumber childNumberPurpose = new ChildNumber(44, true);
        ChildNumber childNumberCoinType = new ChildNumber(0, true);
        ChildNumber childNumberAccount = new ChildNumber(0, true);
        ChildNumber childNumberChange = new ChildNumber(0);
        ChildNumber childNumberAddIndex = new ChildNumber(0);

        HDPath privKeyPath =
                HDPath.m(
                        List.of(
                                childNumberPurpose,
                                childNumberCoinType,
                                childNumberAccount,
                                childNumberChange,
                                childNumberAddIndex));

        DeterministicHierarchy masterKeyTree = new DeterministicHierarchy(masterKey);

        // Derive a child key at path m/44'/0'/0'/0/0 BIP-44 from the master key
        DeterministicKey childKey = masterKeyTree.get(privKeyPath, true, true);

        // From the child key's public key, we now derive a legacy P2PKH Bitcoin address
        this.address = LegacyAddress.fromKey(TestNet3Params.get(), childKey).toString();
        logger.info("The derived address: " + address);

        // Wrap the child private key in an ECKey to enable transaction signing
        ECKey ecKey = ECKey.fromPrivate(childKey.getPrivKey());

        // Declare our constructor to encrypt / decrypt the AESKey using random Salt
        KeyCrypterScrypt crypt = new KeyCrypterScrypt();
        ScryptParameters kcsParamters = crypt.getScryptParameters();

        // Save the KeyCrypterScrypt parameters as bytes in the DB.
        // This is so we re-use the same salt key for AESkey when we decrypt the private key
        this.kcsParamBytes = kcsParamters.toByteArray();

        // Using KeyCrypterScrypt constructor to encrypt / decrypt the AESKey derived
        // from the user password
        KeyParameter aesKey = (crypt.deriveKey(userPassword));

        // Finally encrypt our private key
        ECKey encryptPrivKey = ecKey.encrypt(crypt, aesKey);

        EncryptedData encryptedPrivateKey = encryptPrivKey.getEncryptedPrivateKey();

        this.encryptedPrivKeyBytes = encryptedPrivateKey.encryptedBytes;
        this.encryptedPrivKeyIvector = encryptedPrivateKey.initialisationVector;

        // Store the Public key in bytes reconstruct an encrypted ECKey later
        this.pubKeyBytes = ecKey.getPubKey();
    }

    @Override
    public String getAddress() {
        return address;
    }

    @Override
    public String getCurrency() {
        return "BTC";
    }

    @Override
    public String getSeedPhrase() {
        return seedPhrase;
    }

    @Override
    public double getBalance() {
        return balance;
    }

    @Override
    public byte[] getScryptParamBytes() {
        return kcsParamBytes;
    }

    @Override
    public byte[] getEncryptedPrivKeyBytes() {
        return encryptedPrivKeyBytes;
    }

    @Override
    public byte[] getEncryptedPrivKeyIvector() {
        return encryptedPrivKeyIvector;
    }

    @Override
    public byte[] getPubKeyBytes() {
        return pubKeyBytes;
    }
}
