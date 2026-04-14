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
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bouncycastle.crypto.params.KeyParameter;

public class BitcoinWallet implements Wallet {

    private final String seedPhrase;
    private final String address;
    private final byte[] pubKeyBytes;
    private final byte[] encryptedPrivKeyBytes;
    private final byte[] encryptedPrivKeyIvector;
    // private final String transactionSignKey;
    private final double balance = 0.0;

    public BitcoinWallet(String userPassword) {
        // Using entropy of 32 random bytes, we use it to generate our seed phrase
        // consisting of 24 words
        this.seedPhrase = MnemonicService.generateMnemonic();
        List<String> words = List.of(seedPhrase.split(" "));

        // We now input our seed phrase into BIP-39's derivation algorithm
        // (PBKDF2-HMAC-SHA512) to get our 64-byte seed
        DeterministicSeed seed = new DeterministicSeed(words, null, "", 0);
        byte[] seedBytes = seed.getSeedBytes();

        // We obtain our master private key from the 64-byte seed using HMAC-SHA512
        // (BIP-32)
        DeterministicKey masterKey = HDKeyDerivation.createMasterPrivateKey(seedBytes);

        ChildNumber childNumberPurpose = new ChildNumber(44, true);
        ChildNumber childNumberCoinType = new ChildNumber(0, true);
        ChildNumber childNumberAccount = new ChildNumber(0,true);
        ChildNumber childNumberChange = new ChildNumber(0);
        ChildNumber childNumberAddIndex = new ChildNumber(0);

        HDPath privKeyPath = HDPath.m(List.of(childNumberPurpose, childNumberCoinType, childNumberAccount,
        childNumberChange, childNumberAddIndex));

        DeterministicHierarchy masterKeyTree = new DeterministicHierarchy(masterKey);
        
        // Derive a child key at path m/44'/0'/0'/0/0 BIP-44 from the master key
        DeterministicKey childKey = masterKeyTree.get(privKeyPath, true, true);

        // From the child key's public key, we now derive a legacy P2PKH Bitcoin address
        this.address = LegacyAddress.fromKey(MainNetParams.get(), childKey).toString();

        // Wrap the child private key in an ECKey to enable transaction signing
        ECKey ecKey = ECKey.fromPrivate(childKey.getPrivKey());
 
        // Declare our constructor to encrypt / decrypt the AESKey using random Salt
        KeyCrypterScrypt crypt = new KeyCrypterScrypt();
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
    
    public byte[] getEncryptedPrivKeyBytes(){
        return encryptedPrivKeyBytes;
    }

    public byte[] getEncryptedPrivKeyIvector(){
        return encryptedPrivKeyIvector;
    }

    public byte[] getPubKeyBytes(){
        return pubKeyBytes;
    }

}
