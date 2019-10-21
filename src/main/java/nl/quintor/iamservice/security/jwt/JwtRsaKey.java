package nl.quintor.iamservice.security.jwt;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class JwtRsaKey extends JwtSigningKey {

    private Key publicKey;
    private Key privateKey;

    public JwtRsaKey(File keyStoreFile, String alias, String password) throws KeyStoreException, IOException {
        try {
            loadKeys(keyStoreFile, alias, password);
        } catch (CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    @Override
    public Key getSigningKeyForCreation() {
        return privateKey;
    }

    @Override
    public Key getSigningKeyForVerification() {
        return publicKey;
    }

    private void loadKeys(File keyStoreFile, String keyAlias, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        if (!keyStoreFile.exists())
            throw new KeyStoreException("Provided keyStoreFile is not a valid file");
        if (!keyStoreFile.isFile())
            throw new KeyStoreException("Provided keyStoreFile is not a file");


        KeyStore ks = KeyStore.getInstance(keyStoreFile, password.toCharArray());
        Key key = ks.getKey(keyAlias, password.toCharArray());

        if (!(key instanceof PrivateKey))
            throw new KeyStoreException("Provided alias is not a valid private key in the keystore");

        PrivateKey privateKey = (PrivateKey) key;
        PublicKey publicKey = ks.getCertificate(keyAlias).getPublicKey();

        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }
}
