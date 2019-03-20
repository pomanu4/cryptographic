package ua.company.project.encrypting;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RSAkeyGenerator {
    
    private static final KeyPair keyPair = getKeyPair("RSA");
    
    private static KeyPair getKeyPair(String algorythm){
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorythm);
            generator.initialize(2048);     //depends on how long message you want to encrypt
            KeyPair keyPair = generator.generateKeyPair();
            return keyPair;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSAkeyGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }
    
    private PublicKey getPublicKey(){
        PublicKey key = keyPair.getPublic();
        return key;
    }
    
    private PrivateKey getPrivateKey(){
        PrivateKey key = keyPair.getPrivate();
        return key;
    }
    
    public String getPublicKeyStringB64(){
        PublicKey pk = getPublicKey();
        byte[] byteKey = pk.getEncoded();
        String pubKeyString = Base64.getEncoder().encodeToString(byteKey);
        return pubKeyString;
    }
    
    public String getPrivateKeyStringB64(){
        PrivateKey pk = getPrivateKey();
        byte[] byteKey = pk.getEncoded();
        String pubKeyString = Base64.getEncoder().encodeToString(byteKey);
        return pubKeyString;
    }
    
    public PublicKey getPublicKeyFromStringB64(String b64String) {
        
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(b64String));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            return pubKey;            
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(RSAkeyGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }
    
    public PrivateKey getPrivateKeyFromStringB64(String b64String){
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64String));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(RSAkeyGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
        
    }
}
