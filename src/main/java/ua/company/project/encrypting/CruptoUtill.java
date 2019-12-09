package ua.company.project.encrypting;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CruptoUtill {
    
    private final RSAkeyGenerator rSAkeyGenerator;

    public CruptoUtill() {
        this.rSAkeyGenerator = new RSAkeyGenerator();
    }
    
    public byte[] encryptByRSApublicKey(String message){
        try {
            String publicKeyStringB64 = rSAkeyGenerator.getPublicKeyStringB64();
            PublicKey key = rSAkeyGenerator.getPublicKeyFromStringB64(publicKeyStringB64);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encoded = cipher.doFinal(message.getBytes("UTF-8"));
            return encoded;
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException  | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
            Logger.getLogger(CruptoUtill.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        } 
    }
    
    public byte[] decryptByRSAprivateKey(byte[] encryptedData){
        try {
            String privateKeyStringB64 = rSAkeyGenerator.getPrivateKeyStringB64();
            PrivateKey key = rSAkeyGenerator.getPrivateKeyFromStringB64(privateKeyStringB64);

            Cipher cipher = Cipher.getInstance("RSA");
            
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decoded = cipher.doFinal(encryptedData);
            return decoded; 
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(CruptoUtill.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }
    
    public String sign(String message,  PrivateKey privateKey) throws SignatureException {
        try {
            Signature sign = Signature.getInstance("SHA1withRSA");
            sign.initSign(privateKey);
            sign.update(message.getBytes("utf-8"));
//            sign.update(message.getBytes("Cp1251"));
            byte[] sign1 = sign.sign();
            
            return java.util.Base64.getEncoder().encodeToString(sign1);
        } catch (Exception ex) {
            throw new SignatureException(ex);
        }
    }
    
    public boolean verify(String message, String signature, PublicKey publicKey) throws SignatureException {
        try {
            Signature sign = Signature.getInstance("SHA1withRSA");

            sign.initVerify(publicKey);
            sign.update(message.getBytes("utf-8"));
//            sign.update(message.getBytes("Cp1251"));
            return sign.verify(Base64.getDecoder().decode(signature.getBytes("utf-8")));
        } catch (Exception ex) {
            throw new SignatureException(ex);
        }
    }
    
}
