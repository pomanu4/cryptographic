package ua.company.project.encrypting;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AEScryptoUtill {
    
    private SecureRandom secureRandom;
    
    private String  keyString = null;
    
    private String  vectorString = null;
    
    public AEScryptoUtill() {
        this.secureRandom = new SecureRandom();
    }

    public String getKeyString() {
        return keyString;
    }

    public String getVectorString() {
        return vectorString;
    }
    
    private byte[] get256BitKey(){
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);
        return key;
    }
    
    private byte[] get12byteInitialVector(){
//        byte[] vector = new byte[12];  //for AES/GCM/NoPadding mode
        byte[] vector = new byte[16];
        secureRandom.nextBytes(vector);
        return vector;
    }
    
    private SecretKey getAESsecretKey(){
        byte[] key = get256BitKey();
        SecretKey secretKey = new SecretKeySpec(key,"AES");
        return secretKey;
    }
    
    private void keyBytesToB64String(byte[] bytes){
        String value = Base64.getEncoder().encodeToString(bytes);
        this.keyString = value;
    }
    
    private void vectorBytesToB64String(byte[] bytes){
        String value = Base64.getEncoder().encodeToString(bytes);
        this.vectorString = value;
    }
    
    public String encryptAES(String message){
        try {
            SecretKey secretKey = getAESsecretKey();
            keyBytesToB64String(secretKey.getEncoded());
            
            byte[] vector = get12byteInitialVector();
            vectorBytesToB64String(vector);
            
//            Cipher cipher  = Cipher.getInstance("AES/GCM/NoPadding"); /// or AES/CBC/PKCS5PADDING
//            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, vector);
            Cipher cipher  = Cipher.getInstance("AES/CTR/NoPadding");
            IvParameterSpec parameterSpec = new IvParameterSpec(vector);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            byte[] encoded = cipher.doFinal(message.getBytes("utf-8"));
            String encodeString = Base64.getEncoder().encodeToString(encoded);
            return encodeString; 
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(AEScryptoUtill.class.getName()).log(Level.SEVERE, null, ex);
            return  null;
        }
    }
    
    public String decryptAES(String encMessage){
        
        try {
            byte[] enc = Base64.getDecoder().decode(encMessage);
            
            byte[] key = Base64.getDecoder().decode(this.keyString);
            byte[] vector = Base64.getDecoder().decode(this.vectorString);
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            
//            Cipher cipher  = Cipher.getInstance("AES/GCM/NoPadding");  /// or AES/CBC/PKCS5PADDING
//            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, vector);
            Cipher cipher  = Cipher.getInstance("AES/CTR/NoPadding");
            IvParameterSpec parameterSpec = new IvParameterSpec(vector);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
            byte[] decoded = cipher.doFinal(enc);
            String decodedString = new String(decoded, "utf-8");
            return decodedString;
        } catch (UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(AEScryptoUtill.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        } 
    }
    
}
