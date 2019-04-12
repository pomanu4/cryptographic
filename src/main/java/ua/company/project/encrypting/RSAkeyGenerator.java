package ua.company.project.encrypting;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;


public class RSAkeyGenerator {
    
    private static final KeyPair KEY_PAIR = getKeyPair("RSA");
    
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
        PublicKey key = KEY_PAIR.getPublic();
        return key;
    }
    
    private PrivateKey getPrivateKey(){
        PrivateKey key = KEY_PAIR.getPrivate();
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
    
    public PrivateKey getPrivateKeyFromFile(String filePath){
        Security.addProvider(new BouncyCastleProvider());
        Path path = Paths.get(filePath);
        final String privateKeyPassword = null;
        PasswordFinder finder = () -> {
                if (privateKeyPassword != null) {
                    return privateKeyPassword.toCharArray();
                } else {
                    return new char[0];
                }
            };
        try(PEMReader reader = new PEMReader(new InputStreamReader(new FileInputStream(path.toFile())), finder);) {
            PrivateKey privK = null;
            KeyPair pair = (KeyPair) reader.readObject();
            privK = pair.getPrivate();
            return privK;   
        } catch (IOException ex) {
            return null;
        }
    }
    
    public PublicKey getPublicKeyFromFile(String filePath){
        Security.addProvider(new BouncyCastleProvider());
        Path path = Paths.get(filePath);
        final String privateKeyPassword = null;
        PasswordFinder finder = () -> {
                if (privateKeyPassword != null) {
                    return privateKeyPassword.toCharArray();
                } else {
                    return new char[0];
                }
            };
        try(PEMReader reader = new PEMReader(new InputStreamReader(new FileInputStream(path.toFile())), finder);) {
            PublicKey pubK = null;
            pubK = (PublicKey) reader.readObject();
            return pubK;   
        } catch (IOException ex) {
            return null;
        }
    }
    
    public String signDocument(PrivateKey privK, Document document) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException, UnsupportedEncodingException, TransformerException, IOException{
        
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        DigestMethod method = factory.newDigestMethod(DigestMethod.SHA1, null);
        Transform transform = factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec)null);
        Reference newReference = factory.newReference("", method, Collections.singletonList(transform), null, null);
        CanonicalizationMethod methodCan = factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec)null);
        SignatureMethod signatureMethod = factory.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
        SignedInfo info = factory.newSignedInfo(methodCan, signatureMethod, Collections.singletonList(newReference));
       
        
        XMLSignature XMLSignature = factory.newXMLSignature(info, null);
        
        
        DOMSignContext context = new DOMSignContext(privK, document.getDocumentElement());
        
        XMLSignature.sign(context);
        byte[] b = new byte[1024];
        info.getCanonicalizedData().read(b);
        String can = new String(b, "utf-8").trim();
        System.out.println(can);
       
        
        byte[] value = XMLSignature.getSignatureValue().getValue();
        byte[] encode = Base64.getEncoder().encode(value);
        String str = new String(encode, "utf-8");
//        System.out.println(str);
        return DocUtill.documentToString(document);
    }
    
    public boolean verifyDocument(PublicKey pubK, Document document) throws MarshalException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, XMLSignatureException, InvalidKeySpecException, ParserConfigurationException, SAXException, IOException{
        
        
//        NodeList nodes = document.getElementsByTagName("Signature");
 NodeList nodes = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        DOMValidateContext context = new DOMValidateContext(pubK, nodes.item(0));
        
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        
        XMLSignature signature = factory.unmarshalXMLSignature(context);
        //retrive signature value
        byte[] value = signature.getSignatureValue().getValue();
        String str = new String(Base64.getEncoder().encode(value), "utf-8");
//        System.out.println(str);
       
        
        
        boolean validate = signature.validate(context);
        return validate;
    }
    
    public byte[] encrypt(byte[] message, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] doFinal = cipher.doFinal(message);
        return doFinal;
    }
    
    public byte[] decrypt(byte[] message, PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] doFinal = cipher.doFinal(message);
        return doFinal;
    }
    
    
}
