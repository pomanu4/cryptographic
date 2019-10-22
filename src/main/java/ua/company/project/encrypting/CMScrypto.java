package ua.company.project.encrypting;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class CMScrypto {
    
    public byte[] getCryptoMessage(String message, X509Certificate cert, PrivateKey privateKey, PublicKey publicKey) throws IOException{
            Security.addProvider(new BouncyCastleProvider());
//        X509Certificate cert1 = getCert("D:\\garbage\\CMStest\\cert.pem");

        try {
            CMSTypedData sTypedData = new CMSProcessableByteArray(message.getBytes("utf-8"));
//            List<X509Certificate> certs = new ArrayList<>();/// optionsl
//            certs.add(cert);   /// optional
            
//            Store certStore = new JcaCertStore(certs);
            CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();
            ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
            
            signedDataGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().build()
            ).build(signer, cert));
//            signedDataGenerator.addCertificates(certStore);   // optional
            
            CMSSignedData signedData = signedDataGenerator.generate(sTypedData, true);
            
                       
//            Store certificates = signedData.getCertificates();/// if signed data contain cert cerin
//            X509CertificateHolder cert1 = (X509CertificateHolder) certificates.getMatches(signInfo.getSID()).iterator().next();
          

//            SignerInformation signInfo = (SignerInformation)signedData.getSignerInfos().getSigners().iterator().next();
//            boolean verify = signInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
//            System.out.println(verify);
            
            return signedData.getEncoded();
            /*
            get signed information back
            byte[] cr = signedData.getEncoded();
            ContentInfo conInf = ContentInfo.getInstance(ASN1Sequence.fromByteArray(cr));
            CMSSignedData data = new CMSSignedData(conInf);
            byte[] name = (byte[])data.getSignedContent().getContent();
            System.out.println(new String(name));
             */
            
        } catch (UnsupportedEncodingException | CertificateEncodingException | OperatorCreationException | CMSException ex) {
            Logger.getLogger(CMScrypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    private X509Certificate getCert(String path){
        File f = new File(path);
        try(FileInputStream fis = new FileInputStream(f)){
            PEMParser pEMParser = new PEMParser(new InputStreamReader(fis));
            Object obj = pEMParser.readObject();
            if(obj instanceof X509CertificateHolder){
                X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate((X509CertificateHolder)obj);
                return cert;
            }else{
                System.out.println("can not read cert");
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(CMScrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CMScrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(CMScrypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    
}
