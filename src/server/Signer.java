package server;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;


/**
 * Created by LRX on 2016/11/27.
 */
public class Signer {

    public Signer(String path){
        try {
            signCert(path);
        } catch (Exception e) {
            System.out.println("Error: "+ e.getMessage());
        }
    }
    private X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey signedWithPrivateKey) throws Exception{
        String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
        Security.addProvider(new BouncyCastleProvider());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(PROVIDER_NAME).build(signedWithPrivateKey);
        return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificateBuilder.build(signer));
    }
    private X509Certificate generateCrt(PublicKey publicKey, PrivateKey privateKey, String issuerinfo, String subjectinfo) throws Exception{
        Calendar cal = Calendar.getInstance();
        Date today = cal.getTime();
        cal.add(Calendar.YEAR, 1); // to get previous year add -1
        Date nextYear = cal.getTime();
        Date startDate = today;             // time from which certificate is valid
        Date expiryDate = nextYear;
        X500Name issuerName = new X500Name(issuerinfo);
        X500Name subjectName = new X500Name(subjectinfo);
        BigInteger serial = BigInteger.valueOf(new SecureRandom().nextInt());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, startDate, expiryDate, subjectName, publicKey);
        X509Certificate cert = signCertificate(builder, privateKey);
        return cert;
    }

    private void signCert(String folderPath) throws Exception {
        File keystoreFile = new File("Data\\server.keystore");
        // Load the keystore contents
        FileInputStream in = new FileInputStream(keystoreFile);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(in, "password".toCharArray());
        in.close();

        //get public key file
        File dir = new File(folderPath);
        File[] directoryListing = dir.listFiles();
        if (directoryListing != null) {
            for (File f : directoryListing) {
                //Check file extension
                String[] filename = f.getName().split("\\.");
                //check whehter the file is .key
                if (filename.length <= 1 || !filename[filename.length -1].equals("key")){
                    continue;
                }
                filename = filename[0].split("-");
                if (filename.length < 2){
                    System.out.println("Cannot get ChatRoom name for file " + f.getName());
                    continue;
                }
                String crName = filename[0];
                String userName = filename[1];

                // Read file content and convert to public key
                FileInputStream fis = new FileInputStream(f.getPath());
                byte[] encodedPublicKey = new byte[(int) f.length()];
                fis.read(encodedPublicKey);
                fis.close();
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                        encodedPublicKey);
                PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

                //Retrieve private key, host and port number from keystore
                PrivateKey privateKey = (PrivateKey) ks.getKey(crName, "password".toCharArray());
                X509Certificate cert = (X509Certificate) ks.getCertificate(crName);
                String issuer = cert.getIssuerDN().getName();
                String[] crInfo = issuer.split("\\, ");
                String host = null;
                String port = null;
                for (int i = 0; i < crInfo.length; i++){
                    if (crInfo[i].startsWith("CN=")){
                        host = crInfo[i].substring(3);
                    }
                    if (crInfo[i].startsWith("O=")){
                        port = crInfo[i].substring(2);
                    }
                }
                String subject = "CN="+ userName +", O=" + host +", L="+ port +", ST=hkbu, C=hk";

                //
                Certificate userCert = generateCrt(publicKey, privateKey, issuer, subject);
                String output = folderPath +"\\"+crName+"-"+userName+".cer";
                outputCert(userCert, output);
                System.out.println("Certificate created: "+ output);
            }
        } else {
            System.out.println("No file found!");
        }
    }

    private static void outputCert(Certificate cert, String outputFolder){
        try {
            FileOutputStream fos = new FileOutputStream(outputFolder);
            fos.write(cert.getEncoded());
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1){
            System.out.println("Usage: java Signer Path\\Of\\PublicKeyFolder");
        }
        {
            new Signer(args[0]);
        }
    }
}
