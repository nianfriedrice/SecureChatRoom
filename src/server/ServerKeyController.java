package server;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import javax.crypto.Cipher;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Date;


/**
 * Created by LRX RSS on 2016/11/27.
 */
public class ServerKeyController {
    private String keystoreFile = "";
    private String alias = "";
    private KeyStore keystore = null;
    private char[] password = null;
    private static String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    private X509Certificate clientCert = null;

    public ServerKeyController(String crName, String host, int port) throws Exception{
        alias = crName.toLowerCase();
        password = "password".toCharArray();
        new File("Data").mkdir();
        keystoreFile = "Data\\server.keystore";
        String certPath = "Data\\" + crName + ".cer";
        loadKeyStore();
        if (keystore == null){
            throw new Exception("No KeyStore");
        }

        //check whether the chat room has a key already
        if (!keystore.containsAlias(alias)) {
            KeyPair kp = genKeyPair();
            String info = "CN=" + host + ", O=" + port + ", L=" + crName + ", ST=hkbu, C=hk";
            X509Certificate[] pubCert = new X509Certificate[1];
            pubCert[0] = generateCrt(kp.getPublic(), kp.getPrivate(), info, info);
            storeKeyPair(kp, pubCert);
            outputCertificate(certPath, pubCert[0]);
            } else {
            //check whether the host and port is match
            X509Certificate cert = (X509Certificate) keystore.getCertificate(crName);
            String issuer = cert.getIssuerDN().getName();
            String[] crInfo = issuer.split("\\, ");
            String storedHost = null;
            String storedPort = null;
            for (int i = 0; i < crInfo.length; i++){
                if (crInfo[i].startsWith("CN=")){
                    storedHost = crInfo[i].substring(3);
                }
                if (crInfo[i].startsWith("O=")){
                    storedPort = crInfo[i].substring(2);
                }
            }
            if (!storedHost.equals(host) && !storedPort.equals(port)){
                System.out.println(host + ":" + port + " has already used by another chatroom!");
                throw new Exception("Unmatched Host & Port");
            }
            Certificate pubCert = keystore.getCertificate(alias);
            outputCertificate(certPath, pubCert);
            }
            System.out.println("Please find server certificate in " + certPath);
    }

    private void outputCertificate(String path, Certificate cert){
        try {
            FileOutputStream fos = new FileOutputStream(path);
            fos.write(cert.getEncoded());
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void loadKeyStore(){
        //check if file exist. If not create a new keystore
        File f = new File(keystoreFile);
        if (!f.exists() && !f.isDirectory()) {
                System.out.println("Creating keystore...");
            try {
                keystore = KeyStore.getInstance("JKS");
                keystore.load(null, password);
                // Store away the keystore.
                FileOutputStream fos = new FileOutputStream(keystoreFile);
                keystore.store(fos, password);
                fos.close();
            } catch (Exception e){
                System.out.println("Creation Failed: "+ e.getMessage());
            }
            System.out.println("Creation Complete.");
        } else {
            System.out.println("Loading keystore...");
            try {
                keystore = KeyStore.getInstance("JKS");
                keystore.load(new FileInputStream(keystoreFile), password);
            } catch (Exception e){
                System.out.println("Load Failed: " + e.getMessage());
            }
            System.out.println("Loading Complete.");
        }
    }

    private void storeKeyPair(KeyPair kp, Certificate[] cert){
        try {
            keystore.setKeyEntry(alias, kp.getPrivate(), password, cert);
            FileOutputStream out = new FileOutputStream(keystoreFile);
            keystore.store(out, password);
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
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

    private static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey signedWithPrivateKey) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(PROVIDER_NAME).build(signedWithPrivateKey);
        return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificateBuilder.build(signer));
    }

    private KeyPair genKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024, new SecureRandom());
            KeyPair keypair = keyGen.generateKeyPair();
            PrivateKey privKey = keypair.getPrivate();
            PublicKey pubKey = keypair.getPublic();
            System.out.println("public key: " + getHexString(pubKey.getEncoded()) + " private key: " + getHexString(privKey.getEncoded()));
            return keypair;
        }
        catch (Exception e) {
            System.out.println("Key Generation Error: " + e.getMessage());}
        return null;
    }
    private String getHexString(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    protected KeyManager[] getKeyManagers() throws Exception{
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keystore, password);
        return kmf.getKeyManagers();
    }

    /*
    The checkCert method receive an certificate, check whether the cert is signed by the server.
    The cert will store in a private variable of the ServerKeyController
    This method returns the name extracted from client's cert.
     */
    protected String checkCert(InputStream cert) {
        clientCert = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            clientCert = (X509Certificate) cf.generateCertificate(cert);
            PublicKey publickey = keystore.getCertificate(alias).getPublicKey();
            clientCert.checkValidity(new Date());
            clientCert.verify(publickey);
            String name = clientCert.getSubjectDN().getName();
            int start = name.indexOf("CN=");
            int end = name.indexOf(" ", start);
            if (end == -1) {
                return name.substring(start + 3, name.length());
            } else {
                return name.substring(start + 3, end);
            }
        } catch (Exception e){
            System.out.println("Invalid Certificate!!");
            return null;
        }
    }

    public byte[] encrypt(byte[] num){
        try {
            PublicKey pk = clientCert.getPublicKey();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            return cipher.doFinal(num);
        } catch (Exception e){
            System.out.println("Encryption Failed: "+ e.getMessage());
            return null;
        }
    }
}
