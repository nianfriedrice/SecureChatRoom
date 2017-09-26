package client;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.Cipher;
import javax.net.ssl.*;
import java.io.*;
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
public class ClientKeyController {
    private String keystoreFile = "";
    private String user = "";
    private String alias = "";
    private KeyStore keystore = null;
    private X509Certificate[] pubCert = null;
    char[] password = null;

    public ClientKeyController(String userName) throws Exception{
        alias = userName.toLowerCase();
        password = "password".toCharArray();
        new File("Data").mkdir();
        keystoreFile = "Data\\"+alias+".keystore";
        loadKeyStore();
        //check whether the chat room has a key already
        if (!keystore.containsAlias(alias)) {
            KeyPair kp = genKeyPair();
            String info = "CN=" + alias + ", O=comp4017, L=comp4017, ST=hkbu, C=hk";
            X509Certificate[] pubCert = new X509Certificate[1];
            pubCert[0] = generateCrt(kp.getPublic(), kp.getPrivate(), info, info);
            storeKeyPair(kp, pubCert);
            outputPublicKey(kp.getPublic(),alias);
        } else {
            System.out.println("User "+ userName + "already exists");
            outputPublicKey(keystore.getCertificate(alias).getPublicKey(),alias);
        }
        System.out.println("Please find your public key file under Data folder.");
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

    protected ClientKeyController(String userName, String crName) throws Exception{
        user = userName.toLowerCase();
        alias = crName.toLowerCase();
        password = "password".toCharArray();
        new File("Data").mkdir();
        keystoreFile = "Data\\" + userName.toLowerCase() + ".keystore";
        loadKeyStore();
        if (keystore == null){
            throw new Exception("No KeyStore");
        }
        String certName = alias;
        String certPath = "Data\\" +certName + ".cer";
        //check whether server cert has imported
        if (!keystore.isCertificateEntry(alias)) {
            // import server certificate
            try {
                importCertficate(certName, certPath);
            } catch (Exception e) {
                throw new Exception("Failed to import certificate: " + e.getMessage());
            }
        }
    }

    protected String getServerInfo() throws Exception{
        X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
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
        return host+" "+port;
    }

    private void outputPublicKey(PublicKey publicKey, String user){
        try{
            // Store Public Key.
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                    publicKey.getEncoded());
            FileOutputStream fos = new FileOutputStream("Data\\"+user+".key");
            fos.write(x509EncodedKeySpec.getEncoded());
            fos.close();
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    private InputStream fullStream ( String fname ) throws IOException {
        FileInputStream fis = new FileInputStream(fname);
        DataInputStream dis = new DataInputStream(fis);
        byte[] bytes = new byte[dis.available()];
        dis.readFully(bytes);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        return bais;
    }

    private void importCertficate(String certName, String path) throws Exception{
        //Read cert from file path
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream certstream = fullStream(path);
        java.security.cert.Certificate certFile = cf.generateCertificate(certstream);

        // Add the certificate
        keystore.setCertificateEntry(certName, certFile);

        // Save the new keystore contents
        FileOutputStream out = new FileOutputStream(keystoreFile);
        keystore.store(out, password);
        out.close();
    }

    protected byte[] decrypt(byte[] num) throws Exception{
        PrivateKey pk = (PrivateKey) keystore.getKey(user, password);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, pk);
        return cipher.doFinal(num);
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
        String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
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
//            e.printStackTrace();
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

    protected TrustManager[] getClientKeyManager() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keystore);
        return tmf.getTrustManagers();
    }

    public static void main(String[] args)
        {
            if (args.length != 1){
                System.out.println("Usage: java ClientKeyController userName");
            } else {
                try {
                    if (args.length == 1) {
                        new ClientKeyController(args[0]);
                    }
                } catch (Exception e){
                    System.out.println("Error: " + e.getMessage());
                }
            }
        }
}
