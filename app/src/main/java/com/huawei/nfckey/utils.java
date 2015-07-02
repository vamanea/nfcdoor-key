package com.huawei.nfckey;

/**
 * Created by justin.ribeiro on 10/28/2014.
 */

import android.content.Context;
import android.util.Log;

import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.crypto.util.PrivateKeyFactory;
import org.spongycastle.crypto.util.PublicKeyFactory;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.interfaces.ECPrivateKey;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.openssl.jcajce.JcaPEMWriter;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.x509.X509V3CertificateGenerator;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.security.auth.x500.X500Principal;

/**
 * Just a tiny class to dump things that I may want to use
 *
 * AKA: you probably don't need this, but you might :-)
 */
public class utils {

    private static final String TAG = "NFCKey";
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    /**
     * Simple way to output byte[] to hex (my readable preference)
     * This version quite speedy; originally from: http://stackoverflow.com/a/9855338
     *
     * @param bytes yourByteArray
     * @return string
     *
     */
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Constant-time Byte Array Comparison
     * Less overheard, safer. Originally from: http://codahale.com/a-lesson-in-timing-attacks/
     *
     * @param bytes yourByteArrayA
     * @param bytes yourByteArrayB
     * @return boolean
     *
     */
    public static boolean isEqual(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
    /**
     *
     * @param bytes yourByteArrayA
     * @param bytes yourByteArrayB
     * @return boolean
     *
     */
    public static boolean startsWith(byte[] a, byte[] b) {
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    public static ECPrivateKeyParameters readKey(InputStream is){
        try {
            return (ECPrivateKeyParameters) PrivateKeyFactory.createKey(is);
        }
        catch (Exception e) {
            Log.e("NFCKey", "Failed to read pem object: " + e.getMessage());
        }
        return null;
    }

    public static void generateSessionCert(Context context) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        // Create an eliptic curve key
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "SC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair keyPair = g.generateKeyPair();

        Log.i(TAG, "EC Key generated: " + utils.bytesToHex(keyPair.getPrivate().getEncoded()));

        // Load the CA ECC private key
        FileInputStream fis = context.openFileInput("ecc.key");
        int size = (int)fis.getChannel().size();
        byte[] key = new byte[size];
        fis.read(key);
        fis.close();

        fis = context.openFileInput("cert.pem");
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "SC");
        X509Certificate certificate = (X509Certificate) cf.generateCertificate((InputStream) fis);


        KeyFactory keyFactory = KeyFactory.getInstance(certificate.getPublicKey().getAlgorithm(), "SC");

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(key);
        PrivateKey caKey = keyFactory.generatePrivate(privateKeySpec);


        X509V3CertificateGenerator certGen=new X509V3CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(certificate.getSubjectX500Principal());
        certGen.setNotBefore(certificate.getNotBefore());
        certGen.setNotAfter(certificate.getNotAfter());
        certGen.setSubjectDN(new X500Principal("CN=Herr Steinhilber,OU=IK510844109," + "OU=RTA GmbH, O=ITSG TrustCenter fuer sonstige Leistungserbringer,C=DE"));
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WITHECDSA");
        X509Certificate cert = certGen.generate(caKey, "SC");

        FileOutputStream fos = context.openFileOutput("session.pem", Context.MODE_PRIVATE);
        JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(fos.getFD()));
        pemWriter.writeObject(cert);
        pemWriter.close();
        fos.close();

        fos = context.openFileOutput("session.key", Context.MODE_PRIVATE);
        byte[] privateKey = keyPair.getPrivate().getEncoded();
        fos.write(privateKey, 0, privateKey.length);
        fos.close();



        Log.i(TAG, "EC session cert generated");

    }
}
