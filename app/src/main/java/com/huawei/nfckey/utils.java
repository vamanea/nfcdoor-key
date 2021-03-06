package com.huawei.nfckey;

/**
 * Created by justin.ribeiro on 10/28/2014.
 */

import android.content.Context;
import android.os.Build;
import android.util.Log;

import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.oiw.OIWObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.BasicConstraints;
import org.spongycastle.asn1.x509.ExtendedKeyUsage;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.asn1.x509.KeyPurposeId;
import org.spongycastle.asn1.x509.KeyUsage;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.cert.X509ExtensionUtils;
import org.spongycastle.cert.X509v3CertificateBuilder;
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
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.DigestCalculator;
import org.spongycastle.operator.bc.BcDigestCalculatorProvider;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.x509.X509V3CertificateGenerator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

/**
 * Just a tiny class to dump things that I may want to use
 *
 * AKA: you probably don't need this, but you might :-)
 */
public class utils {

    private static final String TAG = "NFCKey";
    private static native void signCertificate(byte[] input, byte[] output);

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

    public static String prettyBytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        StringBuilder str = new StringBuilder(new String(hexChars));
        int idx = str.length() - 2;

        while (idx > 0)
        {
            str.insert(idx, ":");
            idx = idx - 2;
        }

        return str.toString();
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

    public static String certThumbprint(Context context) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        FileInputStream fis = context.openFileInput("cert.pem");
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "SC");
        X509Certificate certificate = (X509Certificate) cf.generateCertificate((InputStream) fis);

        MessageDigest mdSha1 = null;
        mdSha1 = MessageDigest.getInstance("SHA-1");
        mdSha1.update(certificate.getEncoded());

        StringBuilder str = new StringBuilder(bytesToHex(Arrays.copyOfRange(mdSha1.digest(), 0, 10)));
        int idx = str.length() - 2;

        while (idx > 0)
        {
            str.insert(idx, ":");
            idx = idx - 2;
        }

        return str.toString();
    }

    public static String sessionThumbprint(Context context) throws Exception
    {
        FileInputStream fis = context.openFileInput("session.pem");
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "SC");
        X509Certificate certificate = (X509Certificate) cf.generateCertificate((InputStream) fis);

        MessageDigest mdSha1 = null;
        mdSha1 = MessageDigest.getInstance("SHA-1");
        mdSha1.update(certificate.getEncoded());

        StringBuilder str = new StringBuilder(bytesToHex(Arrays.copyOfRange(mdSha1.digest(), 0, 10)));
        int idx = str.length() - 2;

        while (idx > 0)
        {
            str.insert(idx, ":");
            idx = idx - 2;
        }

        return str.toString();
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

        String subject = "CN=" + Build.MODEL +",OU=" + Build.ID;
        String issuer = certificate.getSubjectDN().toString();
        Date dateOfIssuing = certificate.getNotBefore();
        Date dateOfExpiry = certificate.getNotAfter();
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                new X500Name(issuer),
                new BigInteger("1"),
                dateOfIssuing,
                dateOfExpiry,
                new X500Name(subject),
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
        certBuilder.addExtension(Extension.basicConstraints,true,new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage,true,new KeyUsage(KeyUsage.digitalSignature));

        DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(digCalc);

        SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded()));
        SubjectPublicKeyInfo authPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(certificate.getPublicKey().getEncoded()));

        //Subject Key Identifier
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, x509ExtensionUtils.createSubjectKeyIdentifier(subjPubKeyInfo));
        //Authority Key Identifier
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, x509ExtensionUtils.createAuthorityKeyIdentifier(authPubKeyInfo));

        byte[] certBytes = certBuilder.build(new JCESigner(caKey, certificate.getSigAlgName())).getEncoded();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));


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

    private static class JCESigner implements ContentSigner {

        private static final AlgorithmIdentifier PKCS1_SHA256_WITH_RSA_OID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"));
        private static final AlgorithmIdentifier PKCS1_SHA256_WITH_ECDSA_OID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));

        private Signature signature;
        private ByteArrayOutputStream outputStream;

        public JCESigner(PrivateKey privateKey, String signatureAlgorithm) {
            if (!"SHA256WITHECDSA".equals(signatureAlgorithm)) {
                throw new IllegalArgumentException("Signature algorithm \"" + signatureAlgorithm + "\" not yet supported");
            }
            try {
                this.outputStream = new ByteArrayOutputStream();
                this.signature = Signature.getInstance(signatureAlgorithm);
                this.signature.initSign(privateKey);
            } catch (GeneralSecurityException gse) {
                throw new IllegalArgumentException(gse.getMessage());
            }
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            if (signature.getAlgorithm().equals("SHA256withRSA")) {
                return PKCS1_SHA256_WITH_RSA_OID;
            } else if (signature.getAlgorithm().equals("SHA256WITHECDSA")) {
                return PKCS1_SHA256_WITH_ECDSA_OID;
            } else {
                return null;
            }
        }

        @Override
        public OutputStream getOutputStream() {
            return outputStream;
        }

        @Override
        public byte[] getSignature() {
            try {
                signature.update(outputStream.toByteArray());
                byte[] sig = signature.sign();
                byte[] output = new byte[100];
                Log.i(TAG, "Certificate: " + prettyBytesToHex(outputStream.toByteArray()));
                signCertificate(sig, output);
                Log.i(TAG, "Session cert signature: " + prettyBytesToHex(sig));
                return  sig;
            } catch (GeneralSecurityException gse) {
                gse.printStackTrace();
                return null;
            }
        }    }
}
