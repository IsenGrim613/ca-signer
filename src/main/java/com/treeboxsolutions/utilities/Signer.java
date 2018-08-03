package com.treeboxsolutions.utilities;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import static com.treeboxsolutions.utilities.Preconditions.checkNotNullOrEmpty;
import static com.treeboxsolutions.utilities.Preconditions.isNullOrEmpty;

public class Signer {
    private KeyStore mKeyStore;

    public Signer(KeyStore keyStore) {
        mKeyStore = keyStore;
    }

    public X509Certificate sign(String alias, char[] keyPassword, int validityInDays, PKCS10CertificationRequest csr) {
        try {
            BigInteger sn = generateSn();
            Date endTime = getEndTime(validityInDays);
            X509KeyUsage keyUsageTypes = determineKeyUsageTypes();
            PublicKey publicKey = new JcaPKCS10CertificationRequest(csr).getPublicKey();

            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(alias, new KeyStore.PasswordProtection(keyPassword));
            X509Certificate caCertificate = (X509Certificate) entry.getCertificate();
            X509v3CertificateBuilder certificateBuilder = createCertificateBuilder(caCertificate, sn, csr.getSubject(), publicKey, keyUsageTypes, endTime);

            KeyPair keyPair = new KeyPair(caCertificate.getPublicKey(), entry.getPrivateKey());
            ContentSigner signer = createSigner(keyPair);
            X509CertificateHolder bouncyCastleHolder = certificateBuilder.build(signer);

            return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(bouncyCastleHolder);
        }
        catch (CertificateException | NoSuchAlgorithmException | CertIOException | InvalidKeyException |
                UnrecoverableEntryException | KeyStoreException | OperatorCreationException e) {
            throw new SecurityException(e);
        }
    }

    private BigInteger generateSn() {
        byte[] snBytes = new byte[16];

        SecureRandom random = new SecureRandom();
        random.nextBytes(snBytes);

        return new BigInteger(Hex.encode(snBytes));
    }

    private X509KeyUsage determineKeyUsageTypes() {
        return new X509KeyUsage(X509KeyUsage.digitalSignature | KeyUsage.nonRepudiation);
    }

    private Date getEndTime(int validityInDays) {
        return new Date(System.currentTimeMillis() + (validityInDays * 24L * 60L * 60L * 1000L));
    }

    private X509v3CertificateBuilder createCertificateBuilder(
            X509Certificate caCertificate,
            BigInteger sn,
            X500Name subject,
            PublicKey publicKey,
            X509KeyUsage keyUsages,
            Date endTime)
            throws NoSuchAlgorithmException, CertIOException, CertificateEncodingException {
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                caCertificate,
                sn,
                new Date(),
                endTime,
                subject,
                publicKey
        ).addExtension(
                Extension.basicConstraints,
                false,
                new BasicConstraints(false) // true if it is allowed to sign other certs
        ).addExtension(
                new ASN1ObjectIdentifier("2.5.29.15"),
                true,
                keyUsages
        ).addExtension(
                Extension.authorityKeyIdentifier,
                false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCertificate)
        ).addExtension(
                Extension.subjectKeyIdentifier,
                false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey)
        );

        ExtendedKeyUsage ext = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
        certificateBuilder.addExtension(Extension.extendedKeyUsage, false, ext);

        return certificateBuilder;
    }

    private ContentSigner createSigner(KeyPair keyPair) throws OperatorCreationException {
        String signingAlgorithm;
        if ("RSA".equals(keyPair.getPublic().getAlgorithm())) {
            signingAlgorithm = "SHA384withRSA";
        }
        else {
            signingAlgorithm = "SHA384withECDSA";
        }

        return new JcaContentSignerBuilder(signingAlgorithm).build(keyPair.getPrivate());
    }

    public static class Builder {
        private String mKeyStore;
        private char[] mStorePass;
        private String mStoreType;

        public Builder setKeyStore(String keyStore) {
            mKeyStore = keyStore;
            return this;
        }

        public Builder setStorePass(char[] storePass) {
            mStorePass = storePass;
            return this;
        }

        public Builder setStoreType(String storeType) {
            mStoreType = storeType;
            return this;
        }

        public Signer build() {
            checkNotNullOrEmpty(mKeyStore, "KeyStore");
            checkNotNullOrEmpty(mStorePass, "StorePass");

            String storeType = isNullOrEmpty(mStoreType) ? KeyStore.getDefaultType() : mStoreType;

            try {
                KeyStore keyStore = KeyStore.getInstance(storeType);
                try (FileInputStream keyStoreFileStream = new FileInputStream(mKeyStore)) {
                    keyStore.load(keyStoreFileStream, mStorePass);
                }

                return new Signer(keyStore);
            }
            catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
                throw new SecurityException(e);
            }
        }
    }
}
