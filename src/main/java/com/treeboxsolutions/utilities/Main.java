package com.treeboxsolutions.utilities;

import org.apache.commons.cli.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

import static com.treeboxsolutions.utilities.Preconditions.isNullOrEmpty;

public class Main {
    public static void main(String[] args) {
        Options options = new Options();

        Option keyStore = new Option(null, "keystore", true, "CA keystore");
        keyStore.setRequired(true);
        options.addOption(keyStore);

        Option storePass = new Option(null, "storepass", true, "CA keystore password");
        storePass.setRequired(true);
        options.addOption(storePass);

        Option storeType = new Option(null, "storetype", true, "CA keystore type");
        storeType.setRequired(false);
        options.addOption(storeType);

        Option alias = new Option(null, "alias", true, "CA alias");
        alias.setRequired(true);
        options.addOption(alias);

        Option keyPassword = new Option(null, "keypass", true, "CA alias key password");
        keyPassword.setRequired(false);
        options.addOption(keyPassword);

        Option validityInDays = new Option(null, "validity", true, "Validity of signed cert");
        validityInDays.setRequired(false);
        options.addOption(validityInDays);

        Option csr = new Option(null, "csr", true, "CSR");
        csr.setRequired(true);
        options.addOption(csr);

        Option file = new Option(null, "file", true, "Output file");
        file.setRequired(true);
        options.addOption(file);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine command;

        try {
            command = parser.parse(options, args);
        }
        catch (ParseException e) {
            formatter.printHelp("CA-Signer", options);
            throw new RuntimeException(e);
        }

        String keyStoreValue = command.getOptionValue(keyStore.getLongOpt());
        String storePassValue = command.getOptionValue(storePass.getLongOpt());
        String storeTypeValue = command.getOptionValue(storeType.getLongOpt());
        String aliasValue = command.getOptionValue(alias.getLongOpt());
        String keyPasswordValue = command.getOptionValue(keyPassword.getLongOpt());
        String validityInDaysValue = command.getOptionValue(validityInDays.getLongOpt());
        String csrValue = command.getOptionValue(csr.getLongOpt());
        String fileValue = command.getOptionValue(file.getLongOpt());

        Signer signer = new Signer.Builder()
                .setKeyStore(keyStoreValue)
                .setStorePass(storePassValue.toCharArray())
                .setStoreType(storeTypeValue)
                .build();

        if (isNullOrEmpty(keyPasswordValue)) {
            keyPasswordValue = storePassValue;
        }

        if (isNullOrEmpty(validityInDaysValue)) {
            validityInDaysValue = "99999";
        }

        X509Certificate certificate;
        try (Reader reader = new FileReader(csrValue)) {
            PEMParser pemParser = new PEMParser(reader);
            PKCS10CertificationRequest csrRequest = (PKCS10CertificationRequest) pemParser.readObject();
            certificate = signer.sign(aliasValue, keyPasswordValue.toCharArray(), Integer.parseInt(validityInDaysValue), csrRequest);
        }
        catch (IOException e) {
            throw new UncheckedIOException(e);
        }


        try (OutputStream pemFile = new FileOutputStream(fileValue)) {
            try (JcaPEMWriter pemChainWriter = new JcaPEMWriter(new OutputStreamWriter(pemFile, StandardCharsets.UTF_8))) {
                pemChainWriter.writeObject(certificate);
            }
        }
        catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
