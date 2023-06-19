package com.sap.multidb.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.sap.cp.security.credstore.client.CredentialStoreFactory;
import com.sap.cp.security.credstore.client.CredentialStoreInstance;
import com.sap.cp.security.credstore.client.CredentialStoreNamespaceInstance;
import com.sap.cp.security.credstore.client.EnvCoordinates;
import com.sap.multidb.app.model.EncryptionData;
import com.sap.security.dataencryption.DataEncryption;
import com.sap.security.dataencryption.DataEncryptionException;
import com.sap.security.dataencryption.DataEncryptionKeyProvider;
import com.sap.security.dataencryption.DefaultKeyCache;
import com.sap.security.dataencryption.EncryptDataResult;
import com.sap.security.dataencryption.KeyCache;
import com.sap.security.dataencryption.credstore.DecryptionKeyId;
import com.sap.security.dataencryption.credstore.EncryptionKeyId;
import com.sap.security.dataencryption.credstore.EnvelopeEncryptionKeyProvider;
import com.sap.security.dataencryption.credstore.EnvelopeEncryptionKeyProviderOptions;
import com.sap.security.dataencryption.credstore.KeyringGenerateOptions;

@RestController
public class EncryptionController {

    private static final int encryptionKeysMaxCapacity = 1000;
    private static final int decryptionKeysMaxCapacity = 5000;
    private static final int encryptionKeyExpiryInSec = 1800;
    private static final long decryptionKeyExpiryInSec = 1800;

    EnvelopeEncryptionKeyProvider credentialStoreKeyProvider;
    DataEncryptionKeyProvider[] dataEncryptionKeyProviders;
    DataEncryption dataEncryption = new DataEncryption();

    @PostMapping("/encryptMesage")
    public String encryptMessage(@RequestParam(name = "tenantId") final String tenantId, @RequestBody final EncryptionData text) {
        System.out.println("Start --  : " + text.getMessage());
        KeyCache<EncryptionKeyId, DecryptionKeyId> keyCache = new DefaultKeyCache<>(encryptionKeysMaxCapacity, decryptionKeysMaxCapacity,
                encryptionKeyExpiryInSec, decryptionKeyExpiryInSec);
        CredentialStoreInstance credentialStore = CredentialStoreFactory.getInstance(EnvCoordinates.DEFAULT_ENVIRONMENT);

        CredentialStoreNamespaceInstance namespace = credentialStore.getNamespaceInstance(tenantId);
        System.out.println("Namespace : " + text.getMessage());
        KeyringGenerateOptions keyringGenerateOptions = KeyringGenerateOptions.builder().length(32).subaccountId(tenantId).build();

        EnvelopeEncryptionKeyProviderOptions envelopeEncryptionKeyProviderOptions = EnvelopeEncryptionKeyProviderOptions
                .builder(namespace, "spa-kafka").keyringGenerateOptions(keyringGenerateOptions).keyCache(keyCache)
                .renewEncryptionKeysBeforeExpiry(encryptionKeyExpiryInSec / 4, 30).build();

        this.credentialStoreKeyProvider = new EnvelopeEncryptionKeyProvider(envelopeEncryptionKeyProviderOptions);

        System.out.println("Key Provider -- : " + text.getMessage());

        StringBuilder builder = new StringBuilder();
        byte[] plainData = text.getMessage().getBytes();
        System.out.println("Message : " + text.getMessage());
        EncryptDataResult encryptDataResult = null;
        try {
            encryptDataResult = this.dataEncryption.encryptData(plainData, this.credentialStoreKeyProvider);
            byte[] encryptedData = encryptDataResult.getEncryptedData();
            builder.append(encryptedData).append("\n");
        } catch (DataEncryptionException e) {
            System.out.println("---------EXCEPTION----------------");
            System.out.println(e.getMessage());
            System.out.println("---------EXCEPTION----------------");
        }
        return builder.toString();
    }
}
