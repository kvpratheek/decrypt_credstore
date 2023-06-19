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
import com.sap.security.dataencryption.DecryptDataResult;
import com.sap.security.dataencryption.DefaultKeyCache;
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

    @PostMapping("/decryptMessage")
    public String encryptMessage(@RequestParam(name = "tenantId") final String tenantId, @RequestBody final EncryptionData text) {
        KeyCache<EncryptionKeyId, DecryptionKeyId> keyCache = new DefaultKeyCache<>(encryptionKeysMaxCapacity, decryptionKeysMaxCapacity,
                encryptionKeyExpiryInSec, decryptionKeyExpiryInSec);
        CredentialStoreInstance credentialStore = CredentialStoreFactory.getInstance(EnvCoordinates.DEFAULT_ENVIRONMENT);

        CredentialStoreNamespaceInstance namespace = credentialStore.getNamespaceInstance(tenantId);
        KeyringGenerateOptions keyringGenerateOptions = KeyringGenerateOptions.builder().length(32).subaccountId(tenantId).build();

        EnvelopeEncryptionKeyProviderOptions envelopeEncryptionKeyProviderOptions = EnvelopeEncryptionKeyProviderOptions
                .builder(namespace, "spa-kafka").keyringGenerateOptions(keyringGenerateOptions).keyCache(keyCache)
                .renewEncryptionKeysBeforeExpiry(encryptionKeyExpiryInSec / 4, 30).build();

        this.credentialStoreKeyProvider = new EnvelopeEncryptionKeyProvider(envelopeEncryptionKeyProviderOptions);

        StringBuilder builder = new StringBuilder();
        byte[] plainData = text.getMessage().getBytes();

        this.dataEncryptionKeyProviders = new DataEncryptionKeyProvider[] { credentialStoreKeyProvider };
        DecryptDataResult decryptDataResult;
        try {
            decryptDataResult = this.dataEncryption.decryptData(plainData, this.dataEncryptionKeyProviders);
            byte[] decryptedData = decryptDataResult.getPlainData();
            builder.append("===== Decrypted =====\n");
            builder.append(new String(decryptedData));
            builder.append("===== Decrypted =====\n");
        } catch (DataEncryptionException e) {
            return e.getMessage();
        }
        return builder.toString();
    }
}
