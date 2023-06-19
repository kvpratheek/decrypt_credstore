package com.sap.multidb.app.model;

import java.io.Serializable;

public class EncryptionData implements Serializable {

    private static final long serialVersionUID = 1L;

    private String message;

    public EncryptionData() {
        super();
    }

    public EncryptionData(final String message) {
        super();
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(final String message) {
        this.message = message;
    }

}
