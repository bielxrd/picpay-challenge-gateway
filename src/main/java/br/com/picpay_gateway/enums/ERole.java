package br.com.picpay_gateway.enums;

public enum ERole {
    USER,
    SHOPKEEPER;

    public String getDescription() {
        return "ROLE_" + this.name();
    }
}