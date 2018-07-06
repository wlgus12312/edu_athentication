package com.ubivelox.authentication;

import lombok.Data;

@Data
public class Key
{

    private String ENCKey_MK;
    private String MACKey_MK;
    private String DEKKey_MK;

    private String ENCKey;
    private String MACKey;
    private String DEKKey;

    private String ENCKey_card;
    private String MACKey_card;
    private String DEKKey_card;

    private String ENCSessionKey;
    private String MACSessionKey;
    private String DEKSessionKey;

}
