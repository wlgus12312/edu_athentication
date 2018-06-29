package com.ubivelox.authentication.capduService;

import javax.smartcardio.CardException;

import com.ubivelox.authentication.exception.UbiveloxException;
import com.ubivelox.gaia.GaiaException;

public interface CapduService
{
    // C-APDU 구현
    public String sendApdu(final String cApdu) throws GaiaException, UbiveloxException, CardException;
}
