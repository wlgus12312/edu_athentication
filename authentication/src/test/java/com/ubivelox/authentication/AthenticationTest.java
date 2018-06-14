package com.ubivelox.authentication;

import static org.junit.Assert.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Test;

import com.ubivelox.gaia.GaiaException;

public class AthenticationTest
{
    public static class CommandMessage
    {
    }





    @Test
    public void test() throws GaiaException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException
    {
        // SCP01
        // D1 : 80 50 00 00 08 0000000000000000
        // D2 : 00005314D00E1E48570F010106BCEB4E0723EE1AFF3DE22034C021A6
        // D3 : 848200001047467AC5E61B724BA4387CE6236BA659

        // SCP02
        // D1 : 8050000008EC78EEA2438008A6
        // D2 : 00009151026881950639FF02000D4EB131EA95DE5D29FCFE72F724DC
        // D3 : 848200001070CA81178C079A4A114998A816CBF511

        // ENC Key : 404043434545464649494A4A4C4C4F4F
        // MAC Key : 404043434545464649494A4A4C4C4F4F
        // DE Key : 404043434545464649494A4A4C4C4F4F

        // 217ABF8CC47294B2411871F381D7534E217ABF8CC47294B2
        // 00009151026881950639 FF02 000D 4EB131EA95DE 5D29FCFE72F724DC

        // 84 82 00 00 10 70CA81178C079A4A 114998A816CBF511
        assertEquals("8050000008EC78EEA2438008A6", CardAthentication.initialUpdateCommand("EC78EEA2438008A6"));
        assertEquals("00009151026881950639FF02000D4EB131EA95DE5D29FCFE72F724DC", CardAthentication.initialUpdateResponseCommand("8050000008EC78EEA2438008A6"));
        assertEquals("848200001070CA81178C079A4A114998A816CBF511", CardAthentication.externalUpdateCommand("00009151026881950639FF02000D4EB131EA95DE5D29FCFE72F724DC"));

    }

}
