package com.ubivelox.authentication;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ubivelox.gaia.GaiaException;
import com.ubivelox.gaia.util.GaiaUtils;

public class CardAthentication

{

    private static String SEQUENCECOUNT;
    private static String CARDCHALLENGE = "4EB131EA95DE";





    public static String initialUpdateCommand(final String data)
    {
        String cla = "8050000008";
        String result = cla + data;

        return result;
    }





    public static String initialUpdateResponseCommand(final String initialUpdateCommand) throws GaiaException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {

        // CLA - 80 - 2bytes
        // INS - 50 - 2bytes - INITIALIZE UPDATE
        // P1 - 00 - 2bytes - Key Version Number
        // P2 - 00 - 2bytes - Reference control parameter P2
        // Lc - 08 - 2bytes - Length if host challenge
        // Data - 8bytes - Host challenge
        // Le - 00 - 2byte - 안함
        // UPDATE Command
        // 8050000008EC78EEA2438008A6

        // Respone
        // key diversification data = 10 bytes
        // key infomation = key version number, SCP02 - 2 bytes
        // Seqeuence Count = 세션 키에 사용되는 내부에서 증가되는 카운터 - 2 bytes
        // Card challenge = 내부적으로 생성된 난수 - 6 bytes
        // card cryptogram = 인증 암호문 - 8 bytes

        // 00009151026881950639 FF02 000D 4EB131EA95DE 5D29FCFE72F724DC

        // 암호화 키 값 - 40 4F, DESede, CBC 모드
        // initial chaning vector (ICV) = 0000000000000000

        // ENC Key : 404043434545464649494A4A4C4C4F4F- 0182
        // MAC Key : 404043434545464649494A4A4C4C4F4F - 0101, 0102
        // DE Key : 404043434545464649494A4A4C4C4F4F- 0181

        SEQUENCECOUNT = "000D";

        byte[] sessionKey = null;
        String keyDiversification = "00009151026881950639";
        sessionKey = getSessionKey();

        String sessionKeyStroing = GaiaUtils.convertByteArrayToHexaString(sessionKey);

        String hostChallengeString = initialUpdateCommand.substring(10, initialUpdateCommand.length());

        byte[] cardCryptogram = null;

        cardCryptogram = getCardCryptogram(hostChallengeString, sessionKeyStroing);

        String result = GaiaUtils.convertByteArrayToHexaString(cardCryptogram);
        String resultCardCrytogram = result.substring(32, result.length());

        String keyInfo = "FF02";
        String response = keyDiversification + keyInfo + SEQUENCECOUNT + CARDCHALLENGE + resultCardCrytogram;

        return response;
    }





    private static byte[] getCardCryptogram(final String hostChallengeString, final String sessionKeyStroing)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, GaiaException
    {

        String cardCryptogram = hostChallengeString + SEQUENCECOUNT + CARDCHALLENGE + "8000000000000000";
        String sessionKey = sessionKeyStroing + sessionKeyStroing.substring(0, sessionKeyStroing.length() / 2);

        Cipher cipher;
        SecretKey key = new SecretKeySpec(GaiaUtils.convertHexaStringToByteArray(sessionKey), "DESede");
        byte[] iv = new byte[8];
        IvParameterSpec parameterSpec = new IvParameterSpec(iv);
        cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        return cipher.doFinal(GaiaUtils.convertHexaStringToByteArray(cardCryptogram));
    }





    private static byte[] getSessionKey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, GaiaException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException
    {
        String constant = "0182";

        byte[] macKey = { 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46, 0x49, 0x49, 0x4A, 0x4A, 0x4C, 0x4C, 0x4F, 0x4F, 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46 };
        String derivationData = constant + SEQUENCECOUNT + "000000000000000000000000";

        Cipher cipher;
        SecretKey key = new SecretKeySpec(macKey, "DESede");
        byte[] iv = new byte[8];
        IvParameterSpec parameterSpec = new IvParameterSpec(iv);
        cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        return cipher.doFinal(GaiaUtils.convertHexaStringToByteArray(derivationData));

    }





    public static String externalUpdateCommand(final String initialResponseOrg)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, GaiaException
    {

        // 00009151026881950639FF02000D 4EB131EA95DE 5D29FCFE72F724DC
        // 84 82 00 00 10 70CA81178C079A4A 114998A816CBF511

        String initialUpdate = "8050000008EC78EEA2438008A6";
        String initialResponse = initialResponseOrg;

        String contant = "0182";
        String sequenceCount = initialResponse.substring(24, 28);

        String sessionKey = null;
        sessionKey = GaiaUtils.convertByteArrayToHexaString(hostSessionKey(contant, sequenceCount));
        System.out.println("sessionKey = " + sessionKey);

        contant = "0101";

        String cmacKey = GaiaUtils.convertByteArrayToHexaString(hostSessionKey(contant, sequenceCount));
        System.out.println("cmacKey = " + cmacKey);

        String hostChallenge = initialUpdate.substring(10, initialUpdate.length());
        String cardChallenge = initialResponse.substring(28, 40);

        String hostCryptogram = sequenceCount + cardChallenge + hostChallenge + "8000000000000000";

        hostCryptogram = getHostCryptogram(hostCryptogram, sessionKey).substring(32, hostCryptogram.length());

        return null;
    }





    private static byte[] hostSessionKey(final String contant, final String sequenceCount2)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, GaiaException
    {
        byte[] macKey = { 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46, 0x49, 0x49, 0x4A, 0x4A, 0x4C, 0x4C, 0x4F, 0x4F, 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46 };
        String sessionKey = contant + sequenceCount2 + "000000000000000000000000";

        Cipher cipher;
        SecretKey key = new SecretKeySpec(macKey, "DESede");
        byte[] iv = new byte[8];
        IvParameterSpec parameterSpec = new IvParameterSpec(iv);
        cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        return cipher.doFinal(GaiaUtils.convertHexaStringToByteArray(sessionKey));

    }





    private static String getHostCryptogram(final String hostCryptogram, final String sessionKey2)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, GaiaException
    {

        String sessionKey = sessionKey2 + sessionKey2.substring(0, sessionKey2.length() / 2);

        Cipher cipher;
        SecretKey key = new SecretKeySpec(GaiaUtils.convertHexaStringToByteArray(sessionKey), "DESede");
        byte[] iv = new byte[8];
        IvParameterSpec parameterSpec = new IvParameterSpec(iv);
        cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        return GaiaUtils.convertByteArrayToHexaString(cipher.doFinal(GaiaUtils.convertHexaStringToByteArray(hostCryptogram)));

    }

    // public static String externalAuthenticate(final String D2) throws UbiveloxException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
    // BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException, InvalidAlgorithmParameterException, GaiaException
    // {
    // String initializeUpdateResponse = Scp02.initializeUpdateResponse("8050000008EC78EEA2438008A6");
    //
    // if ( D2.equals(initializeUpdateResponse) )
    // {
    // initializeUpdateResponse += "9000";
    // }
    // else
    // {
    // initializeUpdateResponse += "6A88";
    // }
    //
    // if ( initializeUpdateResponse.substring(initializeUpdateResponse.length() - 4, initializeUpdateResponse.length())
    // .equals("9000") )
    // {
    // // 84 82 00 00 10 70CA81178C079A4A 114998A816CBF511
    // // host cryptogram과 MAC 생성
    // String D1 = "8050000008EC78EEA2438008A6";
    //
    // String hostChallenge = D1.substring(10, D1.length());
    //
    // String sequenceCounter = D2.substring(24, 28);
    //
    // String cardChallenge = D2.substring(28, 40);
    //
    // String sessionkey = getSessionKeyENC("S-ENC", sequenceCounter);
    // byte[] sessionkeyArray = GaiaUtils.convertHexaStringToByteArray(sessionkey + sessionkey.substring(0, sessionkey.length() / 2));
    //
    // String hostCryptogramTmp = Ddes.encrypt(sequenceCounter + cardChallenge + hostChallenge + "8000000000000000", "DESede", "DESede/CBC/NoPadding", sessionkeyArray);
    //
    // String hostCryptogram = hostCryptogramTmp.substring(hostCryptogramTmp.length() - 16, hostCryptogramTmp.length());
    // System.out.println(hostCryptogram);
    //
    // // S-MAC 구하고 07EFCCEB0BB0CC01 A22E0CE1E1E395F8
    //
    // sessionkey = getSessionKeyENC("C-MAC", sequenceCounter);
    // sessionkeyArray = GaiaUtils.convertHexaStringToByteArray(sessionkey);
    //
    // System.out.println("S-MAC 생성 : " + GaiaUtils.convertByteArrayToHexaString(sessionkeyArray));
    //
    // // 848200001070CA81178C079A4A8000000000000000
    // // C-MAC 구해야함 Retail Mac
    //
    // String D3 = "848200001070CA81178C079A4A114998A816CBF511";
    //
    // String dataTmp = D3.substring(0, D3.length() - 16) + "800000";
    // System.out.println("dataTmp : " + dataTmp + " / " + dataTmp.length());
    //
    // byte[] result = retailMac(sessionkeyArray, GaiaUtils.convertHexaStringToByteArray(dataTmp));
    // System.out.println("result : " + GaiaUtils.convertByteArrayToHexaString(result));
    //
    // return "848200001070CA81178C079A4A114998A816CBF511";
    // }
    // throw new UbiveloxException("일치하지 않음");
    // }
    //
    //
    //
    //
    //
    // public static byte[] retailMac(final byte[] key, final byte[] data)
    // {
    // int loc = 0;
    // byte[] edata;
    // // Create Keys
    // byte[] key1 = Arrays.copyOf(key, 8);
    // byte[] key2 = Arrays.copyOfRange(key, 8, 16);
    //
    // try
    // {
    // SecretKey ka = new SecretKeySpec(key1, "DES");
    // Cipher cipherA = Cipher.getInstance("DES/CBC/NoPadding");
    // cipherA.init(Cipher.ENCRYPT_MODE, ka, new IvParameterSpec(new byte[8]));
    //
    // SecretKey kb = new SecretKeySpec(key2, "DES");
    // Cipher cipherB = Cipher.getInstance("DES/CBC/NoPadding");
    // cipherB.init(Cipher.DECRYPT_MODE, kb, new IvParameterSpec(new byte[8]));
    //
    // // Encrypt block by block with Key-A
    // edata = cipherA.doFinal(data);
    //
    // byte[] x = new byte[8];
    // System.arraycopy(data, loc, x, 0, 8);
    //
    // edata = cipherA.doFinal(x);
    //
    // for ( loc = 8; loc < data.length; loc += 8 )
    // {
    // System.arraycopy(data, loc, x, 0, 8);
    // byte[] y = xor_array(edata, x);
    // edata = cipherA.doFinal(y);
    // }
    // // Decrypt the resulting block with Key-B
    // edata = cipherB.doFinal(edata);
    // // Encrypt the resulting block with Key-A
    // edata = cipherA.doFinal(edata);
    // }
    // catch ( Exception e )
    // {
    // e.printStackTrace();
    // return null;
    // }
    // return edata;
    // }
    //
    //
    //
    //
    //
    // private static byte[] xor_array(final byte[] aFirstArray, final byte[] aSecondArray)
    // {
    // byte[] result = new byte[aFirstArray.length];
    //
    // for ( int i = 0; i < result.length; i++ )
    // {
    // result[i] = (byte) (aFirstArray[i] ^ aSecondArray[i]);
    // }
    // return result;
    // }

}
