package com.ubivelox.authentication;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CardException;

import com.ubivelox.authentication.capduService.CapduService;
import com.ubivelox.authentication.exception.UbiveloxException;
import com.ubivelox.gaia.GaiaException;
import com.ubivelox.gaia.util.GaiaUtils;

public class Athentication

{

    private static String SEQUENCECOUNT;
    private static String CARDCHALLENGE = "381AD0F53984";

    static CapduService   capduService;





    public static CapduService getCapduService()
    {
        return capduService;
    }





    public static void setCapduService(final CapduService capduService)
    {
        Athentication.capduService = capduService;
    }

    public static class OffCard
    {
        public static String InitializeUpdate_C_APDU;
        public static String ExternalAuthenticate_C_APDU;
    }

    public static class Key
    {
        public static String ENCKey_MK;
        public static String MACKey_MK;
        public static String DEKKey_MK;

        public static String ENCKey;
        public static String MACKey;
        public static String DEKKey;
     // @formatter:off
        public static byte[] ENC;

        public static byte[] MAC;

        public static byte[] DEK;

        // @formatter:on
    }





    // off-Card가 Card로 보내는 APDU
    public static String initializeUpdate(final String hexString) throws GaiaException, UbiveloxException
    {
        GaiaUtils.checkHexaString(hexString);

        if ( hexString.length() != 16 )
        {
            throw new UbiveloxException("data가 일치 하지 않음");
        }
        String hostChallenge = hexString;
        String cAPDU = OffCard.InitializeUpdate_C_APDU.substring(0, 10) + hostChallenge;

        return cAPDU;
    }





    // 실제로 동작할 때의 메소드
    public static void getMutualAuthentication(final String hostChallenge)
            throws GaiaException, UbiveloxException, CardException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException
    {

        capduService.sendApdu(externalAuthenticate(capduService.sendApdu(initializeUpdate(hostChallenge))));

    }





    public static String getSessionKeyENC(final String sessionTypeOrg, final String sequence_counter)
            throws UbiveloxException, GaiaException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException
    {
        GaiaUtils.checkNullOrEmpty(sessionTypeOrg, sequence_counter);

        byte[] sessionKey = null;
        String sessionType = "";

        if ( sessionTypeOrg.contains("MAC") )
        {
            sessionKey = GaiaUtils.convertHexaStringToByteArray(Key.MACKey + Key.MACKey.substring(0, 16));
            sessionType = "0101";
        }
        else if ( sessionTypeOrg.contains("ENC") )

        {
            sessionKey = GaiaUtils.convertHexaStringToByteArray(Key.ENCKey + Key.ENCKey.substring(0, 16));
            sessionType = "0182";
        }
        else if ( sessionTypeOrg.contains("DEK") )
        {
            sessionKey = GaiaUtils.convertHexaStringToByteArray(Key.DEKKey + Key.DEKKey.substring(0, 16));
            sessionType = "0181";
        }

        String S_ENC = Ddes.encrypt(sessionType + sequence_counter + "000000000000000000000000", "DESede", "DESede/CBC/NoPadding", GaiaUtils.convertByteArrayToHexaString(sessionKey));
        return S_ENC;
    }





    // off-Card가 Card로 보내는 ExternalAuthenticate APDU
    public static String externalAuthenticate(final String InitializeUpdate_R_APDU)
            throws UbiveloxException, GaiaException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException
    {
        GaiaUtils.checkHexaString(InitializeUpdate_R_APDU);
        // CardImpl cardImpl = new CardImpl();
        // String initializeUpdateResponse = cardImpl.sendApdu(OffCard.InitializeUpdate_C_APDU);

        // host cryptogram과 MAC 생성
        String initializeUpdate_C_APDU = OffCard.InitializeUpdate_C_APDU;

        String hostChallenge = initializeUpdate_C_APDU.substring(10, initializeUpdate_C_APDU.length());
        String sequenceCounter = InitializeUpdate_R_APDU.substring(24, 28);
        String cardChallenge = InitializeUpdate_R_APDU.substring(28, 40);

        // 노데리베이셔
        Key.ENCKey = Key.ENCKey_MK;
        Key.MACKey = Key.MACKey_MK;
        Key.DEKKey = Key.DEKKey_MK;

        // 데리베이션 암호 생성
        // Key.ENCKey = Ddes.encrypt(InitializeUpdate_R_APDU.substring(8, 20) + "F001" + InitializeUpdate_R_APDU.substring(8, 20) + "0F01",
        // "DESede",
        // "DESede/ECB/NoPadding",
        // (Key.ENCKey_MK + Key.ENCKey_MK.substring(0, 16)));
        // Key.MACKey = Ddes.encrypt(InitializeUpdate_R_APDU.substring(8, 20) + "F002" + InitializeUpdate_R_APDU.substring(8, 20) + "0F02",
        // "DESede",
        // "DESede/ECB/NoPadding",
        // Key.MACKey_MK + Key.MACKey_MK.substring(0, 16));
        // Key.DEKKey = Ddes.encrypt(InitializeUpdate_R_APDU.substring(8, 20) + "F003" + InitializeUpdate_R_APDU.substring(8, 20) + "0F03",
        // "DESede",
        // "DESede/ECB/NoPadding",
        // (Key.DEKKey_MK + Key.DEKKey_MK.substring(0, 16)));

        String sessionkey = getSessionKeyENC("ENC", sequenceCounter);

        byte[] sessionkeyByteArray = GaiaUtils.convertHexaStringToByteArray(sessionkey + sessionkey.substring(0, sessionkey.length() / 2));

        String hostCryptogramTmp = Ddes.encrypt(sequenceCounter + cardChallenge + hostChallenge + "8000000000000000",
                                                "DESede",
                                                "DESede/CBC/NoPadding",
                                                GaiaUtils.convertByteArrayToHexaString(sessionkeyByteArray));
        // String cardCryptogramTmp = Ddes.encrypt(hostChallenge + sequenceCounter + cardChallenge + "8000000000000000", "DESede", "DESede/CBC/NoPadding", sessionkeyByteArray);

        String hostCryptogram = hostCryptogramTmp.substring(hostCryptogramTmp.length() - 16, hostCryptogramTmp.length());

        sessionkey = getSessionKeyENC("MAC", sequenceCounter);

        sessionkeyByteArray = GaiaUtils.convertHexaStringToByteArray(sessionkey);

        String externalAuthenticate_C_APDU = OffCard.ExternalAuthenticate_C_APDU + hostCryptogram;

        String dataTmp = externalAuthenticate_C_APDU + "800000";

        byte[] result = Ddes.retailMac(sessionkeyByteArray, GaiaUtils.convertHexaStringToByteArray(dataTmp));

        String retailMac = GaiaUtils.convertByteArrayToHexaString(result);

        // if ( GaiaUtils.convertByteArrayToHexaString(result)
        // .equals(externalAuthenticate_C_APDU.substring(externalAuthenticate_C_APDU.length() - 16)) )
        // {
        // return OffCard.ExternalAuthenticate_C_APDU;
        // }

        return "8482000010" + hostCryptogram + retailMac;
        // throw new UbiveloxException("C-MAC 에러");
    }

    //

    // public static String initialUpdateCommand(final String data)
    // {
    // String cla = "8050000008";
    // String result = cla + data;
    // // 들어온 데이터가 렝스가 16이 아니면 익셉션처리
    //
    // return result;
    // }
    //
    //
    //
    //
    //
    // public static String initialUpdateResponseCommand(final String initialUpdateCommand) throws GaiaException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
    // InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    // {
    //
    // // CLA - 80 - 2bytes
    // // INS - 50 - 2bytes - INITIALIZE UPDATE
    // // P1 - 00 - 2bytes - Key Version Number
    // // P2 - 00 - 2bytes - Reference control parameter P2
    // // Lc - 08 - 2bytes - Length if host challenge
    // // Data - 8bytes - Host challenge
    // // Le - 00 - 2byte - 안함
    // // UPDATE Command
    // // 8050000008EC78EEA2438008A6
    //
    // // Respone
    // // key diversification data = 10 bytes
    // // key infomation = key version number, SCP02 - 2 bytes
    // // Seqeuence Count = 세션 키에 사용되는 내부에서 증가되는 카운터 - 2 bytes
    // // Card challenge = 내부적으로 생성된 난수 - 6 bytes
    // // card cryptogram = 인증 암호문 - 8 bytes
    //
    // // 00009151026881950639 FF02 000D 4EB131EA95DE 5D29FCFE72F724DC
    //
    // // 암호화 키 값 - 40 4F, DESede, CBC 모드
    // // initial chaning vector (ICV) = 0000000000000000
    //
    // // ENC Key : 404043434545464649494A4A4C4C4F4F- 0182
    // // MAC Key : 404043434545464649494A4A4C4C4F4F - 0101, 0102
    // // DE Key : 404043434545464649494A4A4C4C4F4F- 0181
    //
    // SEQUENCECOUNT = "000A";
    //
    // byte[] sessionKey = null;
    // String keyDiversification = "00009151026881950639";
    // sessionKey = getSessionKey();
    //
    // String sessionKeyStroing = GaiaUtils.convertByteArrayToHexaString(sessionKey);
    //
    // String hostChallengeString = initialUpdateCommand.substring(10, initialUpdateCommand.length());
    //
    // byte[] cardCryptogram = null;
    //
    // cardCryptogram = getCardCryptogram(hostChallengeString, sessionKeyStroing);
    //
    // String result = GaiaUtils.convertByteArrayToHexaString(cardCryptogram);
    // String resultCardCrytogram = result.substring(32, result.length());
    //
    // String keyInfo = "0102";
    // String response = keyDiversification + keyInfo + SEQUENCECOUNT + CARDCHALLENGE + resultCardCrytogram;
    //
    // return response;
    // }
    //
    //
    //
    //
    //
    // private static byte[] getCardCryptogram(final String hostChallengeString, final String sessionKeyStroing)
    // throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, GaiaException
    // {
    //
    // String cardCryptogram = hostChallengeString + SEQUENCECOUNT + CARDCHALLENGE + "8000000000000000";
    // String sessionKey = sessionKeyStroing + sessionKeyStroing.substring(0, sessionKeyStroing.length() / 2);
    //
    // Cipher cipher;
    // SecretKey key = new SecretKeySpec(GaiaUtils.convertHexaStringToByteArray(sessionKey), "DESede");
    // byte[] iv = new byte[8];
    // IvParameterSpec parameterSpec = new IvParameterSpec(iv);
    // cipher = Cipher.getInstance("DESede/CBC/NoPadding");
    // cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
    //
    // return cipher.doFinal(GaiaUtils.convertHexaStringToByteArray(cardCryptogram));
    // }
    //
    //
    //
    //
    //
    // private static byte[] getSessionKey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, GaiaException, IllegalBlockSizeException,
    // BadPaddingException, InvalidAlgorithmParameterException
    // {
    // String constant = "0182";
    //
    // byte[] macKey = { 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46, 0x49, 0x49, 0x4A, 0x4A, 0x4C, 0x4C, 0x4F, 0x4F, 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46 };
    // String derivationData = constant + SEQUENCECOUNT + "000000000000000000000000";
    //
    // Cipher cipher;
    // SecretKey key = new SecretKeySpec(macKey, "DESede");
    // byte[] iv = new byte[8];
    // IvParameterSpec parameterSpec = new IvParameterSpec(iv);
    // cipher = Cipher.getInstance("DESede/CBC/NoPadding");
    // cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
    //
    // return cipher.doFinal(GaiaUtils.convertHexaStringToByteArray(derivationData));
    //
    // }
    //
    //
    //
    //
    //
    // public static String externalUpdateCommand(final String initialResponseOrg)
    // throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, GaiaException
    // {
    //
    // String externalAuthenticate = "8482030010";
    //
    // String initialUpdate = OffCard.InitializeUpdate_C_APDU;
    // String initialResponse = initialResponseOrg;
    //
    // String contant = "0182";
    // String sequenceCount = initialResponse.substring(24, 28);
    //
    // String sessionKey = null;
    // sessionKey = GaiaUtils.convertByteArrayToHexaString(hostSessionKey(contant, sequenceCount));
    //
    // contant = "0101";
    //
    // String cmacKey = GaiaUtils.convertByteArrayToHexaString(hostSessionKey(contant, sequenceCount));
    //
    // String hostChallenge = initialUpdate.substring(10, initialUpdate.length());
    // String cardChallenge = initialResponse.substring(28, 40);
    //
    // String hostCryptogram = sequenceCount + cardChallenge + hostChallenge + "8000000000000000";
    //
    // hostCryptogram = getHostCryptogram(hostCryptogram, sessionKey).substring(32, hostCryptogram.length());
    // externalAuthenticate += hostCryptogram;
    //
    // byte[] cmacKeybyte = GaiaUtils.convertHexaStringToByteArray(cmacKey);
    //
    // String cMac = "";
    //
    // cMac = retailMac(cmacKeybyte, GaiaUtils.convertHexaStringToByteArray(externalAuthenticate + "800000"));
    //
    // // F80AA680FE762E76
    //
    // // B178DCD0B2913048
    // // 7C2EBA840372CA44
    //
    // externalAuthenticate += cMac;
    // return externalAuthenticate;
    // }
    //
    //
    //
    //
    //
    // private static String cDecrypt(final String cmacKey, final byte[] externalAuthenticate)
    // throws IllegalBlockSizeException, BadPaddingException, GaiaException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException
    // {
    // Cipher cipher;
    // SecretKey key = new SecretKeySpec(GaiaUtils.convertHexaStringToByteArray((cmacKey + cmacKey.substring(0, cmacKey.length() / 2))), "DESede");
    // byte[] iv = new byte[8];
    // IvParameterSpec parameterSpec = new IvParameterSpec(iv);
    // cipher = Cipher.getInstance("DESede/CBC/NoPadding");
    // cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
    //
    // return GaiaUtils.convertByteArrayToHexaString(cipher.doFinal(externalAuthenticate));
    // }
    //
    //
    //
    //
    //
    // private static byte[] hostSessionKey(final String contant, final String sequenceCount2)
    // throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, GaiaException
    // {
    // // byte[] macKey = { 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46, 0x49, 0x49, 0x4A, 0x4A, 0x4C, 0x4C, 0x4F, 0x4F, 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46 };
    // String sessionKey = contant + sequenceCount2 + "000000000000000000000000";
    //
    // Cipher cipher;
    // SecretKey key = null;
    // if ( contant.equals("0101") )
    // {
    // key = new SecretKeySpec(Key.MAC, "DESede");
    // }
    // else if ( contant.equals("0182") )
    // {
    //
    // key = new SecretKeySpec(Key.ENC, "DESede");
    // }
    // byte[] iv = new byte[8];
    // IvParameterSpec parameterSpec = new IvParameterSpec(iv);
    // cipher = Cipher.getInstance("DESede/CBC/NoPadding");
    // cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
    //
    // return cipher.doFinal(GaiaUtils.convertHexaStringToByteArray(sessionKey));
    //
    // }
    //
    //
    //
    //
    //
    // private static String getHostCryptogram(final String hostCryptogram, final String sessionKey2)
    // throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, GaiaException
    // {
    //
    // String sessionKey = sessionKey2 + sessionKey2.substring(0, sessionKey2.length() / 2);
    //
    // Cipher cipher;
    // SecretKey key = new SecretKeySpec(GaiaUtils.convertHexaStringToByteArray(sessionKey), "DESede");
    // byte[] iv = new byte[8];
    // IvParameterSpec parameterSpec = new IvParameterSpec(iv);
    // cipher = Cipher.getInstance("DESede/CBC/NoPadding");
    // cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
    //
    // return GaiaUtils.convertByteArrayToHexaString(cipher.doFinal(GaiaUtils.convertHexaStringToByteArray(hostCryptogram)));
    //
    // }
    //
    //
    //
    //
    //
    // public static String retailMac(final byte[] key, final byte[] data) throws GaiaException
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
    // return GaiaUtils.convertByteArrayToHexaString(edata);
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
