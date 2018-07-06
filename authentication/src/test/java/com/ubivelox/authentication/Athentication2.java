package com.ubivelox.authentication;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.smartcardio.CardException;

import org.slf4j.LoggerFactory;

import com.ubivelox.authentication.capduService.CapduService;
import com.ubivelox.authentication.exception.UbiveloxException;
import com.ubivelox.gaia.GaiaException;
import com.ubivelox.gaia.util.GaiaUtils;

import ch.qos.logback.classic.Logger;

public class Athentication2

{

    CapduService  capduService;

    static Logger LOGGER = (Logger) LoggerFactory.getLogger(Athentication2.class);





    public CapduService getCapduService()
    {
        return this.capduService;
    }





    public void setCapduService(final CapduService capduService)
    {
        this.capduService = capduService;
    }





    // off-Card가 Card로 보내는 APDU
    public String initializeUpdate(final String hexString, final Card offcard2) throws GaiaException, UbiveloxException
    {
        GaiaUtils.checkHexaString(hexString);

        if ( hexString.length() != 16 )
        {
            throw new UbiveloxException("data가 일치 하지 않음");
        }
        String hostChallenge = hexString;

        // offcard2?
        String cAPDU = offcard2.getInitializeUpdate_C_APDU()
                               .substring(0, 10)
                       + hostChallenge;

        return cAPDU;
    }





    // 실제로 동작할 때의 메소드
    public void getMutualAuthentication(final String hostChallenge)
            throws GaiaException, UbiveloxException, CardException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException
    {

        this.capduService.sendApdu(externalAuthenticate(this.capduService.sendApdu(initializeUpdate(hostChallenge, null)), null, null));

    }





    public String getSessionKeyENC(final String sessionTypeOrg, final String sequence_counter, final Key key)
            throws UbiveloxException, GaiaException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException
    {
        GaiaUtils.checkNullOrEmpty(sessionTypeOrg, sequence_counter);

        byte[] sessionKey = null;
        String sessionType = "";

        if ( sessionTypeOrg.contains("MAC") )
        {
            sessionKey = GaiaUtils.convertHexaStringToByteArray(key.getMACKey() + key.getMACKey()
                                                                                     .substring(0, 16));
            sessionType = "0101";
        }
        else if ( sessionTypeOrg.contains("ENC") )

        {
            sessionKey = GaiaUtils.convertHexaStringToByteArray(key.getENCKey() + key.getENCKey()
                                                                                     .substring(0, 16));
            sessionType = "0182";
        }
        else if ( sessionTypeOrg.contains("DEK") )
        {
            sessionKey = GaiaUtils.convertHexaStringToByteArray(key.getDEKKey() + key.getDEKKey()
                                                                                     .substring(0, 16));
            sessionType = "0181";
        }

        String S_ENC = Ddes.encrypt(sessionType + sequence_counter + "000000000000000000000000", "DESede", "DESede/CBC/NoPadding", GaiaUtils.convertByteArrayToHexaString(sessionKey));
        return S_ENC;
    }





    // off-Card가 Card로 보내는 ExternalAuthenticate APDU
    public String externalAuthenticate(final String InitializeUpdate_R_APDU, final Card offcard, final Key key)
            throws UbiveloxException, GaiaException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException
    {
        GaiaUtils.checkHexaString(InitializeUpdate_R_APDU);
        // CardImpl cardImpl = new CardImpl();
        // String initializeUpdateResponse = cardImpl.sendApdu(OffCard.InitializeUpdate_C_APDU);

        // host cryptogram과 MAC 생성

        String initializeUpdate_C_APDU = offcard.getInitializeUpdate_C_APDU();

        String hostChallenge = initializeUpdate_C_APDU.substring(10, initializeUpdate_C_APDU.length());
        String sequenceCounter = InitializeUpdate_R_APDU.substring(24, 28);
        String cardChallenge = InitializeUpdate_R_APDU.substring(28, 40);

        // 노데리베이션
        key.setENCKey(key.getENCKey_MK());
        key.setMACKey(key.getMACKey_MK());
        key.setDEKKey(key.getDEKKey_MK());

        // 데리베이션 암호 생성
        // key.setENCKey(Ddes.encrypt(InitializeUpdate_R_APDU.substring(8, 20) + "F001" + InitializeUpdate_R_APDU.substring(8, 20) + "0F01",
        // "DESede",
        // "DESede/ECB/NoPadding",
        // (key.getENCKey_MK() + key.getENCKey_MK()
        // .substring(0, 16))));
        // key.setMACKey(Ddes.encrypt(InitializeUpdate_R_APDU.substring(8, 20) + "F002" + InitializeUpdate_R_APDU.substring(8, 20) + "0F02",
        // "DESede",
        // "DESede/ECB/NoPadding",
        // key.getMACKey_MK() + key.getMACKey_MK()
        // .substring(0, 16)));
        //
        // key.setDEKKey(Ddes.encrypt(InitializeUpdate_R_APDU.substring(8, 20) + "F003" + InitializeUpdate_R_APDU.substring(8, 20) + "0F03",
        // "DESede",
        // "DESede/ECB/NoPadding",
        // (key.getDEKKey_MK() + key.getDEKKey_MK()
        // .substring(0, 16))));
        key.setENCSessionKey(this.getSessionKeyENC("ENC", sequenceCounter, key));

        byte[] sessionkeyByteArray = GaiaUtils.convertHexaStringToByteArray(key.getENCSessionKey() + key.getENCSessionKey()
                                                                                                        .substring(0,
                                                                                                                   key.getENCSessionKey()
                                                                                                                      .length() / 2));

        String hostCryptogramTmp = Ddes.encrypt(sequenceCounter + cardChallenge + hostChallenge + "8000000000000000",
                                                "DESede",
                                                "DESede/CBC/NoPadding",
                                                GaiaUtils.convertByteArrayToHexaString(sessionkeyByteArray));
        // String cardCryptogramTmp = Ddes.encrypt(hostChallenge + sequenceCounter + cardChallenge + "8000000000000000", "DESede", "DESede/CBC/NoPadding", sessionkeyByteArray);

        String hostCryptogram = hostCryptogramTmp.substring(hostCryptogramTmp.length() - 16, hostCryptogramTmp.length());

        key.setMACSessionKey(this.getSessionKeyENC("MAC", sequenceCounter, key));

        sessionkeyByteArray = GaiaUtils.convertHexaStringToByteArray(key.getMACSessionKey());

        String externalAuthenticate_C_APDU = offcard.getExternalAuthenticate_C_APDU() + hostCryptogram;

        String dataTmp = externalAuthenticate_C_APDU + "800000";

        byte[] result = Ddes.retailMac(sessionkeyByteArray, GaiaUtils.convertHexaStringToByteArray(dataTmp));

        String retailMac = GaiaUtils.convertByteArrayToHexaString(result);

        return "8482000010" + hostCryptogram + retailMac;
    }





    public String putKey(final String sequenceCounter, final String derivationKey, final int scp2, final Card offcard, final Key key)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UbiveloxException, GaiaException, IllegalBlockSizeException, BadPaddingException
    {

        String result = "";

        String encSessionKey = this.getSessionKeyENC("ENC", sequenceCounter, key);
        String dekSessionkey = this.getSessionKeyENC("DEK", sequenceCounter, key);
        String macSessionKey = this.getSessionKeyENC("MAC", sequenceCounter, key);
        // String encSessionKey = key.getENCSessionKey();
        // String dekSessionkey = key.getMACSessionKey();
        // String macSessionKey = key.getMACSessionKey();

        if ( scp2 > 1 )
        {
            // 데리베이션 암호 생성
            key.setENCKey(Ddes.encrypt(derivationKey + "F001" + derivationKey + "0F01",
                                       "DESede",
                                       "DESede/ECB/NoPadding",
                                       (key.getENCKey_MK() + key.getENCKey_MK()
                                                                .substring(0, 16))));
            key.setMACKey(Ddes.encrypt(derivationKey + "F002" + derivationKey + "0F02",
                                       "DESede",
                                       "DESede/ECB/NoPadding",
                                       key.getMACKey_MK() + key.getMACKey_MK()
                                                               .substring(0, 16)));
            key.setDEKKey(Ddes.encrypt(derivationKey + "F003" + derivationKey + "0F03",
                                       "DESede",
                                       "DESede/ECB/NoPadding",
                                       (key.getDEKKey_MK() + key.getDEKKey_MK()
                                                                .substring(0, 16))));

            String encKeyValue = putKeyEncrypt(key.getENCKey(), dekSessionkey);
            String macKeyValue = putKeyEncrypt(key.getMACKey(), dekSessionkey);
            String dekKeyValue = putKeyEncrypt(key.getDEKKey(), dekSessionkey);
            LOGGER.info("encKeyValue [{}]", encKeyValue);
            LOGGER.info("macKeyValue [{}]", macKeyValue);
            LOGGER.info("dekKeyValue [{}]", dekKeyValue);

            String encCheckValue = getCheckValue(key.getENCKey());
            String macCheckValue = getCheckValue(key.getMACKey());
            String dekCheckValue = getCheckValue(key.getDEKKey());

            LOGGER.info("encCheckValue [{}]", encCheckValue);
            LOGGER.info("macCheckValue [{}]", macCheckValue);
            LOGGER.info("dekCheckValue [{}]", dekCheckValue);

            result += "80D8018143018010" + encKeyValue + "03" + encCheckValue + "8010" + macKeyValue + "03" + macCheckValue + "8010" + dekKeyValue + "03" + dekCheckValue;
            LOGGER.info("result [{}]", result);
            return result;

        }
        else
        {

            String encKeyValue = putKeyEncrypt(key.getENCKey_card(), dekSessionkey);
            String macKeyValue = putKeyEncrypt(key.getMACKey_card(), dekSessionkey);
            String dekKeyValue = putKeyEncrypt(key.getDEKKey_card(), dekSessionkey);
            LOGGER.info("encKeyValue [{}]", encKeyValue);
            LOGGER.info("macKeyValue [{}]", macKeyValue);
            LOGGER.info("dekKeyValue [{}]", dekKeyValue);

            String encCheckValue = getCheckValue(key.getENCKey_card());
            String macCheckValue = getCheckValue(key.getMACKey_card());
            String dekCheckValue = getCheckValue(key.getDEKKey_card());

            LOGGER.info("encCheckValue [{}]", encCheckValue);
            LOGGER.info("macCheckValue [{}]", macCheckValue);
            LOGGER.info("dekCheckValue [{}]", dekCheckValue);

            result += "80D8018143018010" + encKeyValue + "03" + encCheckValue + "8010" + macKeyValue + "03" + macCheckValue + "8010" + dekKeyValue + "03" + dekCheckValue;
            LOGGER.info("result [{}]", result);
            return result;

        }

    }





    private String getCheckValue(final String sessionKey)
            throws GaiaException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException
    {

        byte[] baseKey = GaiaUtils.convertHexaStringToByteArray(sessionKey + sessionKey.substring(0, 16));

        Cipher cipher;

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");

        DESedeKeySpec desSedeKeySpec = new DESedeKeySpec(baseKey);

        SecretKey key = keyFactory.generateSecret(desSedeKeySpec);

        cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] byteCardKey = GaiaUtils.convertHexaStringToByteArray("00000000000000000000000000000000");

        byte[] result = cipher.doFinal(byteCardKey);

        return GaiaUtils.convertByteArrayToHexaString(result)
                        .substring(0, 6);

    }





    private static String putKeyEncrypt(final String cardKey, final String dekSessionkey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, GaiaException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] baseKey = GaiaUtils.convertHexaStringToByteArray(dekSessionkey + dekSessionkey.substring(0, 16));

        Cipher cipher;

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");

        DESedeKeySpec desSedeKeySpec = new DESedeKeySpec(baseKey);

        SecretKey key = keyFactory.generateSecret(desSedeKeySpec);

        cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] byteCardKey = GaiaUtils.convertHexaStringToByteArray(cardKey);

        byte[] result = cipher.doFinal(byteCardKey);

        return GaiaUtils.convertByteArrayToHexaString(result);
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
