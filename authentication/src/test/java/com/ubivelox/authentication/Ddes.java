package com.ubivelox.authentication;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.LoggerFactory;

import com.ubivelox.authentication.exception.UbiveloxException;
import com.ubivelox.gaia.GaiaException;
import com.ubivelox.gaia.util.GaiaUtils;

import ch.qos.logback.classic.Logger;

public class Ddes
{

    static Logger LOGGER = (Logger) LoggerFactory.getLogger(Ddes.class);





    // 초기화 및 키 생성
    public static Cipher setInit(final String encryptType, final int opmode, final String transformation, final byte[] baseKey)
            throws UbiveloxException, GaiaException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException
    {
        // @formatter:off
        byte[] keyData24 = new byte[] { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
                0x4D, 0x4E, 0x4F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };

        //AES
        byte[] keyData16 = new byte[] { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
                0x4D, 0x4E, 0x4F };

        //DES
        byte[] keyData8 = new byte[] { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };

        // @formatter:on

        Cipher cipher = null;

        if ( transformation.contains("DESede") )
        {

            if ( transformation.contains("CBC") )
            {
                SecretKey key = new SecretKeySpec(baseKey, encryptType);

                byte[] iv = new byte[8];
                IvParameterSpec parameterSpec = new IvParameterSpec(iv);

                try
                {
                    cipher = Cipher.getInstance(transformation);
                    cipher.init(opmode, key, parameterSpec);
                }
                catch ( Exception e )
                {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

            }
            else if ( transformation.contains("ECB") )
            {

                SecretKeyFactory keyFactory = null;

                try
                {
                    keyFactory = SecretKeyFactory.getInstance(encryptType);

                    DESedeKeySpec desSedeKeySpec = new DESedeKeySpec(baseKey);

                    SecretKey key = keyFactory.generateSecret(desSedeKeySpec);

                    cipher = Cipher.getInstance(transformation);
                    cipher.init(opmode, key);

                }
                catch ( Exception e )
                {
                    e.printStackTrace();
                    // throw new UbiveloxException("cipher 에러");
                }
            }

            // DES 8비트 키
        }
        else if ( transformation.contains("DES/CBC") )
        {
            SecretKey keySpec = null;

            keySpec = new SecretKeySpec(baseKey, encryptType);

            // iv를 0으로 초기화
            byte[] iv = new byte[8];

            IvParameterSpec parameterSpec = new IvParameterSpec(iv);

            Key key = keySpec;

            try
            {
                cipher = Cipher.getInstance(transformation);
                cipher.init(opmode, key, parameterSpec);
            }
            catch ( Exception e )
            {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        }
        else if ( transformation.contains("DES/ECB") )
        {
            SecretKeyFactory keyFactory = null;

            try
            {
                keyFactory = SecretKeyFactory.getInstance(encryptType);

                DESKeySpec desKeySpec = new DESKeySpec(keyData8);

                Key key = keyFactory.generateSecret(desKeySpec);

                cipher = Cipher.getInstance(transformation);
                cipher.init(opmode, key);

            }
            catch ( Exception e )
            {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            // AES 16비트 키
        }
        else if ( transformation.contains("AES") )
        {
            SecretKey keySpec = null;

            keySpec = new SecretKeySpec(keyData16, encryptType);

            Key key = keySpec;
            try
            {
                cipher = Cipher.getInstance(transformation);

                if ( transformation.contains("ECB") )
                {
                    cipher.init(opmode, key);

                }
                else if ( transformation.contains("CBC") )
                {
                    byte[] iv = new byte[16];
                    IvParameterSpec parameterSpec = new IvParameterSpec(iv);
                    cipher.init(opmode, key, parameterSpec);
                }

            }
            catch ( Exception e )
            {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        return cipher;
    }





    // 암호화 하기
    /*
     * encryptType : 암호화 종류 transformation : 암호화 방법
     */
    public static String encrypt(final String HexPlainText, final String encryptType, final String transformation, final String baseKey)
            throws UbiveloxException, GaiaException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException
    {
        GaiaUtils.checkNullOrEmpty(HexPlainText);
        GaiaUtils.checkHexaString(HexPlainText);

        GaiaUtils.checkNullOrEmpty(encryptType, transformation);

        byte[] bytebaseKey = GaiaUtils.convertHexaStringToByteArray(baseKey);

        Cipher cipher = setInit(encryptType, Cipher.ENCRYPT_MODE, transformation, bytebaseKey);

        byte[] inputBytes = GaiaUtils.convertHexaStringToByteArray(HexPlainText);

        byte[] outputBytes = null;
        try
        {
            outputBytes = cipher.doFinal(inputBytes);
        }
        catch ( Exception e )
        {
            // TODO Auto-generated catch block
            e.printStackTrace();

        }

        return GaiaUtils.convertByteArrayToHexaString(outputBytes);
    }





    // 복호화 하기
    public static String decrypt(final String cipherText, final String encryptType, final String transformation, final byte[] baseKey)
            throws UbiveloxException, GaiaException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException
    {
        GaiaUtils.checkNullOrEmpty(cipherText, encryptType, transformation);

        Cipher cipher = setInit(encryptType, Cipher.DECRYPT_MODE, transformation, baseKey);

        byte[] inputBytes = GaiaUtils.convertHexaStringToByteArray(cipherText);

        byte[] outputBytes = null;

        try
        {
            outputBytes = cipher.doFinal(inputBytes);
            return new String(outputBytes, "UTF8");
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }

        throw new UbiveloxException("복호화 에러");
    }





    public static String rsa(final String HexPlainText, final String encryptType) throws NoSuchAlgorithmException, NoSuchProviderException, GaiaException, InvalidKeyException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException
    {
        String strResult = "";

        GaiaUtils.checkHexaString(HexPlainText);

        // RSA 공개키/개인키를 생성한다.

        KeyPairGenerator clsKeyPairGenerator = KeyPairGenerator.getInstance(encryptType);

        clsKeyPairGenerator.initialize(2048);

        KeyPair clsKeyPair = clsKeyPairGenerator.genKeyPair();

        Key clsPublicKey = clsKeyPair.getPublic();

        Key clsPrivateKey = clsKeyPair.getPrivate();

        // KeyFactory fact = KeyFactory.getInstance(encryptType);
        // RSAPublicKeySpec publicKeySpec = fact.getKeySpec(clsPublicKey, RSAPublicKeySpec.class);
        //
        // RSAPrivateKeySpec privateKeySpec = fact.getKeySpec(clsPrivateKey, RSAPrivateKeySpec.class);
        //
        // System.out.println("public key modulus(" + publicKeySpec.getModulus() + ") exponent(" + publicKeySpec.getPublicExponent() + ")");
        // System.out.println("private key modulus(" + privateKeySpec.getModulus() + ") exponent(" + privateKeySpec.getPrivateExponent() + ")");

        // 암호화 한다.
        Cipher cipher = Cipher.getInstance(encryptType);

        cipher.init(Cipher.ENCRYPT_MODE, clsPublicKey);

        byte[] inputBytes = GaiaUtils.convertHexaStringToByteArray(HexPlainText);

        byte[] arrCipherData = cipher.doFinal(inputBytes);

        // String strCipher = new String(arrCipherData);
        // System.out.println(strCipher);
        // System.out.println();

        // 복호화 한다.
        cipher.init(Cipher.DECRYPT_MODE, clsPrivateKey);

        byte[] arrData = cipher.doFinal(arrCipherData);

        strResult = new String(arrData);

        return strResult;
    }





    public static byte[] retailMac(final byte[] key, final byte[] data) throws GaiaException
    {
        GaiaUtils.checkNullOrEmpty(key, data);
        int loc = 0;
        byte[] edata = null;
        // Create Keys
        byte[] key1 = Arrays.copyOf(key, 8);
        byte[] key2 = Arrays.copyOfRange(key, 8, 16);

        try
        {

            Cipher cipherA = Ddes.setInit("DES", Cipher.ENCRYPT_MODE, "DES/CBC/NoPadding", key1);

            Cipher cipherB = Ddes.setInit("DES", Cipher.DECRYPT_MODE, "DES/CBC/NoPadding", key2);

            byte[] x = new byte[8];
            System.arraycopy(data, loc, x, 0, 8);

            edata = cipherA.doFinal(x);

            for ( loc = 8; loc < data.length; loc += 8 )
            {
                System.arraycopy(data, loc, x, 0, 8);
                byte[] y = xor_array(edata, x);
                edata = cipherA.doFinal(y);
            }
            edata = cipherB.doFinal(edata);
            edata = cipherA.doFinal(edata);
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
        return edata;
    }





    private static byte[] xor_array(final byte[] aFirstArray, final byte[] aSecondArray) throws GaiaException
    {
        GaiaUtils.checkNullOrEmpty(aFirstArray, aSecondArray);

        byte[] result = new byte[aFirstArray.length];

        for ( int i = 0; i < result.length; i++ )
        {
            result[i] = (byte) (aFirstArray[i] ^ aSecondArray[i]);
        }
        return result;
    }





    public static String encryptEcb(final String string, final String string2, final String string3, final byte[] convertHexaStringToByteArray)
    {

        return null;
    }
}
