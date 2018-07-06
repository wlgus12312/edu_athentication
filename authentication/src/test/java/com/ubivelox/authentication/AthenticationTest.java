package com.ubivelox.authentication;

import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CardException;

import org.junit.Test;
import org.powermock.api.mockito.PowerMockito;
import org.slf4j.LoggerFactory;

import com.ubivelox.authentication.capduService.CapduService;
import com.ubivelox.authentication.capduService.CapduServiceImpl;
import com.ubivelox.authentication.exception.UbiveloxException;
import com.ubivelox.gaia.GaiaException;

import ch.qos.logback.classic.Logger;

// @RunWith(PowerMockRunner.class)
// @PrepareForTest(CApduService.class)
public class AthenticationTest
{

    static Logger LOGGER = (Logger) LoggerFactory.getLogger(AthenticationTest.class);

    // SCP01
    // D1 : 80 50 00 00 08 0000000000000000
    // D2 : 00005314D00E1E48570F010106BCEB4E0723EE1AFF3DE22034C021A6
    // D3 : 848200001047467AC5E61B724BA4387CE6236BA659

    // SCP02
    // D1 : 8050000008 EC78EEA2438008A6
    // D2 : 00009151026881950639FF02000D 4EB131EA95DE 5D29FCFE72F724DC
    // D3 : 8482000010 70CA81178C079A4A114998A816CBF511

    // OK
    // 8050000008 129662F59920C835
    // 00009151026881950639 0102 000A 381AD0F53984 9DBF08E431EDC88A
    // 8482030010 4EDEB2A02F676522 F80AA680FE762E76

    // OK
    // 8050000008276B46913289214B
    // 00009151026881950639 0102 000B D547B3AA4F2E A6EEE912DF2E44A4
    // 8482030010 0186640BBDBA5D37 E484BFC0B63996E6

    // OK
    // 80500000083A492DC3FA86384C
    // 00009151026881950639 0102 000C 1CDDC545ED09 92D8F0BB71A35D9F
    // 8482030010 DF15C0C6C1351EE0 42084673FA5A46C3

    // OK
    // 80500000085A9FEC552345B239
    // 00009151026881950639 0102 000D AE37775A85C8 03EB4515F28E9956
    // 8482030010 03D59CBCB2341016 FC86E4999C913D33

    // OK
    // 8050000008C4DF0A31CD8B4D95
    // 00009151026881950639 0102 000E 20E75E9D474F41F0C7F7D0DB7F5B
    // 84820300105D28FF04DF25F04A CE782987DD84DBDA

    // OK
    // 805000000856E75049691AE308
    // 000091510268819506390102000F 767538D9E255459C4DAFFC13FEAE
    // 8482030010FD13EE725A87FF67 514CB94EC62177B5

    // OK
    // 80500000086490AE0212C81FFC
    // 0000915102688195063901020010 468755CE6D49C7053CD4399D2A29
    // 84820300107BE04857CC6ABDDB 714A2181489D1A34

    // ENC Key : 404043434545464649494A4A4C4C4F4F
    // MAC Key : 404043434545464649494A4A4C4C4F4F
    // DE Key : 404043434545464649494A4A4C4C4F4F





    // ENC Key : 404043434545464649494A4A4C4C4F4F
    // MAC Key : 505053535555565659595A5A5C5C5F5F
    // DE Key : 606063636565666669696A6A6C6C6F6F

    @Test
    public void testPutKey2() throws Exception
    {
        Card offcard = new Card();

        offcard.setInitializeUpdate_C_APDU("8050000008208D951D91771901");
        offcard.setExternalAuthenticate_C_APDU("8482000010");

        Key key = new Key();

        key.setENCKey_MK("404043434545464649494A4A4C4C4F4F");
        key.setMACKey_MK("404043434545464649494A4A4C4C4F4F");
        key.setDEKKey_MK("404043434545464649494A4A4C4C4F4F");

        key.setENCKey("404142434445464748494A4B4C4D4E4F");
        key.setMACKey("404142434445464748494A4B4C4D4E4F");
        key.setDEKKey("404142434445464748494A4B4C4D4E4F");

        key.setENCKey_card("404142434445464748494A4B4C4D4E4F");
        key.setMACKey_card("404142434445464748494A4B4C4D4E4F");
        key.setDEKKey_card("404142434445464748494A4B4C4D4E4F");

        Athentication2 Athentication2 = new Athentication2();
        CapduService capduServiceImpl = new CapduServiceImpl();

        Athentication2.setCapduService(capduServiceImpl);

        // 셀렉트
        String APDU = "00A4040008A000000003000000";

        String capduReturnString = capduServiceImpl.sendApdu(APDU);

        if ( "9000".equals(capduReturnString.substring(capduReturnString.length() - 4, capduReturnString.length())) )
        {

            String hostChallenge = "208D951D91771901";
            offcard.setInitializeUpdate_C_APDU(Athentication2.initializeUpdate(hostChallenge, offcard));

            // 이니셜업데이트 전송
            String cardIntialResponse = capduServiceImpl.sendApdu(offcard.getInitializeUpdate_C_APDU());

            LOGGER.info("cardIntialResponse[{}]", cardIntialResponse);

            if ( "9000".equals(cardIntialResponse.substring(cardIntialResponse.length() - 4, cardIntialResponse.length())) )
            {
                cardIntialResponse = cardIntialResponse.substring(0, cardIntialResponse.length() - 4);
                // 익스터널 전송
                String external = Athentication2.externalAuthenticate(cardIntialResponse, offcard, key);

                LOGGER.info("external = [{}]", external);

                String result = capduServiceImpl.sendApdu(external);

                LOGGER.info("result = [{}]", result);

                // PUT KEY COMMAND
                if ( "9000".equals(result) )
                {
                    String sequenceCounter = cardIntialResponse.substring(24, 28);
                    String derivationKey = cardIntialResponse.substring(8, 20);
                    int scp = 1;
                    String putkeyResult = Athentication2.putKey(sequenceCounter, derivationKey, scp, offcard, key);

                    LOGGER.info("putkeyResult [{}]", putkeyResult);

                    String putkeyResponse = capduServiceImpl.sendApdu(putkeyResult);

                    LOGGER.info("putkeyResponse [{}]", putkeyResponse);

                }

            }

        }

    }





    @Test
    public void testPutKey() throws Exception
    {

        Card offcard = new Card();

        offcard.setInitializeUpdate_C_APDU("8050000008208D951D91771901");
        offcard.setExternalAuthenticate_C_APDU("8482000010");

        Key key = new Key();

        key.setENCKey_MK("404043434545464649494A4A4C4C4F4F");
        key.setMACKey_MK("404043434545464649494A4A4C4C4F4F");
        key.setDEKKey_MK("404043434545464649494A4A4C4C4F4F");

        key.setENCKey("404142434445464748494A4B4C4D4E4F");
        key.setMACKey("404142434445464748494A4B4C4D4E4F");
        key.setDEKKey("404142434445464748494A4B4C4D4E4F");

        key.setENCKey_card("404142434445464748494A4B4C4D4E4F");
        key.setMACKey_card("404142434445464748494A4B4C4D4E4F");
        key.setDEKKey_card("404142434445464748494A4B4C4D4E4F");

        Athentication2 Athentication2 = new Athentication2();

        // getMutualAuthentication(hostChallenge,offcard,key);
        // this.capduService.sendApdu(externalAuthenticate(this.capduService.sendApdu(initializeUpdate(hostChallenge, offcard)), offcard, key));

        CapduService capduServiceImpl = PowerMockito.mock(CapduService.class);// 가짜 만들기

        Athentication2.setCapduService(capduServiceImpl);
        // 셀렉트
        when(capduServiceImpl.sendApdu("00A4040008A000000003000000")).thenReturn("6F108408A000000003000000A5049F6501FF9000");
        // 이니셜 업데이트
        when(capduServiceImpl.sendApdu("8050000008AEC803799503CA34")).thenReturn("00009151026881950639010200003D029C31C78909CE7F3F937769319000");
        // 익스터널 업데이트
        when(capduServiceImpl.sendApdu("848200001024D51C0125064A5B97DEBFFBAB15A241")).thenReturn("9000");
        when(capduServiceImpl.sendApdu("80D80181430180106D6DF68177BFEF0275C1A066DB4628F7033A783A8010455C717262CA7A216EF25FC3E3A9F96C036372B58010FA5BCBD9F0E1364C340FF95F485ACCA803455EDA")).thenReturn("013A783A6372B5455EDA9000");

        // 셀렉트
        String APDU = "00A4040008A000000003000000";

        String capduReturnString = capduServiceImpl.sendApdu(APDU);

        if ( "9000".equals(capduReturnString.substring(capduReturnString.length() - 4, capduReturnString.length())) )
        {

            String hostChallenge = "AEC803799503CA34";
            offcard.setInitializeUpdate_C_APDU(Athentication2.initializeUpdate(hostChallenge, offcard));

            // 이니셜업데이트 전송
            String cardIntialResponse = capduServiceImpl.sendApdu(offcard.getInitializeUpdate_C_APDU());

            LOGGER.info("cardIntialResponse[{}]", cardIntialResponse);

            if ( "9000".equals(cardIntialResponse.substring(cardIntialResponse.length() - 4, cardIntialResponse.length())) )
            {
                cardIntialResponse = cardIntialResponse.substring(0, cardIntialResponse.length() - 4);
                // 익스터널 전송
                String external = Athentication2.externalAuthenticate(cardIntialResponse, offcard, key);

                LOGGER.info("external = [{}]", external);

                String result = capduServiceImpl.sendApdu(external);

                LOGGER.info("result = [{}]", result);

                // PUT KEY COMMAND
                if ( "9000".equals(result) )
                {
                    String sequenceCounter = cardIntialResponse.substring(24, 28);
                    String derivationKey = cardIntialResponse.substring(8, 20);
                    int scp = 2;
                    String putkeyResult = Athentication2.putKey(sequenceCounter, derivationKey, scp, offcard, key);

                    LOGGER.info("putkeyResult [{}]", putkeyResult);

                    String putkeyResponse = capduServiceImpl.sendApdu(putkeyResult);

                    LOGGER.info("putkeyResponse [{}]", putkeyResponse);

                }

            }

        }

    }





    @Test
    public void testMock() throws GaiaException, UbiveloxException, CardException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException
    {

        Key key = new Key();

        key.setENCKey_MK("404043434545464649494A4A4C4C4F4F");
        key.setMACKey_MK("404043434545464649494A4A4C4C4F4F");
        key.setDEKKey_MK("404043434545464649494A4A4C4C4F4F");

        key.setENCKey("404142434445464748494A4B4C4D4E4F");
        key.setMACKey("404142434445464748494A4B4C4D4E4F");
        key.setDEKKey("404142434445464748494A4B4C4D4E4F");

        key.setENCKey_card("404142434445464748494A4B4C4D4E4F");
        key.setMACKey_card("404142434445464748494A4B4C4D4E4F");
        key.setDEKKey_card("404142434445464748494A4B4C4D4E4F");

        Card offcard = new Card();

        offcard.setExternalAuthenticate_C_APDU("8482000010");
        offcard.setInitializeUpdate_C_APDU("8050000008C25F665A1B66F826");

        CapduService capduServiceImpl = PowerMockito.mock(CapduService.class);// 가짜 만들기
        when(capduServiceImpl.sendApdu("8050000008D1853EB979B8A918")).thenReturn("0000517786E8AA51042D010200018F3D497C0D1257C74F30E21BD3AC");
        when(capduServiceImpl.sendApdu("84820000108BD933FA46AA5EA6FF2E8FBA2D6D2E4E")).thenReturn("");
        Athentication.setCapduService(capduServiceImpl);
        Athentication.getMutualAuthentication("D1853EB979B8A918");

        LOGGER.info("result = [{}]", Athentication.externalAuthenticate(capduServiceImpl.sendApdu(Athentication.initializeUpdate("D1853EB979B8A918"))));

    }





    @Test
    public void testReadPhoto() throws Exception
    {

        Card offcard = new Card();

        offcard.setExternalAuthenticate_C_APDU("8482000010");
        offcard.setInitializeUpdate_C_APDU("8050000008C25F665A1B66F826");

        Key key = new Key();

        key.setENCKey_MK("404043434545464649494A4A4C4C4F4F");
        key.setMACKey_MK("404043434545464649494A4A4C4C4F4F");
        key.setDEKKey_MK("404043434545464649494A4A4C4C4F4F");

        key.setENCKey("404142434445464748494A4B4C4D4E4F");
        key.setMACKey("404142434445464748494A4B4C4D4E4F");
        key.setDEKKey("404142434445464748494A4B4C4D4E4F");

        key.setENCKey_card("404142434445464748494A4B4C4D4E4F");
        key.setMACKey_card("404142434445464748494A4B4C4D4E4F");
        key.setDEKKey_card("404142434445464748494A4B4C4D4E4F");

        CapduService capduServiceImpl = new CapduServiceImpl();

        String APDU = "00A4040008A000000003000000";

        String capduReturnString = capduServiceImpl.sendApdu(APDU);

        LOGGER.info("capduReturnString = [{}]", capduReturnString);

        if ( "9000".equals(capduReturnString.substring(capduReturnString.length() - 4, capduReturnString.length())) )
        {

            Athentication.setCapduService(capduServiceImpl);

            offcard.setExternalAuthenticate_C_APDU("8482000010");
            offcard.setInitializeUpdate_C_APDU("8050000008C25F665A1B66F826");

            String hostChallenge = "D1853EB979B8A918";
            // 이니셜업데이트 생성
            offcard.setInitializeUpdate_C_APDU(Athentication.initializeUpdate(hostChallenge));
            // 이니셜업데이트 전송
            String cardIntialResponse = capduServiceImpl.sendApdu(offcard.getInitializeUpdate_C_APDU());

            LOGGER.info("cardIntialResponse[{}]", cardIntialResponse);

            if ( "9000".equals(cardIntialResponse.substring(cardIntialResponse.length() - 4, cardIntialResponse.length())) )
            {

                cardIntialResponse = cardIntialResponse.substring(0, cardIntialResponse.length() - 4);
                // 익스터널 전송
                String external = Athentication.externalAuthenticate(cardIntialResponse);

                LOGGER.info("external = [{}]", external);

                String result = capduServiceImpl.sendApdu(external);

                LOGGER.info("result = [{}]", result);

            }

        }

    }





    @Test
    public void test2() throws GaiaException, UbiveloxException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            UnsupportedEncodingException, InvalidKeySpecException, InvalidAlgorithmParameterException, CardException
    {

        // settingAPDU("8050000008129662F59920C835", "000091510268819506390102000A381AD0F539849DBF08E431EDC88A", "84820300104EDEB2A02F676522F80AA680FE762E76");
        // CapduService capduServiceImpl = PowerMockito.mock(CapduService.class);// 가짜 만들기
        // // when(capduService.sendApdu("8050000008129662F59920C835")).thenReturn("000091510268819506390102000A381AD0F539849DBF08E431EDC88A");
        // // 하기전에 SELECT 하는것
        // // CAPDU >> 응답
        // // when(capduService.sendCpdu(CAPDU)).thenReturn(RAPDU);
        // when(capduServiceImpl.sendApdu("8050000008129662F59920C835")).thenReturn("000091510268819506390102000A381AD0F539849DBF08E431EDC88A");
        // when(capduServiceImpl.sendApdu("84820300104EDEB2A02F676522F80AA680FE762E76")).thenReturn("");
        // Athentication.setCapduService(capduServiceImpl);
        // Athentication.getMutualAuthentication("129662F59920C835");

        // settingAPDU("8050000008276B46913289214B", "000091510268819506390102000BD547B3AA4F2EA6EEE912DF2E44A4", "84820300100186640BBDBA5D37E484BFC0B63996E6");
        // when(capduService.sendApdu("8050000008276B46913289214B")).thenReturn("000091510268819506390102000BD547B3AA4F2EA6EEE912DF2E44A4");
        // when(capduService.sendApdu("84820300100186640BBDBA5D37E484BFC0B63996E6")).thenReturn("");
        // Athentication.setCapduService(capduService);
        // Athentication.getMutualAuthentication("276B46913289214B");
        //
        // settingAPDU("80500000083A492DC3FA86384C", "000091510268819506390102000C1CDDC545ED0992D8F0BB71A35D9F", "8482030010DF15C0C6C1351EE042084673FA5A46C3");
        // when(capduService.sendApdu("80500000083A492DC3FA86384C")).thenReturn("000091510268819506390102000C1CDDC545ED0992D8F0BB71A35D9F");
        // when(capduService.sendApdu("8482030010DF15C0C6C1351EE042084673FA5A46C3")).thenReturn("");
        // Athentication.setCapduService(capduService);
        // Athentication.getMutualAuthentication("3A492DC3FA86384C");
        //
        // settingAPDU("80500000085A9FEC552345B239", "000091510268819506390102000DAE37775A85C803EB4515F28E9956", "848203001003D59CBCB2341016FC86E4999C913D33");
        // when(capduService.sendApdu("80500000085A9FEC552345B239")).thenReturn("000091510268819506390102000DAE37775A85C803EB4515F28E9956");
        // when(capduService.sendApdu("848203001003D59CBCB2341016FC86E4999C913D33")).thenReturn("");
        // Athentication.setCapduService(capduService);
        // Athentication.getMutualAuthentication("5A9FEC552345B239");
        //
        // settingAPDU("8050000008C4DF0A31CD8B4D95", "000091510268819506390102000E20E75E9D474F41F0C7F7D0DB7F5B", "84820300105D28FF04DF25F04ACE782987DD84DBDA");
        // when(capduService.sendApdu("8050000008C4DF0A31CD8B4D95")).thenReturn("000091510268819506390102000E20E75E9D474F41F0C7F7D0DB7F5B");
        // when(capduService.sendApdu("84820300105D28FF04DF25F04ACE782987DD84DBDA")).thenReturn("");
        // Athentication.setCapduService(capduService);
        // Athentication.getMutualAuthentication("C4DF0A31CD8B4D95");
        //
        // settingAPDU("805000000856E75049691AE308", "000091510268819506390102000F767538D9E255459C4DAFFC13FEAE", "8482030010FD13EE725A87FF67514CB94EC62177B5");
        // when(capduService.sendApdu("805000000856E75049691AE308")).thenReturn("000091510268819506390102000F767538D9E255459C4DAFFC13FEAE");
        // when(capduService.sendApdu("8482030010FD13EE725A87FF67514CB94EC62177B5")).thenReturn("");
        // Athentication.setCapduService(capduService);
        // Athentication.getMutualAuthentication("56E75049691AE308");
        //
        // settingAPDU("80500000086490AE0212C81FFC", "0000915102688195063901020010468755CE6D49C7053CD4399D2A29", "84820300107BE04857CC6ABDDB714A2181489D1A34");
        // when(capduService.sendApdu("80500000086490AE0212C81FFC")).thenReturn("0000915102688195063901020010468755CE6D49C7053CD4399D2A29");
        // when(capduService.sendApdu("84820300107BE04857CC6ABDDB714A2181489D1A34")).thenReturn("");
        // Athentication.setCapduService(capduService);
        // Athentication.getMutualAuthentication("6490AE0212C81FFC");

    }

    // @Test
    // public void test() throws GaiaException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException,
    // InvalidAlgorithmParameterException
    // {
    //
    // assertEquals(OffCard.D1, Athentication.initialUpdateCommand("129662F59920C835"));
    // assertEquals(Card.D2, Athentication.initialUpdateResponseCommand(OffCard.D1));
    // assertEquals(OffCard.D3, Athentication.externalUpdateCommand(Card.D2));
    //
    // }

}
