package com.ubivelox.authentication.capduService;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import com.ubivelox.authentication.exception.UbiveloxException;
import com.ubivelox.gaia.GaiaException;
import com.ubivelox.gaia.util.GaiaUtils;

public class CapduServiceImpl implements CapduService
{

    TerminalFactory terminalFactory = null;
    CardTerminals   cardTerminals   = null;
    CardTerminal    cardTerminal    = null;
    Card            card            = null;





    @Override
    public String sendApdu(final String apdu) throws GaiaException, UbiveloxException, CardException
    {
        try
        {

            // 템플리트, 생성자를 통해서 생성
            if ( this.terminalFactory == null )
            {

                this.terminalFactory = TerminalFactory.getDefault();
                this.cardTerminals = this.terminalFactory.terminals();
                this.cardTerminal = this.cardTerminals.list()
                                                      .get(0);
                this.card = this.cardTerminal.connect("T=0");
            }

            CardChannel cardChannel = this.card.getBasicChannel();

            CommandAPDU cApdu = new CommandAPDU(GaiaUtils.convertHexaStringToByteArray(apdu));

            ResponseAPDU responseApdu = cardChannel.transmit(cApdu);

            byte[] capduByte = responseApdu.getBytes();

            String capduString = GaiaUtils.convertByteArrayToHexaString(capduByte);

            return capduString;
        }
        // 9000 체크하여 에러 발생
        catch ( CardException e )
        {
            throw new UbiveloxException("카드 에러");
        }

    }

}
