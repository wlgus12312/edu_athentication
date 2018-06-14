/**
 *
 */
package com.ubivelox.gaia;

/**
 * <pre>
 * com.ubivelox.securechannel
 * SecureChannelException.java
 * </pre>
 *
 * @Author : visualguide
 * @Date : 2016. 5. 10.
 * @Description :
 */
public class GaiaException extends Exception
{
	/**
	 * 
	 */
	private static final long	serialVersionUID	= -79636166592175064L;





	/**
	 * 
	 */
	public GaiaException()
	{}





	/**
	 * @param message
	 */
	public GaiaException(String message)
	{
		super(message);
	}





	/**
	 * @param cause
	 */
	public GaiaException(Throwable cause)
	{
		super(cause);
	}





	/**
	 * @param message
	 * @param cause
	 */
	public GaiaException(String message, Throwable cause)
	{
		super(message, cause);
	}





	/**
	 * @param message
	 * @param cause
	 * @param enableSuppression
	 * @param writableStackTrace
	 */
	public GaiaException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
	{
		super(message, cause, enableSuppression, writableStackTrace);
	}

}
