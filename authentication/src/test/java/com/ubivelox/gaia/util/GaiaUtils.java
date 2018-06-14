package com.ubivelox.gaia.util;

import java.util.Collection;
import java.util.Map;

import com.ubivelox.gaia.GaiaException;

public final class GaiaUtils
{// @formatter:off
    private static final String HEXSTRING[] = { "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F",
										        "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F",  
										        "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",  
										        "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F",  
										        "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F",  
										        "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",  
										        "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F",  
										        "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F",  
										        "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",  
										        "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F",  
										        "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",  
										        "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",  
										        "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",  
										        "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",  
										        "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",  
										        "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF" };

	private static final byte[]	HEXAVALUE	= new byte[] { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
													       -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
													       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };
// @formatter:on

	private GaiaUtils()
	{}





	/**
	 * <pre>
	 * 1. Summary : 
	 * 2. Details : 인자값에 null이 있으면 exception 발생, 마지막 인자가 Object[] 이면 각 Object 하나 하나 까지 체크
	 * 
	 * 3. LastModifiedDate : 
	 * 4. LastReviewedDate : 
	 * 5. History
	 * 		2016. 5. 13. writing comments
	 * 
	 * </pre>
	 *
	 * @Method Name : checkNull
	 * @param objects
	 * @throws GaiaException
	 */
	public static void checkNull(final Object... objects) throws GaiaException
	{
		if ( objects == null )
		{// checkNull(null) 이라고 호출할 경우
			throw new GaiaException("Target objects is null.");
		}

		StringBuffer sb = null;

		for ( int i = 0; i < objects.length; i++ )
		{
			if ( objects[i] == null )
			{
				// new 를 최대한 늦게 생성, buffer size 최대값을 최소화하기 위해 - i 처리
				if ( sb == null ) sb = new StringBuffer((objects.length - i) * 2);

				sb.append(i).append(",");
			}
			else if ( objects[i] instanceof Object[] && i == objects.length - 1 )
			{
				for ( int j = 0; j < ((Object[]) objects[i]).length; j++ )
				{
					if ( ((Object[]) objects[i])[j] == null )
					{
						// new 를 최대한 늦게 생성, buffer size 최대값을 최소화하기 위해 - i 처리
						if ( sb == null ) sb = new StringBuffer((((Object[]) objects[i]).length - j) * 2);

						sb.append(i + j).append(",");
					}
				}
			}
		}

		if ( sb != null )
		{
			throw new GaiaException("Target objects[" + sb.toString().substring(0, sb.length() - 1) + "] is null.");
		}
	}





	/**
	 * <pre>
	 * 1. Summary : 
	 * 2. Details : 인자값에 null이 있거나 Empty (String, byte[], Collection<?>, Map<?,?>)이 있으면 exception 발생
	 * 마지막 인자가 String[] 이면 각 String 하나 하나 까지 체크
	 * 
	 * 3. LastModifiedDate : 
	 * 4. LastReviewedDate : 
	 * 5. History
	 * 		2016. 5. 13. writing comments
	 * 
	 * </pre>
	 *
	 * @Method Name : checkNullOrEmpty
	 * @param objects
	 * @throws GaiaException
	 */
	public static void checkNullOrEmpty(final Object... objects) throws GaiaException
	{
		if ( objects == null )
		{// checkNull(null) 이라고 호출할 경우
			throw new GaiaException("Target objects is null.");
		}

		StringBuffer sbObject = null;
		StringBuffer sbString = null;
		StringBuffer sbBytes = null;
		StringBuffer sbCollection = null;
		StringBuffer sbMap = null;

		for ( int i = 0; i < objects.length; i++ )
		{
			if ( objects[i] == null )
			{
				// new 를 최대한 늦게 생성, buffer size 최대값을 최소화하기 위해 - i 처리
				if ( sbObject == null ) sbObject = new StringBuffer((objects.length - i) * 2);

				sbObject.append(i).append(",");
			}
			else if ( objects[i] instanceof String )
			{
				if ( ((String) objects[i]).isEmpty() )
				{
					// new 를 최대한 늦게 생성, buffer size 최대값을 최소화하기 위해 - i 처리
					if ( sbString == null ) sbString = new StringBuffer((objects.length - i) * 2);

					sbString.append(i).append(",");
				}
			}
			else if ( objects[i] instanceof byte[] )
			{
				if ( ((byte[]) objects[i]).length == 0 )
				{
					// new 를 최대한 늦게 생성, buffer size 최대값을 최소화하기 위해 - i 처리
					if ( sbBytes == null ) sbBytes = new StringBuffer((objects.length - i) * 2);

					sbBytes.append(i).append(",");
				}
			}
			else if ( objects[i] instanceof Collection<?> )
			{
				if ( ((Collection<?>) objects[i]).isEmpty() )
				{
					// new 를 최대한 늦게 생성, buffer size 최대값을 최소화하기 위해 - i 처리
					if ( sbCollection == null ) sbCollection = new StringBuffer((objects.length - i) * 2);

					sbCollection.append(i).append(",");
				}
			}
			else if ( objects[i] instanceof Map<?, ?> )
			{
				if ( ((Map<?, ?>) objects[i]).isEmpty() )
				{
					// new 를 최대한 늦게 생성, buffer size 최대값을 최소화하기 위해 - i 처리
					if ( sbMap == null ) sbMap = new StringBuffer((objects.length - i) * 2);

					sbMap.append(i).append(",");
				}
			}
			else if ( objects[i] instanceof String[] && objects.length - 1 == i )
			{
				for ( int j = 0; j < ((String[]) objects[i]).length; j++ )
				{
					if ( ((String[]) objects[i])[j] == null )
					{
						// new 를 최대한 늦게 생성, buffer size 최대값을 최소화하기 위해 - i 처리
						if ( sbObject == null ) sbObject = new StringBuffer((((String[]) objects[i]).length - j) * 2);

						sbObject.append(i + j).append(",");
					}
					else if ( ((String[]) objects[i])[j].isEmpty() )
					{
						// new 를 최대한 늦게 생성, buffer size 최대값을 최소화하기 위해 - i 처리
						if ( sbString == null ) sbString = new StringBuffer((((String[]) objects[i]).length - j) * 2);

						sbString.append(i + j).append(",");
					}
				}
			}
		}

		if ( sbObject != null || sbString != null || sbBytes != null || sbCollection != null || sbMap != null )
		{
			StringBuffer exceptionMessage = new StringBuffer();

			if ( sbObject != null )
			{// null 이 있는 경우
				exceptionMessage.append("Target objects[" + sbObject.toString().substring(0, sbObject.length() - 1) + "] is null");
			}

			if ( sbString != null )
			{// empty string 이 있는 경우
				exceptionMessage.append(exceptionMessage.length() == 0 ? "Target" : ",");
				exceptionMessage.append(" objects[" + sbString.toString().substring(0, sbString.length() - 1) + "] is empty String");
			}

			if ( sbBytes != null )
			{// empty byte[] 가 있는 경우
				exceptionMessage.append(exceptionMessage.length() == 0 ? "Target" : ",");
				exceptionMessage.append(" objects[" + sbBytes.toString().substring(0, sbBytes.length() - 1) + "] is empty byte[]");
			}

			if ( sbCollection != null )
			{// empty Collection 이 있는 경우
				exceptionMessage.append(exceptionMessage.length() == 0 ? "Target" : ",");
				exceptionMessage.append(" objects[" + sbCollection.toString().substring(0, sbCollection.length() - 1) + "] is empty Collection");
			}

			if ( sbMap != null )
			{// empty Map 이 있는 경우
				exceptionMessage.append(exceptionMessage.length() == 0 ? "Target" : ",");
				exceptionMessage.append(" objects[" + sbMap.toString().substring(0, sbMap.length() - 1) + "] is empty Map");
			}

			exceptionMessage.append(".");

			throw new GaiaException(exceptionMessage.toString());
		}
	}





	/**
	 * <pre>
	 * 1. Summary : 
	 * 2. Details : Hexa String 이 아니면 exception 발생
	 * 
	 * 3. LastModifiedDate : 
	 * 4. LastReviewedDate : 
	 * 5. History
	 * 		2016. 5. 13. writing comments
	 * 
	 * </pre>
	 *
	 * @Method Name : checkHexaString
	 * @param string
	 * @throws GaiaException
	 */
	public static void checkHexaString(final String... args) throws GaiaException
	{
		checkNullOrEmpty((Object[]) args);

		int i = 0;
		for ( String string : args )
		{
			if ( (string.length() & 0x01) == 1 )
			{// length is odd
				throw new GaiaException("args[" + i + "] is invalid. string length[" + string.length() + "] is not even.");
			}

			for ( int j = 0; j < string.length(); ++j )
			{
				if ( string.charAt(j) > 255 || -1 == HEXAVALUE[string.charAt(j)] )
				{
					throw new GaiaException("args[" + i + "] is invalid. string[" + j + "] is not a hexadigit.");
				}
			}
			++i;
		}
	}





	/**
	 * <pre>
	 * 1. Summary : 
	 * 2. Details : 한 byte 를 hexa string 으로 변환
	 * 
	 * 3. LastModifiedDate : 
	 * 4. LastReviewedDate : 
	 * 5. History
	 * 		2016. 5. 24. writing comments
	 * 
	 * </pre>
	 *
	 * @Method Name : convertByteToHexaString
	 * @param b
	 * @return
	 */
	public static String convertByteToHexaString(byte b)
	{
		return HEXSTRING[(int) b & 0xFF];
	}





	/**
	 * <pre>
	 * 1. Summary : 
	 * 2. Details : byte[] 을 hexa string 으로 변환, 입력 데이터가 null 이거나 empty 일경우 exception 발생
	 * 
	 * 3. LastModifiedDate : 
	 * 4. LastReviewedDate : 
	 * 5. History
	 * 		2016. 5. 16. writing comments
	 * 
	 * </pre>
	 *
	 * @Method Name : convertByteArrayToHexaString
	 * @param data
	 * @return
	 * @throws GaiaException
	 */
	public static String convertByteArrayToHexaString(final byte[] data) throws GaiaException
	{
		checkNullOrEmpty(data);

		StringBuffer result = new StringBuffer(data.length * 2);

		for ( byte b : data )
		{
			result.append(convertByteToHexaString(b));
		}

		return result.toString();
	}





	/**
	 * <pre>
	 * 1. Summary : 
	 * 2. Details : Hexa String 을 byte[] 로 변환, 입력 데이터가 hexa string 이 아닐 경우 exception 발생
	 * 
	 * 3. LastModifiedDate : 
	 * 4. LastReviewedDate : 
	 * 5. History
	 * 		2016. 5. 16. writing comments
	 * 
	 * </pre>
	 *
	 * @Method Name : convertHexaStringToByteArray
	 * @param data
	 * @return
	 * @throws GaiaException
	 */
	public static byte[] convertHexaStringToByteArray(final String data) throws GaiaException
	{
		checkHexaString(data);

		byte[] result = new byte[data.length() / 2];

		for ( int i = 0; i < result.length; ++i )
		{
			result[i] = (byte) ((HEXAVALUE[data.charAt(i * 2)] << 4) + HEXAVALUE[data.charAt(i * 2 + 1)]);
		}

		return result;
	}





	/**
	 * <pre>
	 * 1. Summary : 
	 * 2. Details : hexa string, 80...0 padding, packed block size
	 * 
	 * 3. LastModifiedDate : 
	 * 4. LastReviewedDate : 
	 * 5. History
	 * 		2016. 5. 11. writing comments
	 * 
	 * </pre>
	 *
	 * @Method Name : oneAndZeroesPadding
	 * @param orgData
	 * @param blockSize
	 * @return
	 * @throws GaiaException
	 */
	public static String oneAndZeroesPadding(final String orgData, final int blockSize) throws GaiaException
	{
		//check orgData
		checkHexaString(orgData);

		if ( blockSize < 1 )
		{
			throw new GaiaException("blockSize[" + blockSize + "] is less than 1.");
		}

		if ( blockSize == 8 )
		{
			return orgData + "8000000000000000".substring(0, 16 - (orgData.length() % 16));
		}

		if ( blockSize == 16 )
		{
			return orgData + "80000000000000000000000000000000".substring(0, 32 - (orgData.length() % 32));
		}

		StringBuilder sb = new StringBuilder(orgData.length() + blockSize);

		sb.append(orgData).append("80");

		int leftBytes = blockSize - orgData.length() / 2 % blockSize;

		while ( --leftBytes != 0 )
		{
			sb.append("00");
		}

		return sb.toString();
	}





	/**
	 * <pre>
	 * 1. Summary : 
	 * 2. Details : unpacked string, 80...0 padding, packed block size = 8
	 * 
	 * 3. LastModifiedDate : 
	 * 4. LastReviewedDate : 
	 * 5. History
	 * 		2016. 5. 11. writing comments
	 * 
	 * </pre>
	 *
	 * @Method Name : oneAndZeroesPadding
	 * @param orgData
	 * @return
	 * @throws GaiaException
	 */
	public static String oneAndZeroesPadding(final String orgData) throws GaiaException
	{
		return oneAndZeroesPadding(orgData, 8);
	}





	/**
	 * <pre>
	 * 1. Summary : min <= data.length <= max 를 만족하는지 검사한다. 
	 * 2. Details : 
	 * 
	 * 3. LastModifiedDate : 
	 * 4. LastReviewedDate : 
	 * 5. History
	 * 		2016. 5. 12. writing comments
	 * 
	 * </pre>
	 *
	 * @param data
	 * @param minLength
	 * @param maxLength
	 * @throws GaiaException
	 */
	public static void checkLength(final String data, final int minLength, final int maxLength) throws GaiaException
	{
		checkNullOrEmpty(data);

		if ( data.length() < minLength || maxLength < data.length() )
		{
			throw new GaiaException("data length[" + data.length() + "] is not between " + minLength + " and " + maxLength + ".");
		}
	}





	public static String concateString(final String arg0, final String arg1, final String... args) throws GaiaException
	{
		checkNull(arg0, arg1, args);

		StringBuffer sb = new StringBuffer().append(arg0).append(arg1);

		for ( String string : args )
		{
			sb.append(string);
		}

		return sb.toString();
	}
}
