package com.ubivelox.gaia.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.ubivelox.gaia.GaiaException;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class GaiaUtilsTest
{
	@Test
	public void test0001_checkNull_NormalTest()
	{
		try
		{
			GaiaUtils.checkNull();
			GaiaUtils.checkNull("");
			GaiaUtils.checkNull(new Object());
			GaiaUtils.checkNull(true);
			GaiaUtils.checkNull(false);
			GaiaUtils.checkNull(0);
			GaiaUtils.checkNull(1);
			GaiaUtils.checkNull(-1);
			GaiaUtils.checkNull(0.1);
			GaiaUtils.checkNull(0x12345678);
			GaiaUtils.checkNull("", "");
			GaiaUtils.checkNull("", "", "");
			GaiaUtils.checkNull("", "", "", "");
			GaiaUtils.checkNull("", "", "", "", "");
			GaiaUtils.checkNull("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
					"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
					"", "", "", "", "", "", "", "", "", "", "", "", "");
			GaiaUtils.checkNull(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
					44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
					89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99);
		}
		catch ( GaiaException e )
		{
			e.printStackTrace();
			Assert.assertFalse(true);
		}
	}





	@Test
	public void test0002_checkNull_AbnormalTest()
	{

		try
		{
			GaiaUtils.checkNull(new Object[] { null, "6", null, "8" });
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,2] is null.", e.getMessage());
		}

		try
		{
			Object[] data = new Object[] { null, "6", null, "8" };
			GaiaUtils.checkNull(data);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,2] is null.", e.getMessage());
		}

		try
		{
			Object[] data = new Object[] { null, "6", null, "8" };
			data[3] = data;
			GaiaUtils.checkNull(data);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,2,3,5] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(new Object[] { null, "6", null, "8" }, new Object[] { null, "6", null, "8" });
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1,3] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects is null.", e.getMessage());
		}

		try
		{
			Object x = null;
			GaiaUtils.checkNull(x);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull("", null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(null, "");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(0, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(null, 1);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(null, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1] is null.", e.getMessage());
		}

		try
		{
			Object x = null;
			GaiaUtils.checkNull(x, x);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(null, null, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1,2] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(null, 1, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,2] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(null, 1, null, 3, null, 5, null, 7, null, 9, null, 11, null, 13, null, 15, null, 17, null, 19, null, 21, null, 23, null, 25, null, 27, null, 29, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
					44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
					89, 90, 91, 92, 93, 94, 95, 96, 97, 98, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[99] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
					44, 45, 46, 47, 48, null, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87,
					88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[49] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(new Object[] { null, "1", null, "3" }, new Object[] { null, "5", null, "7" }, new Object[] { null, "9", null, "11" });
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[2,4] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNull(new Object[] { null, "1", null, "3" }, null, "5", null, "7", new Object[] { null, "9", null, "11" });
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1,3,5,7] is null.", e.getMessage());
		}

		try
		{
			Object[] arg = null;
			GaiaUtils.checkNull(arg, null, "2", null, "4", new Object[] { null, "6", null, "8" }, null, "10", null, "12");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1,3,6,8] is null.", e.getMessage());
		}
	}





	@Test
	public void test0003_checkNullOrEmpty_NormalTest()
	{
		List<String> dataList;
		Map<String, String> dataMap;
		try
		{
			GaiaUtils.checkNullOrEmpty(" ");
			GaiaUtils.checkNullOrEmpty("0");
			GaiaUtils.checkNullOrEmpty(new Object());
			GaiaUtils.checkNullOrEmpty(true);
			GaiaUtils.checkNullOrEmpty(false);
			GaiaUtils.checkNullOrEmpty(0);
			GaiaUtils.checkNullOrEmpty(1);
			GaiaUtils.checkNullOrEmpty(-1);
			GaiaUtils.checkNullOrEmpty(0.1);
			GaiaUtils.checkNullOrEmpty(0x12345678);
			GaiaUtils.checkNullOrEmpty("0", "1");
			GaiaUtils.checkNullOrEmpty("0", "1", "2");
			GaiaUtils.checkNullOrEmpty("0", "1", "2", "3");
			GaiaUtils.checkNullOrEmpty("0", "1", "2", "3", "4");
			GaiaUtils.checkNullOrEmpty("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27",
					"28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57",
					"58", "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87",
					"88", "89", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99");
			GaiaUtils.checkNullOrEmpty(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
					42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
					87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99);
			GaiaUtils.checkNullOrEmpty(new byte[] { 0x00 });
			GaiaUtils.checkNullOrEmpty(new byte[] { 0x00 }, "1");
			GaiaUtils.checkNullOrEmpty(new byte[] { 0x00 }, 1);
			GaiaUtils.checkNullOrEmpty(new byte[] { 0x00 }, true);
			GaiaUtils.checkNullOrEmpty(new byte[] { 0x00 }, false);
			GaiaUtils.checkNullOrEmpty("0", new byte[] { 0x01 });
			GaiaUtils.checkNullOrEmpty(0, new byte[] { 0x01 });
			GaiaUtils.checkNullOrEmpty(true, new byte[] { 0x01 });
			GaiaUtils.checkNullOrEmpty(false, new byte[] { 0x01 });

			dataList = new ArrayList<String>();
			dataMap = new HashMap<String, String>();
			dataList.add("0");
			dataMap.put("0", "0");

			GaiaUtils.checkNullOrEmpty(dataList);
			GaiaUtils.checkNullOrEmpty(dataMap);
			GaiaUtils.checkNullOrEmpty(dataList, dataMap);
			GaiaUtils.checkNullOrEmpty(dataList, dataMap, 2);
			GaiaUtils.checkNullOrEmpty(dataList, dataMap, "2");
			GaiaUtils.checkNullOrEmpty(dataList, dataMap, true);
			GaiaUtils.checkNullOrEmpty(dataList, dataMap, false);
			GaiaUtils.checkNullOrEmpty(dataList, dataMap, new byte[] { 0x02 });
			GaiaUtils.checkNullOrEmpty(0, dataList, dataMap);
			GaiaUtils.checkNullOrEmpty("0", dataList, dataMap);
			GaiaUtils.checkNullOrEmpty(true, dataList, dataMap);
			GaiaUtils.checkNullOrEmpty(false, dataList, dataMap);
			GaiaUtils.checkNullOrEmpty(new byte[] { 0x00 }, dataList, dataMap);
		}
		catch ( GaiaException e )
		{
			e.printStackTrace();
			Assert.assertFalse(true);
		}
	}





	@Test
	public void test0004_checkNullOrEmpty_AbnormalTest()
	{
		try
		{
			GaiaUtils.checkNullOrEmpty(null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects is null.", e.getMessage());
		}

		try
		{
			Object x = null;
			GaiaUtils.checkNullOrEmpty(x);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty("0", null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty("", null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1] is null, objects[0] is empty String.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(null, "1");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(null, "");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null, objects[1] is empty String.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(0, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(null, 1);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(null, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty("", "");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1] is empty String.", e.getMessage());
		}

		try
		{
			Object x = null;
			GaiaUtils.checkNullOrEmpty(x, x);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(null, null, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1,2] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(null, 1, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,2] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(null, 1, null, 3, null, 5, null, 7, null, 9, null, 11, null, 13, null, 15, null, 17, null, 19, null, 21, null, 23, null, 25, null, 27, null, 29, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
					42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
					87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[99] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
					42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
					87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, "");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[99] is empty String.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
					42, 43, 44, 45, 46, 47, 48, null, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
					86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[49] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
					42, 43, 44, 45, 46, 47, 48, "", 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
					87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[49] is empty String.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
					42, 43, 44, 45, 46, 47, 48, null, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
					86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, "");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[49] is null, objects[99] is empty String.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
					42, 43, 44, 45, 46, 47, 48, "", 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
					87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[99] is null, objects[49] is empty String.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(new byte[] {});
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is empty byte[].", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(new byte[] {}, new byte[] {});
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1] is empty byte[].", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(new byte[] {}, 1, new byte[] {});
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,2] is empty byte[].", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(null, 1, new byte[] {});
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null, objects[2] is empty byte[].", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty("", 1, new byte[] {});
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is empty String, objects[2] is empty byte[].", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(null, "", new byte[] {});
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null, objects[1] is empty String, objects[2] is empty byte[].", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, new byte[] {}, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
					40, 41, 42, 43, 44, 45, 46, 47, 48, "", 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
					85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[99] is null, objects[49] is empty String, objects[10] is empty byte[].", e.getMessage());
		}

		try
		{
			Object data = null;
			GaiaUtils.checkNullOrEmpty(data);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			String data = null;
			GaiaUtils.checkNullOrEmpty(data);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			byte[] data = null;
			GaiaUtils.checkNullOrEmpty(data);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(new ArrayList<String>());
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is empty Collection.", e.getMessage());
		}

		try
		{
			List<String> dataList = null;
			GaiaUtils.checkNullOrEmpty(dataList);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			List<String> dataList = new ArrayList<String>();
			dataList.add("0");
			GaiaUtils.checkNullOrEmpty(dataList, new ArrayList<String>());
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1] is empty Collection.", e.getMessage());
		}

		try
		{
			List<String> dataList = new ArrayList<String>();
			dataList.add("1");
			GaiaUtils.checkNullOrEmpty(new ArrayList<String>(), dataList);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is empty Collection.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(new ArrayList<String>(), new ArrayList<String>());
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1] is empty Collection.", e.getMessage());
		}

		try
		{
			Map<String, String> dataMap = null;
			GaiaUtils.checkNullOrEmpty(dataMap);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(new HashMap<String, String>());
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is empty Map.", e.getMessage());
		}

		try
		{
			Map<String, String> dataMap = new HashMap<String, String>();
			dataMap.put("0", "0");
			GaiaUtils.checkNullOrEmpty(dataMap, new HashMap<String, String>());
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1] is empty Map.", e.getMessage());
		}

		try
		{
			Map<String, String> dataMap = new HashMap<String, String>();
			dataMap.put("1", "1");
			GaiaUtils.checkNullOrEmpty(new HashMap<String, String>(), dataMap);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is empty Map.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(null, "", new byte[] {}, new ArrayList<String>(), new HashMap<String, String>());
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null, objects[1] is empty String, objects[2] is empty byte[], objects[3] is empty Collection, objects[4] is empty Map.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkNullOrEmpty(new HashMap<String, String>(), new ArrayList<String>(), new byte[] {}, "", null);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[4] is null, objects[3] is empty String, objects[2] is empty byte[], objects[1] is empty Collection, objects[0] is empty Map.", e.getMessage());
		}
	}





	@Test
	public void test0005_checkHexaString_NormalTest()
	{
		try
		{
			GaiaUtils.checkHexaString("00");
			GaiaUtils.checkHexaString("01");
			GaiaUtils.checkHexaString("02");
			GaiaUtils.checkHexaString("03");
			GaiaUtils.checkHexaString("04");
			GaiaUtils.checkHexaString("05");
			GaiaUtils.checkHexaString("06");
			GaiaUtils.checkHexaString("07");
			GaiaUtils.checkHexaString("08");
			GaiaUtils.checkHexaString("09");
			GaiaUtils.checkHexaString("0A");
			GaiaUtils.checkHexaString("0a");
			GaiaUtils.checkHexaString("0B");
			GaiaUtils.checkHexaString("0b");
			GaiaUtils.checkHexaString("0C");
			GaiaUtils.checkHexaString("0c");
			GaiaUtils.checkHexaString("0D");
			GaiaUtils.checkHexaString("0d");
			GaiaUtils.checkHexaString("0E");
			GaiaUtils.checkHexaString("0e");
			GaiaUtils.checkHexaString("0F");
			GaiaUtils.checkHexaString("0f");
			GaiaUtils.checkHexaString("10");
			GaiaUtils.checkHexaString("11");
			GaiaUtils.checkHexaString("12");
			GaiaUtils.checkHexaString("13");
			GaiaUtils.checkHexaString("14");
			GaiaUtils.checkHexaString("15");
			GaiaUtils.checkHexaString("16");
			GaiaUtils.checkHexaString("17");
			GaiaUtils.checkHexaString("18");
			GaiaUtils.checkHexaString("19");
			GaiaUtils.checkHexaString("1A");
			GaiaUtils.checkHexaString("1a");
			GaiaUtils.checkHexaString("1B");
			GaiaUtils.checkHexaString("1b");
			GaiaUtils.checkHexaString("1C");
			GaiaUtils.checkHexaString("1c");
			GaiaUtils.checkHexaString("1D");
			GaiaUtils.checkHexaString("1d");
			GaiaUtils.checkHexaString("1E");
			GaiaUtils.checkHexaString("1e");
			GaiaUtils.checkHexaString("1F");
			GaiaUtils.checkHexaString("1f");
			GaiaUtils.checkHexaString("20");
			GaiaUtils.checkHexaString("21");
			GaiaUtils.checkHexaString("22");
			GaiaUtils.checkHexaString("23");
			GaiaUtils.checkHexaString("24");
			GaiaUtils.checkHexaString("25");
			GaiaUtils.checkHexaString("26");
			GaiaUtils.checkHexaString("27");
			GaiaUtils.checkHexaString("28");
			GaiaUtils.checkHexaString("29");
			GaiaUtils.checkHexaString("2A");
			GaiaUtils.checkHexaString("2a");
			GaiaUtils.checkHexaString("2B");
			GaiaUtils.checkHexaString("2b");
			GaiaUtils.checkHexaString("2C");
			GaiaUtils.checkHexaString("2c");
			GaiaUtils.checkHexaString("2D");
			GaiaUtils.checkHexaString("2d");
			GaiaUtils.checkHexaString("2E");
			GaiaUtils.checkHexaString("2e");
			GaiaUtils.checkHexaString("2F");
			GaiaUtils.checkHexaString("2f");
			GaiaUtils.checkHexaString("30");
			GaiaUtils.checkHexaString("31");
			GaiaUtils.checkHexaString("32");
			GaiaUtils.checkHexaString("33");
			GaiaUtils.checkHexaString("34");
			GaiaUtils.checkHexaString("35");
			GaiaUtils.checkHexaString("36");
			GaiaUtils.checkHexaString("37");
			GaiaUtils.checkHexaString("38");
			GaiaUtils.checkHexaString("39");
			GaiaUtils.checkHexaString("3A");
			GaiaUtils.checkHexaString("3a");
			GaiaUtils.checkHexaString("3B");
			GaiaUtils.checkHexaString("3b");
			GaiaUtils.checkHexaString("3C");
			GaiaUtils.checkHexaString("3c");
			GaiaUtils.checkHexaString("3D");
			GaiaUtils.checkHexaString("3d");
			GaiaUtils.checkHexaString("3E");
			GaiaUtils.checkHexaString("3e");
			GaiaUtils.checkHexaString("3F");
			GaiaUtils.checkHexaString("3f");
			GaiaUtils.checkHexaString("40");
			GaiaUtils.checkHexaString("41");
			GaiaUtils.checkHexaString("42");
			GaiaUtils.checkHexaString("43");
			GaiaUtils.checkHexaString("44");
			GaiaUtils.checkHexaString("45");
			GaiaUtils.checkHexaString("46");
			GaiaUtils.checkHexaString("47");
			GaiaUtils.checkHexaString("48");
			GaiaUtils.checkHexaString("49");
			GaiaUtils.checkHexaString("4A");
			GaiaUtils.checkHexaString("4a");
			GaiaUtils.checkHexaString("4B");
			GaiaUtils.checkHexaString("4b");
			GaiaUtils.checkHexaString("4C");
			GaiaUtils.checkHexaString("4c");
			GaiaUtils.checkHexaString("4D");
			GaiaUtils.checkHexaString("4d");
			GaiaUtils.checkHexaString("4E");
			GaiaUtils.checkHexaString("4e");
			GaiaUtils.checkHexaString("4F");
			GaiaUtils.checkHexaString("4f");
			GaiaUtils.checkHexaString("50");
			GaiaUtils.checkHexaString("51");
			GaiaUtils.checkHexaString("52");
			GaiaUtils.checkHexaString("53");
			GaiaUtils.checkHexaString("54");
			GaiaUtils.checkHexaString("55");
			GaiaUtils.checkHexaString("56");
			GaiaUtils.checkHexaString("57");
			GaiaUtils.checkHexaString("58");
			GaiaUtils.checkHexaString("59");
			GaiaUtils.checkHexaString("5A");
			GaiaUtils.checkHexaString("5a");
			GaiaUtils.checkHexaString("5B");
			GaiaUtils.checkHexaString("5b");
			GaiaUtils.checkHexaString("5C");
			GaiaUtils.checkHexaString("5c");
			GaiaUtils.checkHexaString("5D");
			GaiaUtils.checkHexaString("5d");
			GaiaUtils.checkHexaString("5E");
			GaiaUtils.checkHexaString("5e");
			GaiaUtils.checkHexaString("5F");
			GaiaUtils.checkHexaString("5f");
			GaiaUtils.checkHexaString("60");
			GaiaUtils.checkHexaString("61");
			GaiaUtils.checkHexaString("62");
			GaiaUtils.checkHexaString("63");
			GaiaUtils.checkHexaString("64");
			GaiaUtils.checkHexaString("65");
			GaiaUtils.checkHexaString("66");
			GaiaUtils.checkHexaString("67");
			GaiaUtils.checkHexaString("68");
			GaiaUtils.checkHexaString("69");
			GaiaUtils.checkHexaString("6A");
			GaiaUtils.checkHexaString("6a");
			GaiaUtils.checkHexaString("6B");
			GaiaUtils.checkHexaString("6b");
			GaiaUtils.checkHexaString("6C");
			GaiaUtils.checkHexaString("6c");
			GaiaUtils.checkHexaString("6D");
			GaiaUtils.checkHexaString("6d");
			GaiaUtils.checkHexaString("6E");
			GaiaUtils.checkHexaString("6e");
			GaiaUtils.checkHexaString("6F");
			GaiaUtils.checkHexaString("6f");
			GaiaUtils.checkHexaString("70");
			GaiaUtils.checkHexaString("71");
			GaiaUtils.checkHexaString("72");
			GaiaUtils.checkHexaString("73");
			GaiaUtils.checkHexaString("74");
			GaiaUtils.checkHexaString("75");
			GaiaUtils.checkHexaString("76");
			GaiaUtils.checkHexaString("77");
			GaiaUtils.checkHexaString("78");
			GaiaUtils.checkHexaString("79");
			GaiaUtils.checkHexaString("7A");
			GaiaUtils.checkHexaString("7a");
			GaiaUtils.checkHexaString("7B");
			GaiaUtils.checkHexaString("7b");
			GaiaUtils.checkHexaString("7C");
			GaiaUtils.checkHexaString("7c");
			GaiaUtils.checkHexaString("7D");
			GaiaUtils.checkHexaString("7d");
			GaiaUtils.checkHexaString("7E");
			GaiaUtils.checkHexaString("7e");
			GaiaUtils.checkHexaString("7F");
			GaiaUtils.checkHexaString("7f");
			GaiaUtils.checkHexaString("80");
			GaiaUtils.checkHexaString("81");
			GaiaUtils.checkHexaString("82");
			GaiaUtils.checkHexaString("83");
			GaiaUtils.checkHexaString("84");
			GaiaUtils.checkHexaString("85");
			GaiaUtils.checkHexaString("86");
			GaiaUtils.checkHexaString("87");
			GaiaUtils.checkHexaString("88");
			GaiaUtils.checkHexaString("89");
			GaiaUtils.checkHexaString("8A");
			GaiaUtils.checkHexaString("8a");
			GaiaUtils.checkHexaString("8B");
			GaiaUtils.checkHexaString("8b");
			GaiaUtils.checkHexaString("8C");
			GaiaUtils.checkHexaString("8c");
			GaiaUtils.checkHexaString("8D");
			GaiaUtils.checkHexaString("8d");
			GaiaUtils.checkHexaString("8E");
			GaiaUtils.checkHexaString("8e");
			GaiaUtils.checkHexaString("8F");
			GaiaUtils.checkHexaString("8f");
			GaiaUtils.checkHexaString("90");
			GaiaUtils.checkHexaString("91");
			GaiaUtils.checkHexaString("92");
			GaiaUtils.checkHexaString("93");
			GaiaUtils.checkHexaString("94");
			GaiaUtils.checkHexaString("95");
			GaiaUtils.checkHexaString("96");
			GaiaUtils.checkHexaString("97");
			GaiaUtils.checkHexaString("98");
			GaiaUtils.checkHexaString("99");
			GaiaUtils.checkHexaString("9A");
			GaiaUtils.checkHexaString("9a");
			GaiaUtils.checkHexaString("9B");
			GaiaUtils.checkHexaString("9b");
			GaiaUtils.checkHexaString("9C");
			GaiaUtils.checkHexaString("9c");
			GaiaUtils.checkHexaString("9D");
			GaiaUtils.checkHexaString("9d");
			GaiaUtils.checkHexaString("9E");
			GaiaUtils.checkHexaString("9e");
			GaiaUtils.checkHexaString("9F");
			GaiaUtils.checkHexaString("9f");
			GaiaUtils.checkHexaString("A0");
			GaiaUtils.checkHexaString("A1");
			GaiaUtils.checkHexaString("A2");
			GaiaUtils.checkHexaString("A3");
			GaiaUtils.checkHexaString("A4");
			GaiaUtils.checkHexaString("A5");
			GaiaUtils.checkHexaString("A6");
			GaiaUtils.checkHexaString("A7");
			GaiaUtils.checkHexaString("A8");
			GaiaUtils.checkHexaString("A9");
			GaiaUtils.checkHexaString("AA");
			GaiaUtils.checkHexaString("Aa");
			GaiaUtils.checkHexaString("AB");
			GaiaUtils.checkHexaString("Ab");
			GaiaUtils.checkHexaString("AC");
			GaiaUtils.checkHexaString("Ac");
			GaiaUtils.checkHexaString("AD");
			GaiaUtils.checkHexaString("Ad");
			GaiaUtils.checkHexaString("AE");
			GaiaUtils.checkHexaString("Ae");
			GaiaUtils.checkHexaString("AF");
			GaiaUtils.checkHexaString("Af");
			GaiaUtils.checkHexaString("a0");
			GaiaUtils.checkHexaString("a1");
			GaiaUtils.checkHexaString("a2");
			GaiaUtils.checkHexaString("a3");
			GaiaUtils.checkHexaString("a4");
			GaiaUtils.checkHexaString("a5");
			GaiaUtils.checkHexaString("a6");
			GaiaUtils.checkHexaString("a7");
			GaiaUtils.checkHexaString("a8");
			GaiaUtils.checkHexaString("a9");
			GaiaUtils.checkHexaString("aA");
			GaiaUtils.checkHexaString("aa");
			GaiaUtils.checkHexaString("aB");
			GaiaUtils.checkHexaString("ab");
			GaiaUtils.checkHexaString("aC");
			GaiaUtils.checkHexaString("ac");
			GaiaUtils.checkHexaString("aD");
			GaiaUtils.checkHexaString("ad");
			GaiaUtils.checkHexaString("aE");
			GaiaUtils.checkHexaString("ae");
			GaiaUtils.checkHexaString("aF");
			GaiaUtils.checkHexaString("af");
			GaiaUtils.checkHexaString("B0");
			GaiaUtils.checkHexaString("B1");
			GaiaUtils.checkHexaString("B2");
			GaiaUtils.checkHexaString("B3");
			GaiaUtils.checkHexaString("B4");
			GaiaUtils.checkHexaString("B5");
			GaiaUtils.checkHexaString("B6");
			GaiaUtils.checkHexaString("B7");
			GaiaUtils.checkHexaString("B8");
			GaiaUtils.checkHexaString("B9");
			GaiaUtils.checkHexaString("BA");
			GaiaUtils.checkHexaString("Ba");
			GaiaUtils.checkHexaString("BB");
			GaiaUtils.checkHexaString("Bb");
			GaiaUtils.checkHexaString("BC");
			GaiaUtils.checkHexaString("Bc");
			GaiaUtils.checkHexaString("BD");
			GaiaUtils.checkHexaString("Bd");
			GaiaUtils.checkHexaString("BE");
			GaiaUtils.checkHexaString("Be");
			GaiaUtils.checkHexaString("BF");
			GaiaUtils.checkHexaString("Bf");
			GaiaUtils.checkHexaString("b0");
			GaiaUtils.checkHexaString("b1");
			GaiaUtils.checkHexaString("b2");
			GaiaUtils.checkHexaString("b3");
			GaiaUtils.checkHexaString("b4");
			GaiaUtils.checkHexaString("b5");
			GaiaUtils.checkHexaString("b6");
			GaiaUtils.checkHexaString("b7");
			GaiaUtils.checkHexaString("b8");
			GaiaUtils.checkHexaString("b9");
			GaiaUtils.checkHexaString("bA");
			GaiaUtils.checkHexaString("ba");
			GaiaUtils.checkHexaString("bB");
			GaiaUtils.checkHexaString("bb");
			GaiaUtils.checkHexaString("bC");
			GaiaUtils.checkHexaString("bc");
			GaiaUtils.checkHexaString("bD");
			GaiaUtils.checkHexaString("bd");
			GaiaUtils.checkHexaString("bE");
			GaiaUtils.checkHexaString("be");
			GaiaUtils.checkHexaString("bF");
			GaiaUtils.checkHexaString("bf");
			GaiaUtils.checkHexaString("C0");
			GaiaUtils.checkHexaString("C1");
			GaiaUtils.checkHexaString("C2");
			GaiaUtils.checkHexaString("C3");
			GaiaUtils.checkHexaString("C4");
			GaiaUtils.checkHexaString("C5");
			GaiaUtils.checkHexaString("C6");
			GaiaUtils.checkHexaString("C7");
			GaiaUtils.checkHexaString("C8");
			GaiaUtils.checkHexaString("C9");
			GaiaUtils.checkHexaString("CA");
			GaiaUtils.checkHexaString("Ca");
			GaiaUtils.checkHexaString("CB");
			GaiaUtils.checkHexaString("Cb");
			GaiaUtils.checkHexaString("CC");
			GaiaUtils.checkHexaString("Cc");
			GaiaUtils.checkHexaString("CD");
			GaiaUtils.checkHexaString("Cd");
			GaiaUtils.checkHexaString("CE");
			GaiaUtils.checkHexaString("Ce");
			GaiaUtils.checkHexaString("CF");
			GaiaUtils.checkHexaString("Cf");
			GaiaUtils.checkHexaString("c0");
			GaiaUtils.checkHexaString("c1");
			GaiaUtils.checkHexaString("c2");
			GaiaUtils.checkHexaString("c3");
			GaiaUtils.checkHexaString("c4");
			GaiaUtils.checkHexaString("c5");
			GaiaUtils.checkHexaString("c6");
			GaiaUtils.checkHexaString("c7");
			GaiaUtils.checkHexaString("c8");
			GaiaUtils.checkHexaString("c9");
			GaiaUtils.checkHexaString("cA");
			GaiaUtils.checkHexaString("ca");
			GaiaUtils.checkHexaString("cB");
			GaiaUtils.checkHexaString("cb");
			GaiaUtils.checkHexaString("cC");
			GaiaUtils.checkHexaString("cc");
			GaiaUtils.checkHexaString("cD");
			GaiaUtils.checkHexaString("cd");
			GaiaUtils.checkHexaString("cE");
			GaiaUtils.checkHexaString("ce");
			GaiaUtils.checkHexaString("cF");
			GaiaUtils.checkHexaString("cf");
			GaiaUtils.checkHexaString("D0");
			GaiaUtils.checkHexaString("D1");
			GaiaUtils.checkHexaString("D2");
			GaiaUtils.checkHexaString("D3");
			GaiaUtils.checkHexaString("D4");
			GaiaUtils.checkHexaString("D5");
			GaiaUtils.checkHexaString("D6");
			GaiaUtils.checkHexaString("D7");
			GaiaUtils.checkHexaString("D8");
			GaiaUtils.checkHexaString("D9");
			GaiaUtils.checkHexaString("DA");
			GaiaUtils.checkHexaString("Da");
			GaiaUtils.checkHexaString("DB");
			GaiaUtils.checkHexaString("Db");
			GaiaUtils.checkHexaString("DC");
			GaiaUtils.checkHexaString("Dc");
			GaiaUtils.checkHexaString("DD");
			GaiaUtils.checkHexaString("Dd");
			GaiaUtils.checkHexaString("DE");
			GaiaUtils.checkHexaString("De");
			GaiaUtils.checkHexaString("DF");
			GaiaUtils.checkHexaString("Df");
			GaiaUtils.checkHexaString("d0");
			GaiaUtils.checkHexaString("d1");
			GaiaUtils.checkHexaString("d2");
			GaiaUtils.checkHexaString("d3");
			GaiaUtils.checkHexaString("d4");
			GaiaUtils.checkHexaString("d5");
			GaiaUtils.checkHexaString("d6");
			GaiaUtils.checkHexaString("d7");
			GaiaUtils.checkHexaString("d8");
			GaiaUtils.checkHexaString("d9");
			GaiaUtils.checkHexaString("dA");
			GaiaUtils.checkHexaString("da");
			GaiaUtils.checkHexaString("dB");
			GaiaUtils.checkHexaString("db");
			GaiaUtils.checkHexaString("dC");
			GaiaUtils.checkHexaString("dc");
			GaiaUtils.checkHexaString("dD");
			GaiaUtils.checkHexaString("dd");
			GaiaUtils.checkHexaString("dE");
			GaiaUtils.checkHexaString("de");
			GaiaUtils.checkHexaString("dF");
			GaiaUtils.checkHexaString("df");
			GaiaUtils.checkHexaString("E0");
			GaiaUtils.checkHexaString("E1");
			GaiaUtils.checkHexaString("E2");
			GaiaUtils.checkHexaString("E3");
			GaiaUtils.checkHexaString("E4");
			GaiaUtils.checkHexaString("E5");
			GaiaUtils.checkHexaString("E6");
			GaiaUtils.checkHexaString("E7");
			GaiaUtils.checkHexaString("E8");
			GaiaUtils.checkHexaString("E9");
			GaiaUtils.checkHexaString("EA");
			GaiaUtils.checkHexaString("Ea");
			GaiaUtils.checkHexaString("EB");
			GaiaUtils.checkHexaString("Eb");
			GaiaUtils.checkHexaString("EC");
			GaiaUtils.checkHexaString("Ec");
			GaiaUtils.checkHexaString("ED");
			GaiaUtils.checkHexaString("Ed");
			GaiaUtils.checkHexaString("EE");
			GaiaUtils.checkHexaString("Ee");
			GaiaUtils.checkHexaString("EF");
			GaiaUtils.checkHexaString("Ef");
			GaiaUtils.checkHexaString("e0");
			GaiaUtils.checkHexaString("e1");
			GaiaUtils.checkHexaString("e2");
			GaiaUtils.checkHexaString("e3");
			GaiaUtils.checkHexaString("e4");
			GaiaUtils.checkHexaString("e5");
			GaiaUtils.checkHexaString("e6");
			GaiaUtils.checkHexaString("e7");
			GaiaUtils.checkHexaString("e8");
			GaiaUtils.checkHexaString("e9");
			GaiaUtils.checkHexaString("eA");
			GaiaUtils.checkHexaString("ea");
			GaiaUtils.checkHexaString("eB");
			GaiaUtils.checkHexaString("eb");
			GaiaUtils.checkHexaString("eC");
			GaiaUtils.checkHexaString("ec");
			GaiaUtils.checkHexaString("eD");
			GaiaUtils.checkHexaString("ed");
			GaiaUtils.checkHexaString("eE");
			GaiaUtils.checkHexaString("ee");
			GaiaUtils.checkHexaString("eF");
			GaiaUtils.checkHexaString("ef");
			GaiaUtils.checkHexaString("F0");
			GaiaUtils.checkHexaString("F1");
			GaiaUtils.checkHexaString("F2");
			GaiaUtils.checkHexaString("F3");
			GaiaUtils.checkHexaString("F4");
			GaiaUtils.checkHexaString("F5");
			GaiaUtils.checkHexaString("F6");
			GaiaUtils.checkHexaString("F7");
			GaiaUtils.checkHexaString("F8");
			GaiaUtils.checkHexaString("F9");
			GaiaUtils.checkHexaString("FA");
			GaiaUtils.checkHexaString("Fa");
			GaiaUtils.checkHexaString("FB");
			GaiaUtils.checkHexaString("Fb");
			GaiaUtils.checkHexaString("FC");
			GaiaUtils.checkHexaString("Fc");
			GaiaUtils.checkHexaString("FD");
			GaiaUtils.checkHexaString("Fd");
			GaiaUtils.checkHexaString("FE");
			GaiaUtils.checkHexaString("Fe");
			GaiaUtils.checkHexaString("FF");
			GaiaUtils.checkHexaString("Ff");
			GaiaUtils.checkHexaString("f0");
			GaiaUtils.checkHexaString("f1");
			GaiaUtils.checkHexaString("f2");
			GaiaUtils.checkHexaString("f3");
			GaiaUtils.checkHexaString("f4");
			GaiaUtils.checkHexaString("f5");
			GaiaUtils.checkHexaString("f6");
			GaiaUtils.checkHexaString("f7");
			GaiaUtils.checkHexaString("f8");
			GaiaUtils.checkHexaString("f9");
			GaiaUtils.checkHexaString("fA");
			GaiaUtils.checkHexaString("fa");
			GaiaUtils.checkHexaString("fB");
			GaiaUtils.checkHexaString("fb");
			GaiaUtils.checkHexaString("fC");
			GaiaUtils.checkHexaString("fc");
			GaiaUtils.checkHexaString("fD");
			GaiaUtils.checkHexaString("fd");
			GaiaUtils.checkHexaString("fE");
			GaiaUtils.checkHexaString("fe");
			GaiaUtils.checkHexaString("fF");
			GaiaUtils.checkHexaString("ff");
			GaiaUtils.checkHexaString("00000000000000000000");
			GaiaUtils.checkHexaString("000102030405060708090A0a0B0b0C0c0D0d0E0e0F0f101112131415161718191A1a1B1b1C1c1D1d1E1e1F1f"
					+ "202122232425262728292A2a2B2b2C2c2D2d2E2e2F2f303132333435363738393A3a3B3b3C3c3D3d3E3e3F3f"
					+ "404142434445464748494A4a4B4b4C4c4D4d4E4e4F4f505152535455565758595A5a5B5b5C5c5D5d5E5e5F5f"
					+ "606162636465666768696A6a6B6b6C6c6D6d6E6e6F6f707172737475767778797A7a7B7b7C7c7D7d7E7e7F7f"
					+ "808182838485868788898A8a8B8b8C8c8D8d8E8e8F8f909192939495969798999A9a9B9b9C9c9D9d9E9e9F9f"
					+ "A0A1A2A3A4A5A6A7A8A9AAAaABAbACAcADAdAEAeAFAfa0a1a2a3a4a5a6a7a8a9aAaaaBabaCacaDadaEaeaFaf"
					+ "B0B1B2B3B4B5B6B7B8B9BABaBBBbBCBcBDBdBEBeBFBfb0b1b2b3b4b5b6b7b8b9bAbabBbbbCbcbDbdbEbebFbf"
					+ "C0C1C2C3C4C5C6C7C8C9CACaCBCbCCCcCDCdCECeCFCfc0c1c2c3c4c5c6c7c8c9cAcacBcbcCcccDcdcEcecFcf"
					+ "D0D1D2D3D4D5D6D7D8D9DADaDBDbDCDcDDDdDEDeDFDfd0d1d2d3d4d5d6d7d8d9dAdadBdbdCdcdDdddEdedFdf"
					+ "E0E1E2E3E4E5E6E7E8E9EAEaEBEbECEcEDEdEEEeEFEfe0e1e2e3e4e5e6e7e8e9eAeaeBebeCeceDedeEeeeFef"
					+ "F0F1F2F3F4F5F6F7F8F9FAFaFBFbFCFcFDFdFEFeFFFff0f1f2f3f4f5f6f7f8f9fAfafBfbfCfcfDfdfEfefFff");
			GaiaUtils.checkHexaString("00", "01");
			GaiaUtils.checkHexaString("00", "01", "02");
			GaiaUtils.checkHexaString("00", "01", "02", "03");
			GaiaUtils.checkHexaString("00", "01", "02", "03", "FF");
		}
		catch ( GaiaException e )
		{
			e.printStackTrace();
			Assert.assertFalse(true);
		}
	}





	@Test
	public void test0006_checkHexaString_AbnormalTest()
	{
		try
		{
			GaiaUtils.checkHexaString(null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is empty String.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string length[1] is not even.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString(" ");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string length[1] is not even.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0123456789z0123456789");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string length[21] is not even.", e.getMessage());
		}

		try
		{
			GaiaUtils
					.checkHexaString("000102030405060708090A0a0B0b0C0c0D0d0E0e0F0f101112131415161718191A1a1B1b1C1c1D1d1E1e1F1f202122232425262728292A2a2B2b2C2c2D2d2E2e2F2f303132333435363738393A3a3B3b3C3c3D3d3E3e3F3f404142434445464748494A4a4B4b4C4c4D4d4E4e4F4f505152535455565758595A5a5B5b5C5c5D5d5E5e5F5f606162636465666768696A6a6B6b6C6c6D6d6E6e6F6f707172737475767778797A7a7B7b7C7c7D7d7E7e7F7f808182838485868788898A8a8B8b8C8c8D8d8E8e8F8f909192939495969798999A9a9B9b9C9c9D9d9E9e9F9fA0A1A2A3A4A5A6A7A8A9AAAaABAbACAcADAdAEAeAFAfa0a1a2a3a4a5a6a7a8a9aAaaaBabaCacaDadaEaeaFafB0B1B2B3B4B5B6B7B8B9BABaBBBbBCBcBDBdBEBeBFBfb0b1b2b3b4b5b6b7b8b9bAbabBbbbCbcbDbdbEbebFbfC0C1C2C3C4C5C6C7C8C9CACaCBCbCCCcCDCdCECeCFCfc0c1c2c3c4c5c6c7c8c9cAcacBcbcCcccDcdcEcecFcfD0D1D2D3D4D5D6D7D8D9DADaDBDbDCDcDDDdDEDeDFDfd0d1d2d3d4d5d6d7d8d9dAdadBdbdCdcdDdddEdedFdfE0E1E2E3E4E5E6E7E8E9EAEaEBEbECEcEDEdEEEeEFEfe0e1e2e3e4e5e6e7e8e9eAeaeBebeCeceDedeEeeeFefF0F1F2F3F4F5F6F7F8F9FAFaFBFbFCFcFDFdFEFeFFFff0f1f2f3f4f5f6f7f8f9fAfafBfbfCfcfDfdfEfefFff0");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string length[969] is not even.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0 ");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0000");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0001");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0002");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0003");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0004");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0005");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0006");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0007");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0008");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0009");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\n");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u000B");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u000C");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\r");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u000E");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u000F");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0010");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0011");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0012");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0013");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0014");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0015");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0016");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0017");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0018");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0019");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u001A");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u001B");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u001C");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u001D");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u001E");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u001F");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0020");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0021");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\"");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0023");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0024");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0025");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0026");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0027");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0028");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0029");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u002A");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u002B");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u002C");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u002D");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u002E");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u002F");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u003A");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u003B");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u003C");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u003D");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u003E");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u003F");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0040");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0047");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0048");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0049");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u004A");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u004B");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u004C");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u004D");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u004E");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u004F");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0050");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0051");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0052");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0053");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0054");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0055");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0056");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0057");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0058");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0059");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u005A");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u005B");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\\");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u005D");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u005E");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u005F");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0060");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0067");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0068");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0069");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u006A");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u006B");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u006C");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u006D");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u006E");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u006F");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0070");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0071");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0072");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0073");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0074");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0075");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0076");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0077");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0078");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u0079");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u007A");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u007B");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u007C");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u007D");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u007E");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("0\u007F");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils
					.checkHexaString("00010203040506070809zz0A0a0B0b0C0c0D0d0E0e0F0f101112131415161718191A1a1B1b1C1c1D1d1E1e1F1f202122232425262728292A2a2B2b2C2c2D2d2E2e2F2f303132333435363738393A3a3B3b3C3c3D3d3E3e3F3f404142434445464748494A4a4B4b4C4c4D4d4E4e4F4f505152535455565758595A5a5B5b5C5c5D5d5E5e5F5f606162636465666768696A6a6B6b6C6c6D6d6E6e6F6f707172737475767778797A7a7B7b7C7c7D7d7E7e7F7f808182838485868788898A8a8B8b8C8c8D8d8E8e8F8f909192939495969798999A9a9B9b9C9c9D9d9E9e9F9fA0A1A2A3A4A5A6A7A8A9AAAaABAbACAcADAdAEAeAFAfa0a1a2a3a4a5a6a7a8a9aAaaaBabaCacaDadaEaeaFafB0B1B2B3B4B5B6B7B8B9BABaBBBbBCBcBDBdBEBeBFBfb0b1b2b3b4b5b6b7b8b9bAbabBbbbCbcbDbdbEbebFbfC0C1C2C3C4C5C6C7C8C9CACaCBCbCCCcCDCdCECeCFCfc0c1c2c3c4c5c6c7c8c9cAcacBcbcCcccDcdcEcecFcfD0D1D2D3D4D5D6D7D8D9DADaDBDbDCDcDDDdDEDeDFDfd0d1d2d3d4d5d6d7d8d9dAdadBdbdCdcdDdddEdedFdfE0E1E2E3E4E5E6E7E8E9EAEaEBEbECEcEDEdEEEeEFEfe0e1e2e3e4e5e6e7e8e9eAeaeBebeCeceDedeEeeeFefF0F1F2F3F4F5F6F7F8F9FAFaFBFbFCFcFDFdFEFeFFFff0f1f2f3f4f5f6f7f8f9fAfafBfbfCfcfDfdfEfefFff");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[20] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils
					.checkHexaString("000102030405060708090A0a0B0b0C0c0D0d0E0e0F0f101112131415161718191A1a1B1b1C1c1D1d1E1e1F1f202122232425262728292A2a2B2b2C2c2D2d2E2e2F2f303132333435363738393A3a3B3b3C3c3D3d3E3e3F3f404142434445464748494A4a4B4b4C4c4D4d4E4e4F4f505152535455565758595A5a5B5b5C5c5D5d5E5e5F5f606162636465666768696A6a6B6b6C6c6D6d6E6e6F6f707172737475767778797A7a7B7b7C7c7D7d7E7e7F7f808182838485868788898A8a8B8b8C8c8D8d8E8e8F8f909192939495969798999A9a9B9b9C9c9D9d9E9e9F9fA0A1A2A3A4A5A6A7A8A9AAAaABAbACAcADAdAEAeAFAfa0a1a2a3a4a5a6a7a8a9aAaaaBabaCacaDadaEaeaFafB0B1B2B3B4B5B6B7B8B9BABaBBBbBCBcBDBdBEBeBFBfb0b1b2b3b4b5b6b7b8b9bAbabBbbbCbcbDbdbEbebFbfC0C1C2C3C4C5C6C7C8C9CACaCBCbCCCcCDCdCECeCFCfc0c1c2c3c4c5c6c7c8c9cAcacBcbcCcccDcdcEcecFcfD0D1D2D3D4D5D6D7D8D9DADaDBDbDCDcDDDdDEDeDFDfd0d1d2d3d4d5d6d7d8d9dAdadBdbdCdcdDdddEdedFdfE0E1E2E3E4E5E6E7E8E9EAEaEBEbECEcEDEdEEEeEFEfe0e1e2e3e4e5e6e7e8e9eAeaeBebeCeceDedeEeeeFefF0F1F2F3F4F5F6F7F8F9FAFaFBFbFCFcFDFdFEFeFFFff0f1f2f3f4f5f6f7f8f9fAfafBfbfCfcfDfdfEfefFffzz");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[968] is not a hexadigit.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("00", null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("00", null, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1,2] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("00", "01", "02", "03", null, "05");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[4] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("00", "01", null, "03", null, "05");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[2,4] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("00", "01", null, "", null, "05");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[2,4] is null, objects[3] is empty String.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkHexaString("00", "01", "02", "03", "04", "0Z");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[5] is invalid. string[1] is not a hexadigit.", e.getMessage());
		}
	}





	@Test
	public void test0007_convertByteToHexaString_Test()
	{
		try
		{
			Assert.assertEquals("12", GaiaUtils.convertByteToHexaString((byte) 18));
			Assert.assertEquals("12", GaiaUtils.convertByteToHexaString((byte) 274));
			Assert.assertEquals("12", GaiaUtils.convertByteToHexaString((byte) 4626));
			Assert.assertEquals("12", GaiaUtils.convertByteToHexaString((byte) 1184274));

			Assert.assertEquals("00", GaiaUtils.convertByteToHexaString((byte) 0x00));
			Assert.assertEquals("01", GaiaUtils.convertByteToHexaString((byte) 0x01));
			Assert.assertEquals("02", GaiaUtils.convertByteToHexaString((byte) 0x02));
			Assert.assertEquals("03", GaiaUtils.convertByteToHexaString((byte) 0x03));
			Assert.assertEquals("04", GaiaUtils.convertByteToHexaString((byte) 0x04));
			Assert.assertEquals("05", GaiaUtils.convertByteToHexaString((byte) 0x05));
			Assert.assertEquals("06", GaiaUtils.convertByteToHexaString((byte) 0x06));
			Assert.assertEquals("07", GaiaUtils.convertByteToHexaString((byte) 0x07));
			Assert.assertEquals("08", GaiaUtils.convertByteToHexaString((byte) 0x08));
			Assert.assertEquals("09", GaiaUtils.convertByteToHexaString((byte) 0x09));
			Assert.assertEquals("0A", GaiaUtils.convertByteToHexaString((byte) 0x0A));
			Assert.assertEquals("0B", GaiaUtils.convertByteToHexaString((byte) 0x0B));
			Assert.assertEquals("0C", GaiaUtils.convertByteToHexaString((byte) 0x0C));
			Assert.assertEquals("0D", GaiaUtils.convertByteToHexaString((byte) 0x0D));
			Assert.assertEquals("0E", GaiaUtils.convertByteToHexaString((byte) 0x0E));
			Assert.assertEquals("0F", GaiaUtils.convertByteToHexaString((byte) 0x0F));
			Assert.assertEquals("10", GaiaUtils.convertByteToHexaString((byte) 0x10));
			Assert.assertEquals("11", GaiaUtils.convertByteToHexaString((byte) 0x11));
			Assert.assertEquals("12", GaiaUtils.convertByteToHexaString((byte) 0x12));
			Assert.assertEquals("13", GaiaUtils.convertByteToHexaString((byte) 0x13));
			Assert.assertEquals("14", GaiaUtils.convertByteToHexaString((byte) 0x14));
			Assert.assertEquals("15", GaiaUtils.convertByteToHexaString((byte) 0x15));
			Assert.assertEquals("16", GaiaUtils.convertByteToHexaString((byte) 0x16));
			Assert.assertEquals("17", GaiaUtils.convertByteToHexaString((byte) 0x17));
			Assert.assertEquals("18", GaiaUtils.convertByteToHexaString((byte) 0x18));
			Assert.assertEquals("19", GaiaUtils.convertByteToHexaString((byte) 0x19));
			Assert.assertEquals("1A", GaiaUtils.convertByteToHexaString((byte) 0x1A));
			Assert.assertEquals("1B", GaiaUtils.convertByteToHexaString((byte) 0x1B));
			Assert.assertEquals("1C", GaiaUtils.convertByteToHexaString((byte) 0x1C));
			Assert.assertEquals("1D", GaiaUtils.convertByteToHexaString((byte) 0x1D));
			Assert.assertEquals("1E", GaiaUtils.convertByteToHexaString((byte) 0x1E));
			Assert.assertEquals("1F", GaiaUtils.convertByteToHexaString((byte) 0x1F));
			Assert.assertEquals("20", GaiaUtils.convertByteToHexaString((byte) 0x20));
			Assert.assertEquals("21", GaiaUtils.convertByteToHexaString((byte) 0x21));
			Assert.assertEquals("22", GaiaUtils.convertByteToHexaString((byte) 0x22));
			Assert.assertEquals("23", GaiaUtils.convertByteToHexaString((byte) 0x23));
			Assert.assertEquals("24", GaiaUtils.convertByteToHexaString((byte) 0x24));
			Assert.assertEquals("25", GaiaUtils.convertByteToHexaString((byte) 0x25));
			Assert.assertEquals("26", GaiaUtils.convertByteToHexaString((byte) 0x26));
			Assert.assertEquals("27", GaiaUtils.convertByteToHexaString((byte) 0x27));
			Assert.assertEquals("28", GaiaUtils.convertByteToHexaString((byte) 0x28));
			Assert.assertEquals("29", GaiaUtils.convertByteToHexaString((byte) 0x29));
			Assert.assertEquals("2A", GaiaUtils.convertByteToHexaString((byte) 0x2A));
			Assert.assertEquals("2B", GaiaUtils.convertByteToHexaString((byte) 0x2B));
			Assert.assertEquals("2C", GaiaUtils.convertByteToHexaString((byte) 0x2C));
			Assert.assertEquals("2D", GaiaUtils.convertByteToHexaString((byte) 0x2D));
			Assert.assertEquals("2E", GaiaUtils.convertByteToHexaString((byte) 0x2E));
			Assert.assertEquals("2F", GaiaUtils.convertByteToHexaString((byte) 0x2F));
			Assert.assertEquals("30", GaiaUtils.convertByteToHexaString((byte) 0x30));
			Assert.assertEquals("31", GaiaUtils.convertByteToHexaString((byte) 0x31));
			Assert.assertEquals("32", GaiaUtils.convertByteToHexaString((byte) 0x32));
			Assert.assertEquals("33", GaiaUtils.convertByteToHexaString((byte) 0x33));
			Assert.assertEquals("34", GaiaUtils.convertByteToHexaString((byte) 0x34));
			Assert.assertEquals("35", GaiaUtils.convertByteToHexaString((byte) 0x35));
			Assert.assertEquals("36", GaiaUtils.convertByteToHexaString((byte) 0x36));
			Assert.assertEquals("37", GaiaUtils.convertByteToHexaString((byte) 0x37));
			Assert.assertEquals("38", GaiaUtils.convertByteToHexaString((byte) 0x38));
			Assert.assertEquals("39", GaiaUtils.convertByteToHexaString((byte) 0x39));
			Assert.assertEquals("3A", GaiaUtils.convertByteToHexaString((byte) 0x3A));
			Assert.assertEquals("3B", GaiaUtils.convertByteToHexaString((byte) 0x3B));
			Assert.assertEquals("3C", GaiaUtils.convertByteToHexaString((byte) 0x3C));
			Assert.assertEquals("3D", GaiaUtils.convertByteToHexaString((byte) 0x3D));
			Assert.assertEquals("3E", GaiaUtils.convertByteToHexaString((byte) 0x3E));
			Assert.assertEquals("3F", GaiaUtils.convertByteToHexaString((byte) 0x3F));
			Assert.assertEquals("40", GaiaUtils.convertByteToHexaString((byte) 0x40));
			Assert.assertEquals("41", GaiaUtils.convertByteToHexaString((byte) 0x41));
			Assert.assertEquals("42", GaiaUtils.convertByteToHexaString((byte) 0x42));
			Assert.assertEquals("43", GaiaUtils.convertByteToHexaString((byte) 0x43));
			Assert.assertEquals("44", GaiaUtils.convertByteToHexaString((byte) 0x44));
			Assert.assertEquals("45", GaiaUtils.convertByteToHexaString((byte) 0x45));
			Assert.assertEquals("46", GaiaUtils.convertByteToHexaString((byte) 0x46));
			Assert.assertEquals("47", GaiaUtils.convertByteToHexaString((byte) 0x47));
			Assert.assertEquals("48", GaiaUtils.convertByteToHexaString((byte) 0x48));
			Assert.assertEquals("49", GaiaUtils.convertByteToHexaString((byte) 0x49));
			Assert.assertEquals("4A", GaiaUtils.convertByteToHexaString((byte) 0x4A));
			Assert.assertEquals("4B", GaiaUtils.convertByteToHexaString((byte) 0x4B));
			Assert.assertEquals("4C", GaiaUtils.convertByteToHexaString((byte) 0x4C));
			Assert.assertEquals("4D", GaiaUtils.convertByteToHexaString((byte) 0x4D));
			Assert.assertEquals("4E", GaiaUtils.convertByteToHexaString((byte) 0x4E));
			Assert.assertEquals("4F", GaiaUtils.convertByteToHexaString((byte) 0x4F));
			Assert.assertEquals("50", GaiaUtils.convertByteToHexaString((byte) 0x50));
			Assert.assertEquals("51", GaiaUtils.convertByteToHexaString((byte) 0x51));
			Assert.assertEquals("52", GaiaUtils.convertByteToHexaString((byte) 0x52));
			Assert.assertEquals("53", GaiaUtils.convertByteToHexaString((byte) 0x53));
			Assert.assertEquals("54", GaiaUtils.convertByteToHexaString((byte) 0x54));
			Assert.assertEquals("55", GaiaUtils.convertByteToHexaString((byte) 0x55));
			Assert.assertEquals("56", GaiaUtils.convertByteToHexaString((byte) 0x56));
			Assert.assertEquals("57", GaiaUtils.convertByteToHexaString((byte) 0x57));
			Assert.assertEquals("58", GaiaUtils.convertByteToHexaString((byte) 0x58));
			Assert.assertEquals("59", GaiaUtils.convertByteToHexaString((byte) 0x59));
			Assert.assertEquals("5A", GaiaUtils.convertByteToHexaString((byte) 0x5A));
			Assert.assertEquals("5B", GaiaUtils.convertByteToHexaString((byte) 0x5B));
			Assert.assertEquals("5C", GaiaUtils.convertByteToHexaString((byte) 0x5C));
			Assert.assertEquals("5D", GaiaUtils.convertByteToHexaString((byte) 0x5D));
			Assert.assertEquals("5E", GaiaUtils.convertByteToHexaString((byte) 0x5E));
			Assert.assertEquals("5F", GaiaUtils.convertByteToHexaString((byte) 0x5F));
			Assert.assertEquals("60", GaiaUtils.convertByteToHexaString((byte) 0x60));
			Assert.assertEquals("61", GaiaUtils.convertByteToHexaString((byte) 0x61));
			Assert.assertEquals("62", GaiaUtils.convertByteToHexaString((byte) 0x62));
			Assert.assertEquals("63", GaiaUtils.convertByteToHexaString((byte) 0x63));
			Assert.assertEquals("64", GaiaUtils.convertByteToHexaString((byte) 0x64));
			Assert.assertEquals("65", GaiaUtils.convertByteToHexaString((byte) 0x65));
			Assert.assertEquals("66", GaiaUtils.convertByteToHexaString((byte) 0x66));
			Assert.assertEquals("67", GaiaUtils.convertByteToHexaString((byte) 0x67));
			Assert.assertEquals("68", GaiaUtils.convertByteToHexaString((byte) 0x68));
			Assert.assertEquals("69", GaiaUtils.convertByteToHexaString((byte) 0x69));
			Assert.assertEquals("6A", GaiaUtils.convertByteToHexaString((byte) 0x6A));
			Assert.assertEquals("6B", GaiaUtils.convertByteToHexaString((byte) 0x6B));
			Assert.assertEquals("6C", GaiaUtils.convertByteToHexaString((byte) 0x6C));
			Assert.assertEquals("6D", GaiaUtils.convertByteToHexaString((byte) 0x6D));
			Assert.assertEquals("6E", GaiaUtils.convertByteToHexaString((byte) 0x6E));
			Assert.assertEquals("6F", GaiaUtils.convertByteToHexaString((byte) 0x6F));
			Assert.assertEquals("70", GaiaUtils.convertByteToHexaString((byte) 0x70));
			Assert.assertEquals("71", GaiaUtils.convertByteToHexaString((byte) 0x71));
			Assert.assertEquals("72", GaiaUtils.convertByteToHexaString((byte) 0x72));
			Assert.assertEquals("73", GaiaUtils.convertByteToHexaString((byte) 0x73));
			Assert.assertEquals("74", GaiaUtils.convertByteToHexaString((byte) 0x74));
			Assert.assertEquals("75", GaiaUtils.convertByteToHexaString((byte) 0x75));
			Assert.assertEquals("76", GaiaUtils.convertByteToHexaString((byte) 0x76));
			Assert.assertEquals("77", GaiaUtils.convertByteToHexaString((byte) 0x77));
			Assert.assertEquals("78", GaiaUtils.convertByteToHexaString((byte) 0x78));
			Assert.assertEquals("79", GaiaUtils.convertByteToHexaString((byte) 0x79));
			Assert.assertEquals("7A", GaiaUtils.convertByteToHexaString((byte) 0x7A));
			Assert.assertEquals("7B", GaiaUtils.convertByteToHexaString((byte) 0x7B));
			Assert.assertEquals("7C", GaiaUtils.convertByteToHexaString((byte) 0x7C));
			Assert.assertEquals("7D", GaiaUtils.convertByteToHexaString((byte) 0x7D));
			Assert.assertEquals("7E", GaiaUtils.convertByteToHexaString((byte) 0x7E));
			Assert.assertEquals("7F", GaiaUtils.convertByteToHexaString((byte) 0x7F));

			Assert.assertEquals("80", GaiaUtils.convertByteToHexaString((byte) 0x80));
			Assert.assertEquals("81", GaiaUtils.convertByteToHexaString((byte) 0x81));
			Assert.assertEquals("82", GaiaUtils.convertByteToHexaString((byte) 0x82));
			Assert.assertEquals("83", GaiaUtils.convertByteToHexaString((byte) 0x83));
			Assert.assertEquals("84", GaiaUtils.convertByteToHexaString((byte) 0x84));
			Assert.assertEquals("85", GaiaUtils.convertByteToHexaString((byte) 0x85));
			Assert.assertEquals("86", GaiaUtils.convertByteToHexaString((byte) 0x86));
			Assert.assertEquals("87", GaiaUtils.convertByteToHexaString((byte) 0x87));
			Assert.assertEquals("88", GaiaUtils.convertByteToHexaString((byte) 0x88));
			Assert.assertEquals("89", GaiaUtils.convertByteToHexaString((byte) 0x89));
			Assert.assertEquals("8A", GaiaUtils.convertByteToHexaString((byte) 0x8A));
			Assert.assertEquals("8B", GaiaUtils.convertByteToHexaString((byte) 0x8B));
			Assert.assertEquals("8C", GaiaUtils.convertByteToHexaString((byte) 0x8C));
			Assert.assertEquals("8D", GaiaUtils.convertByteToHexaString((byte) 0x8D));
			Assert.assertEquals("8E", GaiaUtils.convertByteToHexaString((byte) 0x8E));
			Assert.assertEquals("8F", GaiaUtils.convertByteToHexaString((byte) 0x8F));
			Assert.assertEquals("90", GaiaUtils.convertByteToHexaString((byte) 0x90));
			Assert.assertEquals("91", GaiaUtils.convertByteToHexaString((byte) 0x91));
			Assert.assertEquals("92", GaiaUtils.convertByteToHexaString((byte) 0x92));
			Assert.assertEquals("93", GaiaUtils.convertByteToHexaString((byte) 0x93));
			Assert.assertEquals("94", GaiaUtils.convertByteToHexaString((byte) 0x94));
			Assert.assertEquals("95", GaiaUtils.convertByteToHexaString((byte) 0x95));
			Assert.assertEquals("96", GaiaUtils.convertByteToHexaString((byte) 0x96));
			Assert.assertEquals("97", GaiaUtils.convertByteToHexaString((byte) 0x97));
			Assert.assertEquals("98", GaiaUtils.convertByteToHexaString((byte) 0x98));
			Assert.assertEquals("99", GaiaUtils.convertByteToHexaString((byte) 0x99));
			Assert.assertEquals("9A", GaiaUtils.convertByteToHexaString((byte) 0x9A));
			Assert.assertEquals("9B", GaiaUtils.convertByteToHexaString((byte) 0x9B));
			Assert.assertEquals("9C", GaiaUtils.convertByteToHexaString((byte) 0x9C));
			Assert.assertEquals("9D", GaiaUtils.convertByteToHexaString((byte) 0x9D));
			Assert.assertEquals("9E", GaiaUtils.convertByteToHexaString((byte) 0x9E));
			Assert.assertEquals("9F", GaiaUtils.convertByteToHexaString((byte) 0x9F));
			Assert.assertEquals("A0", GaiaUtils.convertByteToHexaString((byte) 0xA0));
			Assert.assertEquals("A1", GaiaUtils.convertByteToHexaString((byte) 0xA1));
			Assert.assertEquals("A2", GaiaUtils.convertByteToHexaString((byte) 0xA2));
			Assert.assertEquals("A3", GaiaUtils.convertByteToHexaString((byte) 0xA3));
			Assert.assertEquals("A4", GaiaUtils.convertByteToHexaString((byte) 0xA4));
			Assert.assertEquals("A5", GaiaUtils.convertByteToHexaString((byte) 0xA5));
			Assert.assertEquals("A6", GaiaUtils.convertByteToHexaString((byte) 0xA6));
			Assert.assertEquals("A7", GaiaUtils.convertByteToHexaString((byte) 0xA7));
			Assert.assertEquals("A8", GaiaUtils.convertByteToHexaString((byte) 0xA8));
			Assert.assertEquals("A9", GaiaUtils.convertByteToHexaString((byte) 0xA9));
			Assert.assertEquals("AA", GaiaUtils.convertByteToHexaString((byte) 0xAA));
			Assert.assertEquals("AB", GaiaUtils.convertByteToHexaString((byte) 0xAB));
			Assert.assertEquals("AC", GaiaUtils.convertByteToHexaString((byte) 0xAC));
			Assert.assertEquals("AD", GaiaUtils.convertByteToHexaString((byte) 0xAD));
			Assert.assertEquals("AE", GaiaUtils.convertByteToHexaString((byte) 0xAE));
			Assert.assertEquals("AF", GaiaUtils.convertByteToHexaString((byte) 0xAF));
			Assert.assertEquals("B0", GaiaUtils.convertByteToHexaString((byte) 0xB0));
			Assert.assertEquals("B1", GaiaUtils.convertByteToHexaString((byte) 0xB1));
			Assert.assertEquals("B2", GaiaUtils.convertByteToHexaString((byte) 0xB2));
			Assert.assertEquals("B3", GaiaUtils.convertByteToHexaString((byte) 0xB3));
			Assert.assertEquals("B4", GaiaUtils.convertByteToHexaString((byte) 0xB4));
			Assert.assertEquals("B5", GaiaUtils.convertByteToHexaString((byte) 0xB5));
			Assert.assertEquals("B6", GaiaUtils.convertByteToHexaString((byte) 0xB6));
			Assert.assertEquals("B7", GaiaUtils.convertByteToHexaString((byte) 0xB7));
			Assert.assertEquals("B8", GaiaUtils.convertByteToHexaString((byte) 0xB8));
			Assert.assertEquals("B9", GaiaUtils.convertByteToHexaString((byte) 0xB9));
			Assert.assertEquals("BA", GaiaUtils.convertByteToHexaString((byte) 0xBA));
			Assert.assertEquals("BB", GaiaUtils.convertByteToHexaString((byte) 0xBB));
			Assert.assertEquals("BC", GaiaUtils.convertByteToHexaString((byte) 0xBC));
			Assert.assertEquals("BD", GaiaUtils.convertByteToHexaString((byte) 0xBD));
			Assert.assertEquals("BE", GaiaUtils.convertByteToHexaString((byte) 0xBE));
			Assert.assertEquals("BF", GaiaUtils.convertByteToHexaString((byte) 0xBF));
			Assert.assertEquals("C0", GaiaUtils.convertByteToHexaString((byte) 0xC0));
			Assert.assertEquals("C1", GaiaUtils.convertByteToHexaString((byte) 0xC1));
			Assert.assertEquals("C2", GaiaUtils.convertByteToHexaString((byte) 0xC2));
			Assert.assertEquals("C3", GaiaUtils.convertByteToHexaString((byte) 0xC3));
			Assert.assertEquals("C4", GaiaUtils.convertByteToHexaString((byte) 0xC4));
			Assert.assertEquals("C5", GaiaUtils.convertByteToHexaString((byte) 0xC5));
			Assert.assertEquals("C6", GaiaUtils.convertByteToHexaString((byte) 0xC6));
			Assert.assertEquals("C7", GaiaUtils.convertByteToHexaString((byte) 0xC7));
			Assert.assertEquals("C8", GaiaUtils.convertByteToHexaString((byte) 0xC8));
			Assert.assertEquals("C9", GaiaUtils.convertByteToHexaString((byte) 0xC9));
			Assert.assertEquals("CA", GaiaUtils.convertByteToHexaString((byte) 0xCA));
			Assert.assertEquals("CB", GaiaUtils.convertByteToHexaString((byte) 0xCB));
			Assert.assertEquals("CC", GaiaUtils.convertByteToHexaString((byte) 0xCC));
			Assert.assertEquals("CD", GaiaUtils.convertByteToHexaString((byte) 0xCD));
			Assert.assertEquals("CE", GaiaUtils.convertByteToHexaString((byte) 0xCE));
			Assert.assertEquals("CF", GaiaUtils.convertByteToHexaString((byte) 0xCF));
			Assert.assertEquals("D0", GaiaUtils.convertByteToHexaString((byte) 0xD0));
			Assert.assertEquals("D1", GaiaUtils.convertByteToHexaString((byte) 0xD1));
			Assert.assertEquals("D2", GaiaUtils.convertByteToHexaString((byte) 0xD2));
			Assert.assertEquals("D3", GaiaUtils.convertByteToHexaString((byte) 0xD3));
			Assert.assertEquals("D4", GaiaUtils.convertByteToHexaString((byte) 0xD4));
			Assert.assertEquals("D5", GaiaUtils.convertByteToHexaString((byte) 0xD5));
			Assert.assertEquals("D6", GaiaUtils.convertByteToHexaString((byte) 0xD6));
			Assert.assertEquals("D7", GaiaUtils.convertByteToHexaString((byte) 0xD7));
			Assert.assertEquals("D8", GaiaUtils.convertByteToHexaString((byte) 0xD8));
			Assert.assertEquals("D9", GaiaUtils.convertByteToHexaString((byte) 0xD9));
			Assert.assertEquals("DA", GaiaUtils.convertByteToHexaString((byte) 0xDA));
			Assert.assertEquals("DB", GaiaUtils.convertByteToHexaString((byte) 0xDB));
			Assert.assertEquals("DC", GaiaUtils.convertByteToHexaString((byte) 0xDC));
			Assert.assertEquals("DD", GaiaUtils.convertByteToHexaString((byte) 0xDD));
			Assert.assertEquals("DE", GaiaUtils.convertByteToHexaString((byte) 0xDE));
			Assert.assertEquals("DF", GaiaUtils.convertByteToHexaString((byte) 0xDF));
			Assert.assertEquals("E0", GaiaUtils.convertByteToHexaString((byte) 0xE0));
			Assert.assertEquals("E1", GaiaUtils.convertByteToHexaString((byte) 0xE1));
			Assert.assertEquals("E2", GaiaUtils.convertByteToHexaString((byte) 0xE2));
			Assert.assertEquals("E3", GaiaUtils.convertByteToHexaString((byte) 0xE3));
			Assert.assertEquals("E4", GaiaUtils.convertByteToHexaString((byte) 0xE4));
			Assert.assertEquals("E5", GaiaUtils.convertByteToHexaString((byte) 0xE5));
			Assert.assertEquals("E6", GaiaUtils.convertByteToHexaString((byte) 0xE6));
			Assert.assertEquals("E7", GaiaUtils.convertByteToHexaString((byte) 0xE7));
			Assert.assertEquals("E8", GaiaUtils.convertByteToHexaString((byte) 0xE8));
			Assert.assertEquals("E9", GaiaUtils.convertByteToHexaString((byte) 0xE9));
			Assert.assertEquals("EA", GaiaUtils.convertByteToHexaString((byte) 0xEA));
			Assert.assertEquals("EB", GaiaUtils.convertByteToHexaString((byte) 0xEB));
			Assert.assertEquals("EC", GaiaUtils.convertByteToHexaString((byte) 0xEC));
			Assert.assertEquals("ED", GaiaUtils.convertByteToHexaString((byte) 0xED));
			Assert.assertEquals("EE", GaiaUtils.convertByteToHexaString((byte) 0xEE));
			Assert.assertEquals("EF", GaiaUtils.convertByteToHexaString((byte) 0xEF));
			Assert.assertEquals("F0", GaiaUtils.convertByteToHexaString((byte) 0xF0));
			Assert.assertEquals("F1", GaiaUtils.convertByteToHexaString((byte) 0xF1));
			Assert.assertEquals("F2", GaiaUtils.convertByteToHexaString((byte) 0xF2));
			Assert.assertEquals("F3", GaiaUtils.convertByteToHexaString((byte) 0xF3));
			Assert.assertEquals("F4", GaiaUtils.convertByteToHexaString((byte) 0xF4));
			Assert.assertEquals("F5", GaiaUtils.convertByteToHexaString((byte) 0xF5));
			Assert.assertEquals("F6", GaiaUtils.convertByteToHexaString((byte) 0xF6));
			Assert.assertEquals("F7", GaiaUtils.convertByteToHexaString((byte) 0xF7));
			Assert.assertEquals("F8", GaiaUtils.convertByteToHexaString((byte) 0xF8));
			Assert.assertEquals("F9", GaiaUtils.convertByteToHexaString((byte) 0xF9));
			Assert.assertEquals("FA", GaiaUtils.convertByteToHexaString((byte) 0xFA));
			Assert.assertEquals("FB", GaiaUtils.convertByteToHexaString((byte) 0xFB));
			Assert.assertEquals("FC", GaiaUtils.convertByteToHexaString((byte) 0xFC));
			Assert.assertEquals("FD", GaiaUtils.convertByteToHexaString((byte) 0xFD));
			Assert.assertEquals("FE", GaiaUtils.convertByteToHexaString((byte) 0xFE));
			Assert.assertEquals("FF", GaiaUtils.convertByteToHexaString((byte) 0xFF));

			Assert.assertEquals("80", GaiaUtils.convertByteToHexaString((byte) 128));
			Assert.assertEquals("81", GaiaUtils.convertByteToHexaString((byte) 129));
			Assert.assertEquals("82", GaiaUtils.convertByteToHexaString((byte) 130));
			Assert.assertEquals("83", GaiaUtils.convertByteToHexaString((byte) 131));
			Assert.assertEquals("84", GaiaUtils.convertByteToHexaString((byte) 132));
			Assert.assertEquals("85", GaiaUtils.convertByteToHexaString((byte) 133));
			Assert.assertEquals("86", GaiaUtils.convertByteToHexaString((byte) 134));
			Assert.assertEquals("87", GaiaUtils.convertByteToHexaString((byte) 135));
			Assert.assertEquals("88", GaiaUtils.convertByteToHexaString((byte) 136));
			Assert.assertEquals("89", GaiaUtils.convertByteToHexaString((byte) 137));
			Assert.assertEquals("8A", GaiaUtils.convertByteToHexaString((byte) 138));
			Assert.assertEquals("8B", GaiaUtils.convertByteToHexaString((byte) 139));
			Assert.assertEquals("8C", GaiaUtils.convertByteToHexaString((byte) 140));
			Assert.assertEquals("8D", GaiaUtils.convertByteToHexaString((byte) 141));
			Assert.assertEquals("8E", GaiaUtils.convertByteToHexaString((byte) 142));
			Assert.assertEquals("8F", GaiaUtils.convertByteToHexaString((byte) 143));
			Assert.assertEquals("90", GaiaUtils.convertByteToHexaString((byte) 144));
			Assert.assertEquals("91", GaiaUtils.convertByteToHexaString((byte) 145));
			Assert.assertEquals("92", GaiaUtils.convertByteToHexaString((byte) 146));
			Assert.assertEquals("93", GaiaUtils.convertByteToHexaString((byte) 147));
			Assert.assertEquals("94", GaiaUtils.convertByteToHexaString((byte) 148));
			Assert.assertEquals("95", GaiaUtils.convertByteToHexaString((byte) 149));
			Assert.assertEquals("96", GaiaUtils.convertByteToHexaString((byte) 150));
			Assert.assertEquals("97", GaiaUtils.convertByteToHexaString((byte) 151));
			Assert.assertEquals("98", GaiaUtils.convertByteToHexaString((byte) 152));
			Assert.assertEquals("99", GaiaUtils.convertByteToHexaString((byte) 153));
			Assert.assertEquals("9A", GaiaUtils.convertByteToHexaString((byte) 154));
			Assert.assertEquals("9B", GaiaUtils.convertByteToHexaString((byte) 155));
			Assert.assertEquals("9C", GaiaUtils.convertByteToHexaString((byte) 156));
			Assert.assertEquals("9D", GaiaUtils.convertByteToHexaString((byte) 157));
			Assert.assertEquals("9E", GaiaUtils.convertByteToHexaString((byte) 158));
			Assert.assertEquals("9F", GaiaUtils.convertByteToHexaString((byte) 159));
			Assert.assertEquals("A0", GaiaUtils.convertByteToHexaString((byte) 160));
			Assert.assertEquals("A1", GaiaUtils.convertByteToHexaString((byte) 161));
			Assert.assertEquals("A2", GaiaUtils.convertByteToHexaString((byte) 162));
			Assert.assertEquals("A3", GaiaUtils.convertByteToHexaString((byte) 163));
			Assert.assertEquals("A4", GaiaUtils.convertByteToHexaString((byte) 164));
			Assert.assertEquals("A5", GaiaUtils.convertByteToHexaString((byte) 165));
			Assert.assertEquals("A6", GaiaUtils.convertByteToHexaString((byte) 166));
			Assert.assertEquals("A7", GaiaUtils.convertByteToHexaString((byte) 167));
			Assert.assertEquals("A8", GaiaUtils.convertByteToHexaString((byte) 168));
			Assert.assertEquals("A9", GaiaUtils.convertByteToHexaString((byte) 169));
			Assert.assertEquals("AA", GaiaUtils.convertByteToHexaString((byte) 170));
			Assert.assertEquals("AB", GaiaUtils.convertByteToHexaString((byte) 171));
			Assert.assertEquals("AC", GaiaUtils.convertByteToHexaString((byte) 172));
			Assert.assertEquals("AD", GaiaUtils.convertByteToHexaString((byte) 173));
			Assert.assertEquals("AE", GaiaUtils.convertByteToHexaString((byte) 174));
			Assert.assertEquals("AF", GaiaUtils.convertByteToHexaString((byte) 175));
			Assert.assertEquals("B0", GaiaUtils.convertByteToHexaString((byte) 176));
			Assert.assertEquals("B1", GaiaUtils.convertByteToHexaString((byte) 177));
			Assert.assertEquals("B2", GaiaUtils.convertByteToHexaString((byte) 178));
			Assert.assertEquals("B3", GaiaUtils.convertByteToHexaString((byte) 179));
			Assert.assertEquals("B4", GaiaUtils.convertByteToHexaString((byte) 180));
			Assert.assertEquals("B5", GaiaUtils.convertByteToHexaString((byte) 181));
			Assert.assertEquals("B6", GaiaUtils.convertByteToHexaString((byte) 182));
			Assert.assertEquals("B7", GaiaUtils.convertByteToHexaString((byte) 183));
			Assert.assertEquals("B8", GaiaUtils.convertByteToHexaString((byte) 184));
			Assert.assertEquals("B9", GaiaUtils.convertByteToHexaString((byte) 185));
			Assert.assertEquals("BA", GaiaUtils.convertByteToHexaString((byte) 186));
			Assert.assertEquals("BB", GaiaUtils.convertByteToHexaString((byte) 187));
			Assert.assertEquals("BC", GaiaUtils.convertByteToHexaString((byte) 188));
			Assert.assertEquals("BD", GaiaUtils.convertByteToHexaString((byte) 189));
			Assert.assertEquals("BE", GaiaUtils.convertByteToHexaString((byte) 190));
			Assert.assertEquals("BF", GaiaUtils.convertByteToHexaString((byte) 191));
			Assert.assertEquals("C0", GaiaUtils.convertByteToHexaString((byte) 192));
			Assert.assertEquals("C1", GaiaUtils.convertByteToHexaString((byte) 193));
			Assert.assertEquals("C2", GaiaUtils.convertByteToHexaString((byte) 194));
			Assert.assertEquals("C3", GaiaUtils.convertByteToHexaString((byte) 195));
			Assert.assertEquals("C4", GaiaUtils.convertByteToHexaString((byte) 196));
			Assert.assertEquals("C5", GaiaUtils.convertByteToHexaString((byte) 197));
			Assert.assertEquals("C6", GaiaUtils.convertByteToHexaString((byte) 198));
			Assert.assertEquals("C7", GaiaUtils.convertByteToHexaString((byte) 199));
			Assert.assertEquals("C8", GaiaUtils.convertByteToHexaString((byte) 200));
			Assert.assertEquals("C9", GaiaUtils.convertByteToHexaString((byte) 201));
			Assert.assertEquals("CA", GaiaUtils.convertByteToHexaString((byte) 202));
			Assert.assertEquals("CB", GaiaUtils.convertByteToHexaString((byte) 203));
			Assert.assertEquals("CC", GaiaUtils.convertByteToHexaString((byte) 204));
			Assert.assertEquals("CD", GaiaUtils.convertByteToHexaString((byte) 205));
			Assert.assertEquals("CE", GaiaUtils.convertByteToHexaString((byte) 206));
			Assert.assertEquals("CF", GaiaUtils.convertByteToHexaString((byte) 207));
			Assert.assertEquals("D0", GaiaUtils.convertByteToHexaString((byte) 208));
			Assert.assertEquals("D1", GaiaUtils.convertByteToHexaString((byte) 209));
			Assert.assertEquals("D2", GaiaUtils.convertByteToHexaString((byte) 210));
			Assert.assertEquals("D3", GaiaUtils.convertByteToHexaString((byte) 211));
			Assert.assertEquals("D4", GaiaUtils.convertByteToHexaString((byte) 212));
			Assert.assertEquals("D5", GaiaUtils.convertByteToHexaString((byte) 213));
			Assert.assertEquals("D6", GaiaUtils.convertByteToHexaString((byte) 214));
			Assert.assertEquals("D7", GaiaUtils.convertByteToHexaString((byte) 215));
			Assert.assertEquals("D8", GaiaUtils.convertByteToHexaString((byte) 216));
			Assert.assertEquals("D9", GaiaUtils.convertByteToHexaString((byte) 217));
			Assert.assertEquals("DA", GaiaUtils.convertByteToHexaString((byte) 218));
			Assert.assertEquals("DB", GaiaUtils.convertByteToHexaString((byte) 219));
			Assert.assertEquals("DC", GaiaUtils.convertByteToHexaString((byte) 220));
			Assert.assertEquals("DD", GaiaUtils.convertByteToHexaString((byte) 221));
			Assert.assertEquals("DE", GaiaUtils.convertByteToHexaString((byte) 222));
			Assert.assertEquals("DF", GaiaUtils.convertByteToHexaString((byte) 223));
			Assert.assertEquals("E0", GaiaUtils.convertByteToHexaString((byte) 224));
			Assert.assertEquals("E1", GaiaUtils.convertByteToHexaString((byte) 225));
			Assert.assertEquals("E2", GaiaUtils.convertByteToHexaString((byte) 226));
			Assert.assertEquals("E3", GaiaUtils.convertByteToHexaString((byte) 227));
			Assert.assertEquals("E4", GaiaUtils.convertByteToHexaString((byte) 228));
			Assert.assertEquals("E5", GaiaUtils.convertByteToHexaString((byte) 229));
			Assert.assertEquals("E6", GaiaUtils.convertByteToHexaString((byte) 230));
			Assert.assertEquals("E7", GaiaUtils.convertByteToHexaString((byte) 231));
			Assert.assertEquals("E8", GaiaUtils.convertByteToHexaString((byte) 232));
			Assert.assertEquals("E9", GaiaUtils.convertByteToHexaString((byte) 233));
			Assert.assertEquals("EA", GaiaUtils.convertByteToHexaString((byte) 234));
			Assert.assertEquals("EB", GaiaUtils.convertByteToHexaString((byte) 235));
			Assert.assertEquals("EC", GaiaUtils.convertByteToHexaString((byte) 236));
			Assert.assertEquals("ED", GaiaUtils.convertByteToHexaString((byte) 237));
			Assert.assertEquals("EE", GaiaUtils.convertByteToHexaString((byte) 238));
			Assert.assertEquals("EF", GaiaUtils.convertByteToHexaString((byte) 239));
			Assert.assertEquals("F0", GaiaUtils.convertByteToHexaString((byte) 240));
			Assert.assertEquals("F1", GaiaUtils.convertByteToHexaString((byte) 241));
			Assert.assertEquals("F2", GaiaUtils.convertByteToHexaString((byte) 242));
			Assert.assertEquals("F3", GaiaUtils.convertByteToHexaString((byte) 243));
			Assert.assertEquals("F4", GaiaUtils.convertByteToHexaString((byte) 244));
			Assert.assertEquals("F5", GaiaUtils.convertByteToHexaString((byte) 245));
			Assert.assertEquals("F6", GaiaUtils.convertByteToHexaString((byte) 246));
			Assert.assertEquals("F7", GaiaUtils.convertByteToHexaString((byte) 247));
			Assert.assertEquals("F8", GaiaUtils.convertByteToHexaString((byte) 248));
			Assert.assertEquals("F9", GaiaUtils.convertByteToHexaString((byte) 249));
			Assert.assertEquals("FA", GaiaUtils.convertByteToHexaString((byte) 250));
			Assert.assertEquals("FB", GaiaUtils.convertByteToHexaString((byte) 251));
			Assert.assertEquals("FC", GaiaUtils.convertByteToHexaString((byte) 252));
			Assert.assertEquals("FD", GaiaUtils.convertByteToHexaString((byte) 253));
			Assert.assertEquals("FE", GaiaUtils.convertByteToHexaString((byte) 254));
			Assert.assertEquals("FF", GaiaUtils.convertByteToHexaString((byte) 255));

			Assert.assertEquals("80", GaiaUtils.convertByteToHexaString((byte) -128));
			Assert.assertEquals("81", GaiaUtils.convertByteToHexaString((byte) -127));
			Assert.assertEquals("82", GaiaUtils.convertByteToHexaString((byte) -126));
			Assert.assertEquals("83", GaiaUtils.convertByteToHexaString((byte) -125));
			Assert.assertEquals("84", GaiaUtils.convertByteToHexaString((byte) -124));
			Assert.assertEquals("85", GaiaUtils.convertByteToHexaString((byte) -123));
			Assert.assertEquals("86", GaiaUtils.convertByteToHexaString((byte) -122));
			Assert.assertEquals("87", GaiaUtils.convertByteToHexaString((byte) -121));
			Assert.assertEquals("88", GaiaUtils.convertByteToHexaString((byte) -120));
			Assert.assertEquals("89", GaiaUtils.convertByteToHexaString((byte) -119));
			Assert.assertEquals("8A", GaiaUtils.convertByteToHexaString((byte) -118));
			Assert.assertEquals("8B", GaiaUtils.convertByteToHexaString((byte) -117));
			Assert.assertEquals("8C", GaiaUtils.convertByteToHexaString((byte) -116));
			Assert.assertEquals("8D", GaiaUtils.convertByteToHexaString((byte) -115));
			Assert.assertEquals("8E", GaiaUtils.convertByteToHexaString((byte) -114));
			Assert.assertEquals("8F", GaiaUtils.convertByteToHexaString((byte) -113));
			Assert.assertEquals("90", GaiaUtils.convertByteToHexaString((byte) -112));
			Assert.assertEquals("91", GaiaUtils.convertByteToHexaString((byte) -111));
			Assert.assertEquals("92", GaiaUtils.convertByteToHexaString((byte) -110));
			Assert.assertEquals("93", GaiaUtils.convertByteToHexaString((byte) -109));
			Assert.assertEquals("94", GaiaUtils.convertByteToHexaString((byte) -108));
			Assert.assertEquals("95", GaiaUtils.convertByteToHexaString((byte) -107));
			Assert.assertEquals("96", GaiaUtils.convertByteToHexaString((byte) -106));
			Assert.assertEquals("97", GaiaUtils.convertByteToHexaString((byte) -105));
			Assert.assertEquals("98", GaiaUtils.convertByteToHexaString((byte) -104));
			Assert.assertEquals("99", GaiaUtils.convertByteToHexaString((byte) -103));
			Assert.assertEquals("9A", GaiaUtils.convertByteToHexaString((byte) -102));
			Assert.assertEquals("9B", GaiaUtils.convertByteToHexaString((byte) -101));
			Assert.assertEquals("9C", GaiaUtils.convertByteToHexaString((byte) -100));
			Assert.assertEquals("9D", GaiaUtils.convertByteToHexaString((byte) -99));
			Assert.assertEquals("9E", GaiaUtils.convertByteToHexaString((byte) -98));
			Assert.assertEquals("9F", GaiaUtils.convertByteToHexaString((byte) -97));
			Assert.assertEquals("A0", GaiaUtils.convertByteToHexaString((byte) -96));
			Assert.assertEquals("A1", GaiaUtils.convertByteToHexaString((byte) -95));
			Assert.assertEquals("A2", GaiaUtils.convertByteToHexaString((byte) -94));
			Assert.assertEquals("A3", GaiaUtils.convertByteToHexaString((byte) -93));
			Assert.assertEquals("A4", GaiaUtils.convertByteToHexaString((byte) -92));
			Assert.assertEquals("A5", GaiaUtils.convertByteToHexaString((byte) -91));
			Assert.assertEquals("A6", GaiaUtils.convertByteToHexaString((byte) -90));
			Assert.assertEquals("A7", GaiaUtils.convertByteToHexaString((byte) -89));
			Assert.assertEquals("A8", GaiaUtils.convertByteToHexaString((byte) -88));
			Assert.assertEquals("A9", GaiaUtils.convertByteToHexaString((byte) -87));
			Assert.assertEquals("AA", GaiaUtils.convertByteToHexaString((byte) -86));
			Assert.assertEquals("AB", GaiaUtils.convertByteToHexaString((byte) -85));
			Assert.assertEquals("AC", GaiaUtils.convertByteToHexaString((byte) -84));
			Assert.assertEquals("AD", GaiaUtils.convertByteToHexaString((byte) -83));
			Assert.assertEquals("AE", GaiaUtils.convertByteToHexaString((byte) -82));
			Assert.assertEquals("AF", GaiaUtils.convertByteToHexaString((byte) -81));
			Assert.assertEquals("B0", GaiaUtils.convertByteToHexaString((byte) -80));
			Assert.assertEquals("B1", GaiaUtils.convertByteToHexaString((byte) -79));
			Assert.assertEquals("B2", GaiaUtils.convertByteToHexaString((byte) -78));
			Assert.assertEquals("B3", GaiaUtils.convertByteToHexaString((byte) -77));
			Assert.assertEquals("B4", GaiaUtils.convertByteToHexaString((byte) -76));
			Assert.assertEquals("B5", GaiaUtils.convertByteToHexaString((byte) -75));
			Assert.assertEquals("B6", GaiaUtils.convertByteToHexaString((byte) -74));
			Assert.assertEquals("B7", GaiaUtils.convertByteToHexaString((byte) -73));
			Assert.assertEquals("B8", GaiaUtils.convertByteToHexaString((byte) -72));
			Assert.assertEquals("B9", GaiaUtils.convertByteToHexaString((byte) -71));
			Assert.assertEquals("BA", GaiaUtils.convertByteToHexaString((byte) -70));
			Assert.assertEquals("BB", GaiaUtils.convertByteToHexaString((byte) -69));
			Assert.assertEquals("BC", GaiaUtils.convertByteToHexaString((byte) -68));
			Assert.assertEquals("BD", GaiaUtils.convertByteToHexaString((byte) -67));
			Assert.assertEquals("BE", GaiaUtils.convertByteToHexaString((byte) -66));
			Assert.assertEquals("BF", GaiaUtils.convertByteToHexaString((byte) -65));
			Assert.assertEquals("C0", GaiaUtils.convertByteToHexaString((byte) -64));
			Assert.assertEquals("C1", GaiaUtils.convertByteToHexaString((byte) -63));
			Assert.assertEquals("C2", GaiaUtils.convertByteToHexaString((byte) -62));
			Assert.assertEquals("C3", GaiaUtils.convertByteToHexaString((byte) -61));
			Assert.assertEquals("C4", GaiaUtils.convertByteToHexaString((byte) -60));
			Assert.assertEquals("C5", GaiaUtils.convertByteToHexaString((byte) -59));
			Assert.assertEquals("C6", GaiaUtils.convertByteToHexaString((byte) -58));
			Assert.assertEquals("C7", GaiaUtils.convertByteToHexaString((byte) -57));
			Assert.assertEquals("C8", GaiaUtils.convertByteToHexaString((byte) -56));
			Assert.assertEquals("C9", GaiaUtils.convertByteToHexaString((byte) -55));
			Assert.assertEquals("CA", GaiaUtils.convertByteToHexaString((byte) -54));
			Assert.assertEquals("CB", GaiaUtils.convertByteToHexaString((byte) -53));
			Assert.assertEquals("CC", GaiaUtils.convertByteToHexaString((byte) -52));
			Assert.assertEquals("CD", GaiaUtils.convertByteToHexaString((byte) -51));
			Assert.assertEquals("CE", GaiaUtils.convertByteToHexaString((byte) -50));
			Assert.assertEquals("CF", GaiaUtils.convertByteToHexaString((byte) -49));
			Assert.assertEquals("D0", GaiaUtils.convertByteToHexaString((byte) -48));
			Assert.assertEquals("D1", GaiaUtils.convertByteToHexaString((byte) -47));
			Assert.assertEquals("D2", GaiaUtils.convertByteToHexaString((byte) -46));
			Assert.assertEquals("D3", GaiaUtils.convertByteToHexaString((byte) -45));
			Assert.assertEquals("D4", GaiaUtils.convertByteToHexaString((byte) -44));
			Assert.assertEquals("D5", GaiaUtils.convertByteToHexaString((byte) -43));
			Assert.assertEquals("D6", GaiaUtils.convertByteToHexaString((byte) -42));
			Assert.assertEquals("D7", GaiaUtils.convertByteToHexaString((byte) -41));
			Assert.assertEquals("D8", GaiaUtils.convertByteToHexaString((byte) -40));
			Assert.assertEquals("D9", GaiaUtils.convertByteToHexaString((byte) -39));
			Assert.assertEquals("DA", GaiaUtils.convertByteToHexaString((byte) -38));
			Assert.assertEquals("DB", GaiaUtils.convertByteToHexaString((byte) -37));
			Assert.assertEquals("DC", GaiaUtils.convertByteToHexaString((byte) -36));
			Assert.assertEquals("DD", GaiaUtils.convertByteToHexaString((byte) -35));
			Assert.assertEquals("DE", GaiaUtils.convertByteToHexaString((byte) -34));
			Assert.assertEquals("DF", GaiaUtils.convertByteToHexaString((byte) -33));
			Assert.assertEquals("E0", GaiaUtils.convertByteToHexaString((byte) -32));
			Assert.assertEquals("E1", GaiaUtils.convertByteToHexaString((byte) -31));
			Assert.assertEquals("E2", GaiaUtils.convertByteToHexaString((byte) -30));
			Assert.assertEquals("E3", GaiaUtils.convertByteToHexaString((byte) -29));
			Assert.assertEquals("E4", GaiaUtils.convertByteToHexaString((byte) -28));
			Assert.assertEquals("E5", GaiaUtils.convertByteToHexaString((byte) -27));
			Assert.assertEquals("E6", GaiaUtils.convertByteToHexaString((byte) -26));
			Assert.assertEquals("E7", GaiaUtils.convertByteToHexaString((byte) -25));
			Assert.assertEquals("E8", GaiaUtils.convertByteToHexaString((byte) -24));
			Assert.assertEquals("E9", GaiaUtils.convertByteToHexaString((byte) -23));
			Assert.assertEquals("EA", GaiaUtils.convertByteToHexaString((byte) -22));
			Assert.assertEquals("EB", GaiaUtils.convertByteToHexaString((byte) -21));
			Assert.assertEquals("EC", GaiaUtils.convertByteToHexaString((byte) -20));
			Assert.assertEquals("ED", GaiaUtils.convertByteToHexaString((byte) -19));
			Assert.assertEquals("EE", GaiaUtils.convertByteToHexaString((byte) -18));
			Assert.assertEquals("EF", GaiaUtils.convertByteToHexaString((byte) -17));
			Assert.assertEquals("F0", GaiaUtils.convertByteToHexaString((byte) -16));
			Assert.assertEquals("F1", GaiaUtils.convertByteToHexaString((byte) -15));
			Assert.assertEquals("F2", GaiaUtils.convertByteToHexaString((byte) -14));
			Assert.assertEquals("F3", GaiaUtils.convertByteToHexaString((byte) -13));
			Assert.assertEquals("F4", GaiaUtils.convertByteToHexaString((byte) -12));
			Assert.assertEquals("F5", GaiaUtils.convertByteToHexaString((byte) -11));
			Assert.assertEquals("F6", GaiaUtils.convertByteToHexaString((byte) -10));
			Assert.assertEquals("F7", GaiaUtils.convertByteToHexaString((byte) -9));
			Assert.assertEquals("F8", GaiaUtils.convertByteToHexaString((byte) -8));
			Assert.assertEquals("F9", GaiaUtils.convertByteToHexaString((byte) -7));
			Assert.assertEquals("FA", GaiaUtils.convertByteToHexaString((byte) -6));
			Assert.assertEquals("FB", GaiaUtils.convertByteToHexaString((byte) -5));
			Assert.assertEquals("FC", GaiaUtils.convertByteToHexaString((byte) -4));
			Assert.assertEquals("FD", GaiaUtils.convertByteToHexaString((byte) -3));
			Assert.assertEquals("FE", GaiaUtils.convertByteToHexaString((byte) -2));
			Assert.assertEquals("FF", GaiaUtils.convertByteToHexaString((byte) -1));
		}
		catch ( Exception e )
		{
			e.printStackTrace();
			Assert.assertFalse(true);
		}
	}





	@Test
	public void test0008_convertByteArrayToHexaString_NormalTest()
	{
		try
		{
			Assert.assertEquals("00", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x00 }));
			Assert.assertEquals("01", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x01 }));
			Assert.assertEquals("02", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x02 }));
			Assert.assertEquals("03", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x03 }));
			Assert.assertEquals("04", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x04 }));
			Assert.assertEquals("05", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x05 }));
			Assert.assertEquals("06", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x06 }));
			Assert.assertEquals("07", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x07 }));
			Assert.assertEquals("08", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x08 }));
			Assert.assertEquals("09", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x09 }));
			Assert.assertEquals("0A", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x0A }));
			Assert.assertEquals("0B", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x0B }));
			Assert.assertEquals("0C", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x0C }));
			Assert.assertEquals("0D", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x0D }));
			Assert.assertEquals("0E", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x0E }));
			Assert.assertEquals("0F", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x0F }));
			Assert.assertEquals("10", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x10 }));
			Assert.assertEquals("11", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x11 }));
			Assert.assertEquals("12", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x12 }));
			Assert.assertEquals("13", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x13 }));
			Assert.assertEquals("14", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x14 }));
			Assert.assertEquals("15", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x15 }));
			Assert.assertEquals("16", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x16 }));
			Assert.assertEquals("17", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x17 }));
			Assert.assertEquals("18", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x18 }));
			Assert.assertEquals("19", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x19 }));
			Assert.assertEquals("1A", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x1A }));
			Assert.assertEquals("1B", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x1B }));
			Assert.assertEquals("1C", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x1C }));
			Assert.assertEquals("1D", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x1D }));
			Assert.assertEquals("1E", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x1E }));
			Assert.assertEquals("1F", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x1F }));
			Assert.assertEquals("20", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x20 }));
			Assert.assertEquals("21", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x21 }));
			Assert.assertEquals("22", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x22 }));
			Assert.assertEquals("23", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x23 }));
			Assert.assertEquals("24", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x24 }));
			Assert.assertEquals("25", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x25 }));
			Assert.assertEquals("26", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x26 }));
			Assert.assertEquals("27", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x27 }));
			Assert.assertEquals("28", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x28 }));
			Assert.assertEquals("29", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x29 }));
			Assert.assertEquals("2A", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x2A }));
			Assert.assertEquals("2B", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x2B }));
			Assert.assertEquals("2C", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x2C }));
			Assert.assertEquals("2D", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x2D }));
			Assert.assertEquals("2E", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x2E }));
			Assert.assertEquals("2F", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x2F }));
			Assert.assertEquals("30", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x30 }));
			Assert.assertEquals("31", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x31 }));
			Assert.assertEquals("32", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x32 }));
			Assert.assertEquals("33", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x33 }));
			Assert.assertEquals("34", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x34 }));
			Assert.assertEquals("35", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x35 }));
			Assert.assertEquals("36", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x36 }));
			Assert.assertEquals("37", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x37 }));
			Assert.assertEquals("38", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x38 }));
			Assert.assertEquals("39", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x39 }));
			Assert.assertEquals("3A", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x3A }));
			Assert.assertEquals("3B", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x3B }));
			Assert.assertEquals("3C", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x3C }));
			Assert.assertEquals("3D", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x3D }));
			Assert.assertEquals("3E", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x3E }));
			Assert.assertEquals("3F", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x3F }));
			Assert.assertEquals("40", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x40 }));
			Assert.assertEquals("41", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x41 }));
			Assert.assertEquals("42", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x42 }));
			Assert.assertEquals("43", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x43 }));
			Assert.assertEquals("44", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x44 }));
			Assert.assertEquals("45", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x45 }));
			Assert.assertEquals("46", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x46 }));
			Assert.assertEquals("47", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x47 }));
			Assert.assertEquals("48", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x48 }));
			Assert.assertEquals("49", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x49 }));
			Assert.assertEquals("4A", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x4A }));
			Assert.assertEquals("4B", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x4B }));
			Assert.assertEquals("4C", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x4C }));
			Assert.assertEquals("4D", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x4D }));
			Assert.assertEquals("4E", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x4E }));
			Assert.assertEquals("4F", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x4F }));
			Assert.assertEquals("50", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x50 }));
			Assert.assertEquals("51", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x51 }));
			Assert.assertEquals("52", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x52 }));
			Assert.assertEquals("53", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x53 }));
			Assert.assertEquals("54", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x54 }));
			Assert.assertEquals("55", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x55 }));
			Assert.assertEquals("56", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x56 }));
			Assert.assertEquals("57", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x57 }));
			Assert.assertEquals("58", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x58 }));
			Assert.assertEquals("59", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x59 }));
			Assert.assertEquals("5A", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x5A }));
			Assert.assertEquals("5B", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x5B }));
			Assert.assertEquals("5C", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x5C }));
			Assert.assertEquals("5D", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x5D }));
			Assert.assertEquals("5E", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x5E }));
			Assert.assertEquals("5F", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x5F }));
			Assert.assertEquals("60", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x60 }));
			Assert.assertEquals("61", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x61 }));
			Assert.assertEquals("62", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x62 }));
			Assert.assertEquals("63", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x63 }));
			Assert.assertEquals("64", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x64 }));
			Assert.assertEquals("65", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x65 }));
			Assert.assertEquals("66", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x66 }));
			Assert.assertEquals("67", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x67 }));
			Assert.assertEquals("68", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x68 }));
			Assert.assertEquals("69", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x69 }));
			Assert.assertEquals("6A", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x6A }));
			Assert.assertEquals("6B", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x6B }));
			Assert.assertEquals("6C", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x6C }));
			Assert.assertEquals("6D", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x6D }));
			Assert.assertEquals("6E", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x6E }));
			Assert.assertEquals("6F", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x6F }));
			Assert.assertEquals("70", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x70 }));
			Assert.assertEquals("71", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x71 }));
			Assert.assertEquals("72", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x72 }));
			Assert.assertEquals("73", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x73 }));
			Assert.assertEquals("74", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x74 }));
			Assert.assertEquals("75", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x75 }));
			Assert.assertEquals("76", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x76 }));
			Assert.assertEquals("77", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x77 }));
			Assert.assertEquals("78", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x78 }));
			Assert.assertEquals("79", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x79 }));
			Assert.assertEquals("7A", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x7A }));
			Assert.assertEquals("7B", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x7B }));
			Assert.assertEquals("7C", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x7C }));
			Assert.assertEquals("7D", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x7D }));
			Assert.assertEquals("7E", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x7E }));
			Assert.assertEquals("7F", GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x7F }));

			Assert.assertEquals("80", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x80 }));
			Assert.assertEquals("81", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x81 }));
			Assert.assertEquals("82", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x82 }));
			Assert.assertEquals("83", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x83 }));
			Assert.assertEquals("84", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x84 }));
			Assert.assertEquals("85", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x85 }));
			Assert.assertEquals("86", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x86 }));
			Assert.assertEquals("87", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x87 }));
			Assert.assertEquals("88", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x88 }));
			Assert.assertEquals("89", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x89 }));
			Assert.assertEquals("8A", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x8A }));
			Assert.assertEquals("8B", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x8B }));
			Assert.assertEquals("8C", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x8C }));
			Assert.assertEquals("8D", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x8D }));
			Assert.assertEquals("8E", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x8E }));
			Assert.assertEquals("8F", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x8F }));
			Assert.assertEquals("90", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x90 }));
			Assert.assertEquals("91", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x91 }));
			Assert.assertEquals("92", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x92 }));
			Assert.assertEquals("93", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x93 }));
			Assert.assertEquals("94", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x94 }));
			Assert.assertEquals("95", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x95 }));
			Assert.assertEquals("96", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x96 }));
			Assert.assertEquals("97", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x97 }));
			Assert.assertEquals("98", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x98 }));
			Assert.assertEquals("99", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x99 }));
			Assert.assertEquals("9A", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x9A }));
			Assert.assertEquals("9B", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x9B }));
			Assert.assertEquals("9C", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x9C }));
			Assert.assertEquals("9D", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x9D }));
			Assert.assertEquals("9E", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x9E }));
			Assert.assertEquals("9F", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0x9F }));
			Assert.assertEquals("A0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xA0 }));
			Assert.assertEquals("A1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xA1 }));
			Assert.assertEquals("A2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xA2 }));
			Assert.assertEquals("A3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xA3 }));
			Assert.assertEquals("A4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xA4 }));
			Assert.assertEquals("A5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xA5 }));
			Assert.assertEquals("A6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xA6 }));
			Assert.assertEquals("A7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xA7 }));
			Assert.assertEquals("A8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xA8 }));
			Assert.assertEquals("A9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xA9 }));
			Assert.assertEquals("AA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xAA }));
			Assert.assertEquals("AB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xAB }));
			Assert.assertEquals("AC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xAC }));
			Assert.assertEquals("AD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xAD }));
			Assert.assertEquals("AE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xAE }));
			Assert.assertEquals("AF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xAF }));
			Assert.assertEquals("B0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xB0 }));
			Assert.assertEquals("B1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xB1 }));
			Assert.assertEquals("B2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xB2 }));
			Assert.assertEquals("B3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xB3 }));
			Assert.assertEquals("B4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xB4 }));
			Assert.assertEquals("B5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xB5 }));
			Assert.assertEquals("B6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xB6 }));
			Assert.assertEquals("B7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xB7 }));
			Assert.assertEquals("B8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xB8 }));
			Assert.assertEquals("B9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xB9 }));
			Assert.assertEquals("BA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xBA }));
			Assert.assertEquals("BB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xBB }));
			Assert.assertEquals("BC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xBC }));
			Assert.assertEquals("BD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xBD }));
			Assert.assertEquals("BE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xBE }));
			Assert.assertEquals("BF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xBF }));
			Assert.assertEquals("C0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xC0 }));
			Assert.assertEquals("C1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xC1 }));
			Assert.assertEquals("C2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xC2 }));
			Assert.assertEquals("C3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xC3 }));
			Assert.assertEquals("C4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xC4 }));
			Assert.assertEquals("C5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xC5 }));
			Assert.assertEquals("C6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xC6 }));
			Assert.assertEquals("C7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xC7 }));
			Assert.assertEquals("C8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xC8 }));
			Assert.assertEquals("C9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xC9 }));
			Assert.assertEquals("CA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xCA }));
			Assert.assertEquals("CB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xCB }));
			Assert.assertEquals("CC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xCC }));
			Assert.assertEquals("CD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xCD }));
			Assert.assertEquals("CE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xCE }));
			Assert.assertEquals("CF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xCF }));
			Assert.assertEquals("D0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xD0 }));
			Assert.assertEquals("D1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xD1 }));
			Assert.assertEquals("D2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xD2 }));
			Assert.assertEquals("D3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xD3 }));
			Assert.assertEquals("D4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xD4 }));
			Assert.assertEquals("D5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xD5 }));
			Assert.assertEquals("D6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xD6 }));
			Assert.assertEquals("D7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xD7 }));
			Assert.assertEquals("D8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xD8 }));
			Assert.assertEquals("D9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xD9 }));
			Assert.assertEquals("DA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xDA }));
			Assert.assertEquals("DB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xDB }));
			Assert.assertEquals("DC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xDC }));
			Assert.assertEquals("DD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xDD }));
			Assert.assertEquals("DE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xDE }));
			Assert.assertEquals("DF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xDF }));
			Assert.assertEquals("E0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xE0 }));
			Assert.assertEquals("E1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xE1 }));
			Assert.assertEquals("E2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xE2 }));
			Assert.assertEquals("E3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xE3 }));
			Assert.assertEquals("E4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xE4 }));
			Assert.assertEquals("E5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xE5 }));
			Assert.assertEquals("E6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xE6 }));
			Assert.assertEquals("E7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xE7 }));
			Assert.assertEquals("E8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xE8 }));
			Assert.assertEquals("E9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xE9 }));
			Assert.assertEquals("EA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xEA }));
			Assert.assertEquals("EB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xEB }));
			Assert.assertEquals("EC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xEC }));
			Assert.assertEquals("ED", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xED }));
			Assert.assertEquals("EE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xEE }));
			Assert.assertEquals("EF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xEF }));
			Assert.assertEquals("F0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xF0 }));
			Assert.assertEquals("F1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xF1 }));
			Assert.assertEquals("F2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xF2 }));
			Assert.assertEquals("F3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xF3 }));
			Assert.assertEquals("F4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xF4 }));
			Assert.assertEquals("F5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xF5 }));
			Assert.assertEquals("F6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xF6 }));
			Assert.assertEquals("F7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xF7 }));
			Assert.assertEquals("F8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xF8 }));
			Assert.assertEquals("F9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xF9 }));
			Assert.assertEquals("FA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xFA }));
			Assert.assertEquals("FB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xFB }));
			Assert.assertEquals("FC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xFC }));
			Assert.assertEquals("FD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xFD }));
			Assert.assertEquals("FE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xFE }));
			Assert.assertEquals("FF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 0xFF }));

			Assert.assertEquals("80", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 128 }));
			Assert.assertEquals("81", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 129 }));
			Assert.assertEquals("82", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 130 }));
			Assert.assertEquals("83", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 131 }));
			Assert.assertEquals("84", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 132 }));
			Assert.assertEquals("85", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 133 }));
			Assert.assertEquals("86", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 134 }));
			Assert.assertEquals("87", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 135 }));
			Assert.assertEquals("88", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 136 }));
			Assert.assertEquals("89", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 137 }));
			Assert.assertEquals("8A", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 138 }));
			Assert.assertEquals("8B", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 139 }));
			Assert.assertEquals("8C", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 140 }));
			Assert.assertEquals("8D", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 141 }));
			Assert.assertEquals("8E", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 142 }));
			Assert.assertEquals("8F", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 143 }));
			Assert.assertEquals("90", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 144 }));
			Assert.assertEquals("91", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 145 }));
			Assert.assertEquals("92", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 146 }));
			Assert.assertEquals("93", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 147 }));
			Assert.assertEquals("94", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 148 }));
			Assert.assertEquals("95", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 149 }));
			Assert.assertEquals("96", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 150 }));
			Assert.assertEquals("97", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 151 }));
			Assert.assertEquals("98", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 152 }));
			Assert.assertEquals("99", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 153 }));
			Assert.assertEquals("9A", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 154 }));
			Assert.assertEquals("9B", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 155 }));
			Assert.assertEquals("9C", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 156 }));
			Assert.assertEquals("9D", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 157 }));
			Assert.assertEquals("9E", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 158 }));
			Assert.assertEquals("9F", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 159 }));
			Assert.assertEquals("A0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 160 }));
			Assert.assertEquals("A1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 161 }));
			Assert.assertEquals("A2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 162 }));
			Assert.assertEquals("A3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 163 }));
			Assert.assertEquals("A4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 164 }));
			Assert.assertEquals("A5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 165 }));
			Assert.assertEquals("A6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 166 }));
			Assert.assertEquals("A7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 167 }));
			Assert.assertEquals("A8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 168 }));
			Assert.assertEquals("A9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 169 }));
			Assert.assertEquals("AA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 170 }));
			Assert.assertEquals("AB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 171 }));
			Assert.assertEquals("AC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 172 }));
			Assert.assertEquals("AD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 173 }));
			Assert.assertEquals("AE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 174 }));
			Assert.assertEquals("AF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 175 }));
			Assert.assertEquals("B0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 176 }));
			Assert.assertEquals("B1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 177 }));
			Assert.assertEquals("B2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 178 }));
			Assert.assertEquals("B3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 179 }));
			Assert.assertEquals("B4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 180 }));
			Assert.assertEquals("B5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 181 }));
			Assert.assertEquals("B6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 182 }));
			Assert.assertEquals("B7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 183 }));
			Assert.assertEquals("B8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 184 }));
			Assert.assertEquals("B9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 185 }));
			Assert.assertEquals("BA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 186 }));
			Assert.assertEquals("BB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 187 }));
			Assert.assertEquals("BC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 188 }));
			Assert.assertEquals("BD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 189 }));
			Assert.assertEquals("BE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 190 }));
			Assert.assertEquals("BF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 191 }));
			Assert.assertEquals("C0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 192 }));
			Assert.assertEquals("C1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 193 }));
			Assert.assertEquals("C2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 194 }));
			Assert.assertEquals("C3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 195 }));
			Assert.assertEquals("C4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 196 }));
			Assert.assertEquals("C5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 197 }));
			Assert.assertEquals("C6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 198 }));
			Assert.assertEquals("C7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 199 }));
			Assert.assertEquals("C8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 200 }));
			Assert.assertEquals("C9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 201 }));
			Assert.assertEquals("CA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 202 }));
			Assert.assertEquals("CB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 203 }));
			Assert.assertEquals("CC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 204 }));
			Assert.assertEquals("CD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 205 }));
			Assert.assertEquals("CE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 206 }));
			Assert.assertEquals("CF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 207 }));
			Assert.assertEquals("D0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 208 }));
			Assert.assertEquals("D1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 209 }));
			Assert.assertEquals("D2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 210 }));
			Assert.assertEquals("D3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 211 }));
			Assert.assertEquals("D4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 212 }));
			Assert.assertEquals("D5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 213 }));
			Assert.assertEquals("D6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 214 }));
			Assert.assertEquals("D7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 215 }));
			Assert.assertEquals("D8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 216 }));
			Assert.assertEquals("D9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 217 }));
			Assert.assertEquals("DA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 218 }));
			Assert.assertEquals("DB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 219 }));
			Assert.assertEquals("DC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 220 }));
			Assert.assertEquals("DD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 221 }));
			Assert.assertEquals("DE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 222 }));
			Assert.assertEquals("DF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 223 }));
			Assert.assertEquals("E0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 224 }));
			Assert.assertEquals("E1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 225 }));
			Assert.assertEquals("E2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 226 }));
			Assert.assertEquals("E3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 227 }));
			Assert.assertEquals("E4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 228 }));
			Assert.assertEquals("E5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 229 }));
			Assert.assertEquals("E6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 230 }));
			Assert.assertEquals("E7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 231 }));
			Assert.assertEquals("E8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 232 }));
			Assert.assertEquals("E9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 233 }));
			Assert.assertEquals("EA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 234 }));
			Assert.assertEquals("EB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 235 }));
			Assert.assertEquals("EC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 236 }));
			Assert.assertEquals("ED", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 237 }));
			Assert.assertEquals("EE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 238 }));
			Assert.assertEquals("EF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 239 }));
			Assert.assertEquals("F0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 240 }));
			Assert.assertEquals("F1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 241 }));
			Assert.assertEquals("F2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 242 }));
			Assert.assertEquals("F3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 243 }));
			Assert.assertEquals("F4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 244 }));
			Assert.assertEquals("F5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 245 }));
			Assert.assertEquals("F6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 246 }));
			Assert.assertEquals("F7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 247 }));
			Assert.assertEquals("F8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 248 }));
			Assert.assertEquals("F9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 249 }));
			Assert.assertEquals("FA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 250 }));
			Assert.assertEquals("FB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 251 }));
			Assert.assertEquals("FC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 252 }));
			Assert.assertEquals("FD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 253 }));
			Assert.assertEquals("FE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 254 }));
			Assert.assertEquals("FF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) 255 }));

			Assert.assertEquals("80", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -128 }));
			Assert.assertEquals("81", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -127 }));
			Assert.assertEquals("82", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -126 }));
			Assert.assertEquals("83", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -125 }));
			Assert.assertEquals("84", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -124 }));
			Assert.assertEquals("85", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -123 }));
			Assert.assertEquals("86", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -122 }));
			Assert.assertEquals("87", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -121 }));
			Assert.assertEquals("88", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -120 }));
			Assert.assertEquals("89", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -119 }));
			Assert.assertEquals("8A", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -118 }));
			Assert.assertEquals("8B", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -117 }));
			Assert.assertEquals("8C", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -116 }));
			Assert.assertEquals("8D", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -115 }));
			Assert.assertEquals("8E", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -114 }));
			Assert.assertEquals("8F", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -113 }));
			Assert.assertEquals("90", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -112 }));
			Assert.assertEquals("91", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -111 }));
			Assert.assertEquals("92", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -110 }));
			Assert.assertEquals("93", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -109 }));
			Assert.assertEquals("94", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -108 }));
			Assert.assertEquals("95", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -107 }));
			Assert.assertEquals("96", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -106 }));
			Assert.assertEquals("97", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -105 }));
			Assert.assertEquals("98", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -104 }));
			Assert.assertEquals("99", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -103 }));
			Assert.assertEquals("9A", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -102 }));
			Assert.assertEquals("9B", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -101 }));
			Assert.assertEquals("9C", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -100 }));
			Assert.assertEquals("9D", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -99 }));
			Assert.assertEquals("9E", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -98 }));
			Assert.assertEquals("9F", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -97 }));
			Assert.assertEquals("A0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -96 }));
			Assert.assertEquals("A1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -95 }));
			Assert.assertEquals("A2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -94 }));
			Assert.assertEquals("A3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -93 }));
			Assert.assertEquals("A4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -92 }));
			Assert.assertEquals("A5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -91 }));
			Assert.assertEquals("A6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -90 }));
			Assert.assertEquals("A7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -89 }));
			Assert.assertEquals("A8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -88 }));
			Assert.assertEquals("A9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -87 }));
			Assert.assertEquals("AA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -86 }));
			Assert.assertEquals("AB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -85 }));
			Assert.assertEquals("AC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -84 }));
			Assert.assertEquals("AD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -83 }));
			Assert.assertEquals("AE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -82 }));
			Assert.assertEquals("AF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -81 }));
			Assert.assertEquals("B0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -80 }));
			Assert.assertEquals("B1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -79 }));
			Assert.assertEquals("B2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -78 }));
			Assert.assertEquals("B3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -77 }));
			Assert.assertEquals("B4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -76 }));
			Assert.assertEquals("B5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -75 }));
			Assert.assertEquals("B6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -74 }));
			Assert.assertEquals("B7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -73 }));
			Assert.assertEquals("B8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -72 }));
			Assert.assertEquals("B9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -71 }));
			Assert.assertEquals("BA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -70 }));
			Assert.assertEquals("BB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -69 }));
			Assert.assertEquals("BC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -68 }));
			Assert.assertEquals("BD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -67 }));
			Assert.assertEquals("BE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -66 }));
			Assert.assertEquals("BF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -65 }));
			Assert.assertEquals("C0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -64 }));
			Assert.assertEquals("C1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -63 }));
			Assert.assertEquals("C2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -62 }));
			Assert.assertEquals("C3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -61 }));
			Assert.assertEquals("C4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -60 }));
			Assert.assertEquals("C5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -59 }));
			Assert.assertEquals("C6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -58 }));
			Assert.assertEquals("C7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -57 }));
			Assert.assertEquals("C8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -56 }));
			Assert.assertEquals("C9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -55 }));
			Assert.assertEquals("CA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -54 }));
			Assert.assertEquals("CB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -53 }));
			Assert.assertEquals("CC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -52 }));
			Assert.assertEquals("CD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -51 }));
			Assert.assertEquals("CE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -50 }));
			Assert.assertEquals("CF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -49 }));
			Assert.assertEquals("D0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -48 }));
			Assert.assertEquals("D1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -47 }));
			Assert.assertEquals("D2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -46 }));
			Assert.assertEquals("D3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -45 }));
			Assert.assertEquals("D4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -44 }));
			Assert.assertEquals("D5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -43 }));
			Assert.assertEquals("D6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -42 }));
			Assert.assertEquals("D7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -41 }));
			Assert.assertEquals("D8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -40 }));
			Assert.assertEquals("D9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -39 }));
			Assert.assertEquals("DA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -38 }));
			Assert.assertEquals("DB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -37 }));
			Assert.assertEquals("DC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -36 }));
			Assert.assertEquals("DD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -35 }));
			Assert.assertEquals("DE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -34 }));
			Assert.assertEquals("DF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -33 }));
			Assert.assertEquals("E0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -32 }));
			Assert.assertEquals("E1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -31 }));
			Assert.assertEquals("E2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -30 }));
			Assert.assertEquals("E3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -29 }));
			Assert.assertEquals("E4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -28 }));
			Assert.assertEquals("E5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -27 }));
			Assert.assertEquals("E6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -26 }));
			Assert.assertEquals("E7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -25 }));
			Assert.assertEquals("E8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -24 }));
			Assert.assertEquals("E9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -23 }));
			Assert.assertEquals("EA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -22 }));
			Assert.assertEquals("EB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -21 }));
			Assert.assertEquals("EC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -20 }));
			Assert.assertEquals("ED", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -19 }));
			Assert.assertEquals("EE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -18 }));
			Assert.assertEquals("EF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -17 }));
			Assert.assertEquals("F0", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -16 }));
			Assert.assertEquals("F1", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -15 }));
			Assert.assertEquals("F2", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -14 }));
			Assert.assertEquals("F3", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -13 }));
			Assert.assertEquals("F4", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -12 }));
			Assert.assertEquals("F5", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -11 }));
			Assert.assertEquals("F6", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -10 }));
			Assert.assertEquals("F7", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -9 }));
			Assert.assertEquals("F8", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -8 }));
			Assert.assertEquals("F9", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -7 }));
			Assert.assertEquals("FA", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -6 }));
			Assert.assertEquals("FB", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -5 }));
			Assert.assertEquals("FC", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -4 }));
			Assert.assertEquals("FD", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -3 }));
			Assert.assertEquals("FE", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -2 }));
			Assert.assertEquals("FF", GaiaUtils.convertByteArrayToHexaString(new byte[] { (byte) -1 }));

			Assert.assertEquals(
					"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
					GaiaUtils.convertByteArrayToHexaString(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
							0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
							0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
							0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
							0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, (byte) 0x80, (byte) 0x81,
							(byte) 0x82, (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87, (byte) 0x88, (byte) 0x89, (byte) 0x8A, (byte) 0x8B, (byte) 0x8C, (byte) 0x8D, (byte) 0x8E,
							(byte) 0x8F, (byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93, (byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97, (byte) 0x98, (byte) 0x99, (byte) 0x9A, (byte) 0x9B,
							(byte) 0x9C, (byte) 0x9D, (byte) 0x9E, (byte) 0x9F, (byte) 0xA0, (byte) 0xA1, (byte) 0xA2, (byte) 0xA3, (byte) 0xA4, (byte) 0xA5, (byte) 0xA6, (byte) 0xA7, (byte) 0xA8,
							(byte) 0xA9, (byte) 0xAA, (byte) 0xAB, (byte) 0xAC, (byte) 0xAD, (byte) 0xAE, (byte) 0xAF, (byte) 0xB0, (byte) 0xB1, (byte) 0xB2, (byte) 0xB3, (byte) 0xB4, (byte) 0xB5,
							(byte) 0xB6, (byte) 0xB7, (byte) 0xB8, (byte) 0xB9, (byte) 0xBA, (byte) 0xBB, (byte) 0xBC, (byte) 0xBD, (byte) 0xBE, (byte) 0xBF, (byte) 0xC0, (byte) 0xC1, (byte) 0xC2,
							(byte) 0xC3, (byte) 0xC4, (byte) 0xC5, (byte) 0xC6, (byte) 0xC7, (byte) 0xC8, (byte) 0xC9, (byte) 0xCA, (byte) 0xCB, (byte) 0xCC, (byte) 0xCD, (byte) 0xCE, (byte) 0xCF,
							(byte) 0xD0, (byte) 0xD1, (byte) 0xD2, (byte) 0xD3, (byte) 0xD4, (byte) 0xD5, (byte) 0xD6, (byte) 0xD7, (byte) 0xD8, (byte) 0xD9, (byte) 0xDA, (byte) 0xDB, (byte) 0xDC,
							(byte) 0xDD, (byte) 0xDE, (byte) 0xDF, (byte) 0xE0, (byte) 0xE1, (byte) 0xE2, (byte) 0xE3, (byte) 0xE4, (byte) 0xE5, (byte) 0xE6, (byte) 0xE7, (byte) 0xE8, (byte) 0xE9,
							(byte) 0xEA, (byte) 0xEB, (byte) 0xEC, (byte) 0xED, (byte) 0xEE, (byte) 0xEF, (byte) 0xF0, (byte) 0xF1, (byte) 0xF2, (byte) 0xF3, (byte) 0xF4, (byte) 0xF5, (byte) 0xF6,
							(byte) 0xF7, (byte) 0xF8, (byte) 0xF9, (byte) 0xFA, (byte) 0xFB, (byte) 0xFC, (byte) 0xFD, (byte) 0xFE, (byte) 0xFF }));
		}
		catch ( GaiaException e )
		{
			e.printStackTrace();
			Assert.assertFalse(true);
		}
	}





	@Test
	public void test0009_convertByteArrayToHexaString_AbnormalTest()
	{
		try
		{
			GaiaUtils.convertByteArrayToHexaString(null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			byte[] data = null;
			GaiaUtils.convertByteArrayToHexaString(data);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.convertByteArrayToHexaString(new byte[] {});
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is empty byte[].", e.getMessage());
		}

		try
		{
			byte[] data = new byte[] {};
			GaiaUtils.convertByteArrayToHexaString(data);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is empty byte[].", e.getMessage());
		}
	}





	@Test
	public void test0010_convertHexaStringToByteArray_NormalTest()
	{
		try
		{
			Assert.assertArrayEquals(new byte[] { 0x00 }, GaiaUtils.convertHexaStringToByteArray("00"));
			Assert.assertArrayEquals(new byte[] { 0x01 }, GaiaUtils.convertHexaStringToByteArray("01"));
			Assert.assertArrayEquals(new byte[] { 0x02 }, GaiaUtils.convertHexaStringToByteArray("02"));
			Assert.assertArrayEquals(new byte[] { 0x03 }, GaiaUtils.convertHexaStringToByteArray("03"));
			Assert.assertArrayEquals(new byte[] { 0x04 }, GaiaUtils.convertHexaStringToByteArray("04"));
			Assert.assertArrayEquals(new byte[] { 0x05 }, GaiaUtils.convertHexaStringToByteArray("05"));
			Assert.assertArrayEquals(new byte[] { 0x06 }, GaiaUtils.convertHexaStringToByteArray("06"));
			Assert.assertArrayEquals(new byte[] { 0x07 }, GaiaUtils.convertHexaStringToByteArray("07"));
			Assert.assertArrayEquals(new byte[] { 0x08 }, GaiaUtils.convertHexaStringToByteArray("08"));
			Assert.assertArrayEquals(new byte[] { 0x09 }, GaiaUtils.convertHexaStringToByteArray("09"));
			Assert.assertArrayEquals(new byte[] { 0x0A }, GaiaUtils.convertHexaStringToByteArray("0A"));
			Assert.assertArrayEquals(new byte[] { 0x0B }, GaiaUtils.convertHexaStringToByteArray("0B"));
			Assert.assertArrayEquals(new byte[] { 0x0C }, GaiaUtils.convertHexaStringToByteArray("0C"));
			Assert.assertArrayEquals(new byte[] { 0x0D }, GaiaUtils.convertHexaStringToByteArray("0D"));
			Assert.assertArrayEquals(new byte[] { 0x0E }, GaiaUtils.convertHexaStringToByteArray("0E"));
			Assert.assertArrayEquals(new byte[] { 0x0F }, GaiaUtils.convertHexaStringToByteArray("0F"));
			Assert.assertArrayEquals(new byte[] { 0x10 }, GaiaUtils.convertHexaStringToByteArray("10"));
			Assert.assertArrayEquals(new byte[] { 0x11 }, GaiaUtils.convertHexaStringToByteArray("11"));
			Assert.assertArrayEquals(new byte[] { 0x12 }, GaiaUtils.convertHexaStringToByteArray("12"));
			Assert.assertArrayEquals(new byte[] { 0x13 }, GaiaUtils.convertHexaStringToByteArray("13"));
			Assert.assertArrayEquals(new byte[] { 0x14 }, GaiaUtils.convertHexaStringToByteArray("14"));
			Assert.assertArrayEquals(new byte[] { 0x15 }, GaiaUtils.convertHexaStringToByteArray("15"));
			Assert.assertArrayEquals(new byte[] { 0x16 }, GaiaUtils.convertHexaStringToByteArray("16"));
			Assert.assertArrayEquals(new byte[] { 0x17 }, GaiaUtils.convertHexaStringToByteArray("17"));
			Assert.assertArrayEquals(new byte[] { 0x18 }, GaiaUtils.convertHexaStringToByteArray("18"));
			Assert.assertArrayEquals(new byte[] { 0x19 }, GaiaUtils.convertHexaStringToByteArray("19"));
			Assert.assertArrayEquals(new byte[] { 0x1A }, GaiaUtils.convertHexaStringToByteArray("1A"));
			Assert.assertArrayEquals(new byte[] { 0x1B }, GaiaUtils.convertHexaStringToByteArray("1B"));
			Assert.assertArrayEquals(new byte[] { 0x1C }, GaiaUtils.convertHexaStringToByteArray("1C"));
			Assert.assertArrayEquals(new byte[] { 0x1D }, GaiaUtils.convertHexaStringToByteArray("1D"));
			Assert.assertArrayEquals(new byte[] { 0x1E }, GaiaUtils.convertHexaStringToByteArray("1E"));
			Assert.assertArrayEquals(new byte[] { 0x1F }, GaiaUtils.convertHexaStringToByteArray("1F"));
			Assert.assertArrayEquals(new byte[] { 0x20 }, GaiaUtils.convertHexaStringToByteArray("20"));
			Assert.assertArrayEquals(new byte[] { 0x21 }, GaiaUtils.convertHexaStringToByteArray("21"));
			Assert.assertArrayEquals(new byte[] { 0x22 }, GaiaUtils.convertHexaStringToByteArray("22"));
			Assert.assertArrayEquals(new byte[] { 0x23 }, GaiaUtils.convertHexaStringToByteArray("23"));
			Assert.assertArrayEquals(new byte[] { 0x24 }, GaiaUtils.convertHexaStringToByteArray("24"));
			Assert.assertArrayEquals(new byte[] { 0x25 }, GaiaUtils.convertHexaStringToByteArray("25"));
			Assert.assertArrayEquals(new byte[] { 0x26 }, GaiaUtils.convertHexaStringToByteArray("26"));
			Assert.assertArrayEquals(new byte[] { 0x27 }, GaiaUtils.convertHexaStringToByteArray("27"));
			Assert.assertArrayEquals(new byte[] { 0x28 }, GaiaUtils.convertHexaStringToByteArray("28"));
			Assert.assertArrayEquals(new byte[] { 0x29 }, GaiaUtils.convertHexaStringToByteArray("29"));
			Assert.assertArrayEquals(new byte[] { 0x2A }, GaiaUtils.convertHexaStringToByteArray("2A"));
			Assert.assertArrayEquals(new byte[] { 0x2B }, GaiaUtils.convertHexaStringToByteArray("2B"));
			Assert.assertArrayEquals(new byte[] { 0x2C }, GaiaUtils.convertHexaStringToByteArray("2C"));
			Assert.assertArrayEquals(new byte[] { 0x2D }, GaiaUtils.convertHexaStringToByteArray("2D"));
			Assert.assertArrayEquals(new byte[] { 0x2E }, GaiaUtils.convertHexaStringToByteArray("2E"));
			Assert.assertArrayEquals(new byte[] { 0x2F }, GaiaUtils.convertHexaStringToByteArray("2F"));
			Assert.assertArrayEquals(new byte[] { 0x30 }, GaiaUtils.convertHexaStringToByteArray("30"));
			Assert.assertArrayEquals(new byte[] { 0x31 }, GaiaUtils.convertHexaStringToByteArray("31"));
			Assert.assertArrayEquals(new byte[] { 0x32 }, GaiaUtils.convertHexaStringToByteArray("32"));
			Assert.assertArrayEquals(new byte[] { 0x33 }, GaiaUtils.convertHexaStringToByteArray("33"));
			Assert.assertArrayEquals(new byte[] { 0x34 }, GaiaUtils.convertHexaStringToByteArray("34"));
			Assert.assertArrayEquals(new byte[] { 0x35 }, GaiaUtils.convertHexaStringToByteArray("35"));
			Assert.assertArrayEquals(new byte[] { 0x36 }, GaiaUtils.convertHexaStringToByteArray("36"));
			Assert.assertArrayEquals(new byte[] { 0x37 }, GaiaUtils.convertHexaStringToByteArray("37"));
			Assert.assertArrayEquals(new byte[] { 0x38 }, GaiaUtils.convertHexaStringToByteArray("38"));
			Assert.assertArrayEquals(new byte[] { 0x39 }, GaiaUtils.convertHexaStringToByteArray("39"));
			Assert.assertArrayEquals(new byte[] { 0x3A }, GaiaUtils.convertHexaStringToByteArray("3A"));
			Assert.assertArrayEquals(new byte[] { 0x3B }, GaiaUtils.convertHexaStringToByteArray("3B"));
			Assert.assertArrayEquals(new byte[] { 0x3C }, GaiaUtils.convertHexaStringToByteArray("3C"));
			Assert.assertArrayEquals(new byte[] { 0x3D }, GaiaUtils.convertHexaStringToByteArray("3D"));
			Assert.assertArrayEquals(new byte[] { 0x3E }, GaiaUtils.convertHexaStringToByteArray("3E"));
			Assert.assertArrayEquals(new byte[] { 0x3F }, GaiaUtils.convertHexaStringToByteArray("3F"));
			Assert.assertArrayEquals(new byte[] { 0x40 }, GaiaUtils.convertHexaStringToByteArray("40"));
			Assert.assertArrayEquals(new byte[] { 0x41 }, GaiaUtils.convertHexaStringToByteArray("41"));
			Assert.assertArrayEquals(new byte[] { 0x42 }, GaiaUtils.convertHexaStringToByteArray("42"));
			Assert.assertArrayEquals(new byte[] { 0x43 }, GaiaUtils.convertHexaStringToByteArray("43"));
			Assert.assertArrayEquals(new byte[] { 0x44 }, GaiaUtils.convertHexaStringToByteArray("44"));
			Assert.assertArrayEquals(new byte[] { 0x45 }, GaiaUtils.convertHexaStringToByteArray("45"));
			Assert.assertArrayEquals(new byte[] { 0x46 }, GaiaUtils.convertHexaStringToByteArray("46"));
			Assert.assertArrayEquals(new byte[] { 0x47 }, GaiaUtils.convertHexaStringToByteArray("47"));
			Assert.assertArrayEquals(new byte[] { 0x48 }, GaiaUtils.convertHexaStringToByteArray("48"));
			Assert.assertArrayEquals(new byte[] { 0x49 }, GaiaUtils.convertHexaStringToByteArray("49"));
			Assert.assertArrayEquals(new byte[] { 0x4A }, GaiaUtils.convertHexaStringToByteArray("4A"));
			Assert.assertArrayEquals(new byte[] { 0x4B }, GaiaUtils.convertHexaStringToByteArray("4B"));
			Assert.assertArrayEquals(new byte[] { 0x4C }, GaiaUtils.convertHexaStringToByteArray("4C"));
			Assert.assertArrayEquals(new byte[] { 0x4D }, GaiaUtils.convertHexaStringToByteArray("4D"));
			Assert.assertArrayEquals(new byte[] { 0x4E }, GaiaUtils.convertHexaStringToByteArray("4E"));
			Assert.assertArrayEquals(new byte[] { 0x4F }, GaiaUtils.convertHexaStringToByteArray("4F"));
			Assert.assertArrayEquals(new byte[] { 0x50 }, GaiaUtils.convertHexaStringToByteArray("50"));
			Assert.assertArrayEquals(new byte[] { 0x51 }, GaiaUtils.convertHexaStringToByteArray("51"));
			Assert.assertArrayEquals(new byte[] { 0x52 }, GaiaUtils.convertHexaStringToByteArray("52"));
			Assert.assertArrayEquals(new byte[] { 0x53 }, GaiaUtils.convertHexaStringToByteArray("53"));
			Assert.assertArrayEquals(new byte[] { 0x54 }, GaiaUtils.convertHexaStringToByteArray("54"));
			Assert.assertArrayEquals(new byte[] { 0x55 }, GaiaUtils.convertHexaStringToByteArray("55"));
			Assert.assertArrayEquals(new byte[] { 0x56 }, GaiaUtils.convertHexaStringToByteArray("56"));
			Assert.assertArrayEquals(new byte[] { 0x57 }, GaiaUtils.convertHexaStringToByteArray("57"));
			Assert.assertArrayEquals(new byte[] { 0x58 }, GaiaUtils.convertHexaStringToByteArray("58"));
			Assert.assertArrayEquals(new byte[] { 0x59 }, GaiaUtils.convertHexaStringToByteArray("59"));
			Assert.assertArrayEquals(new byte[] { 0x5A }, GaiaUtils.convertHexaStringToByteArray("5A"));
			Assert.assertArrayEquals(new byte[] { 0x5B }, GaiaUtils.convertHexaStringToByteArray("5B"));
			Assert.assertArrayEquals(new byte[] { 0x5C }, GaiaUtils.convertHexaStringToByteArray("5C"));
			Assert.assertArrayEquals(new byte[] { 0x5D }, GaiaUtils.convertHexaStringToByteArray("5D"));
			Assert.assertArrayEquals(new byte[] { 0x5E }, GaiaUtils.convertHexaStringToByteArray("5E"));
			Assert.assertArrayEquals(new byte[] { 0x5F }, GaiaUtils.convertHexaStringToByteArray("5F"));
			Assert.assertArrayEquals(new byte[] { 0x60 }, GaiaUtils.convertHexaStringToByteArray("60"));
			Assert.assertArrayEquals(new byte[] { 0x61 }, GaiaUtils.convertHexaStringToByteArray("61"));
			Assert.assertArrayEquals(new byte[] { 0x62 }, GaiaUtils.convertHexaStringToByteArray("62"));
			Assert.assertArrayEquals(new byte[] { 0x63 }, GaiaUtils.convertHexaStringToByteArray("63"));
			Assert.assertArrayEquals(new byte[] { 0x64 }, GaiaUtils.convertHexaStringToByteArray("64"));
			Assert.assertArrayEquals(new byte[] { 0x65 }, GaiaUtils.convertHexaStringToByteArray("65"));
			Assert.assertArrayEquals(new byte[] { 0x66 }, GaiaUtils.convertHexaStringToByteArray("66"));
			Assert.assertArrayEquals(new byte[] { 0x67 }, GaiaUtils.convertHexaStringToByteArray("67"));
			Assert.assertArrayEquals(new byte[] { 0x68 }, GaiaUtils.convertHexaStringToByteArray("68"));
			Assert.assertArrayEquals(new byte[] { 0x69 }, GaiaUtils.convertHexaStringToByteArray("69"));
			Assert.assertArrayEquals(new byte[] { 0x6A }, GaiaUtils.convertHexaStringToByteArray("6A"));
			Assert.assertArrayEquals(new byte[] { 0x6B }, GaiaUtils.convertHexaStringToByteArray("6B"));
			Assert.assertArrayEquals(new byte[] { 0x6C }, GaiaUtils.convertHexaStringToByteArray("6C"));
			Assert.assertArrayEquals(new byte[] { 0x6D }, GaiaUtils.convertHexaStringToByteArray("6D"));
			Assert.assertArrayEquals(new byte[] { 0x6E }, GaiaUtils.convertHexaStringToByteArray("6E"));
			Assert.assertArrayEquals(new byte[] { 0x6F }, GaiaUtils.convertHexaStringToByteArray("6F"));
			Assert.assertArrayEquals(new byte[] { 0x70 }, GaiaUtils.convertHexaStringToByteArray("70"));
			Assert.assertArrayEquals(new byte[] { 0x71 }, GaiaUtils.convertHexaStringToByteArray("71"));
			Assert.assertArrayEquals(new byte[] { 0x72 }, GaiaUtils.convertHexaStringToByteArray("72"));
			Assert.assertArrayEquals(new byte[] { 0x73 }, GaiaUtils.convertHexaStringToByteArray("73"));
			Assert.assertArrayEquals(new byte[] { 0x74 }, GaiaUtils.convertHexaStringToByteArray("74"));
			Assert.assertArrayEquals(new byte[] { 0x75 }, GaiaUtils.convertHexaStringToByteArray("75"));
			Assert.assertArrayEquals(new byte[] { 0x76 }, GaiaUtils.convertHexaStringToByteArray("76"));
			Assert.assertArrayEquals(new byte[] { 0x77 }, GaiaUtils.convertHexaStringToByteArray("77"));
			Assert.assertArrayEquals(new byte[] { 0x78 }, GaiaUtils.convertHexaStringToByteArray("78"));
			Assert.assertArrayEquals(new byte[] { 0x79 }, GaiaUtils.convertHexaStringToByteArray("79"));
			Assert.assertArrayEquals(new byte[] { 0x7A }, GaiaUtils.convertHexaStringToByteArray("7A"));
			Assert.assertArrayEquals(new byte[] { 0x7B }, GaiaUtils.convertHexaStringToByteArray("7B"));
			Assert.assertArrayEquals(new byte[] { 0x7C }, GaiaUtils.convertHexaStringToByteArray("7C"));
			Assert.assertArrayEquals(new byte[] { 0x7D }, GaiaUtils.convertHexaStringToByteArray("7D"));
			Assert.assertArrayEquals(new byte[] { 0x7E }, GaiaUtils.convertHexaStringToByteArray("7E"));
			Assert.assertArrayEquals(new byte[] { 0x7F }, GaiaUtils.convertHexaStringToByteArray("7F"));

			Assert.assertArrayEquals(new byte[] { (byte) 0x80 }, GaiaUtils.convertHexaStringToByteArray("80"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x81 }, GaiaUtils.convertHexaStringToByteArray("81"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x82 }, GaiaUtils.convertHexaStringToByteArray("82"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x83 }, GaiaUtils.convertHexaStringToByteArray("83"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x84 }, GaiaUtils.convertHexaStringToByteArray("84"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x85 }, GaiaUtils.convertHexaStringToByteArray("85"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x86 }, GaiaUtils.convertHexaStringToByteArray("86"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x87 }, GaiaUtils.convertHexaStringToByteArray("87"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x88 }, GaiaUtils.convertHexaStringToByteArray("88"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x89 }, GaiaUtils.convertHexaStringToByteArray("89"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x8A }, GaiaUtils.convertHexaStringToByteArray("8A"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x8B }, GaiaUtils.convertHexaStringToByteArray("8B"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x8C }, GaiaUtils.convertHexaStringToByteArray("8C"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x8D }, GaiaUtils.convertHexaStringToByteArray("8D"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x8E }, GaiaUtils.convertHexaStringToByteArray("8E"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x8F }, GaiaUtils.convertHexaStringToByteArray("8F"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x90 }, GaiaUtils.convertHexaStringToByteArray("90"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x91 }, GaiaUtils.convertHexaStringToByteArray("91"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x92 }, GaiaUtils.convertHexaStringToByteArray("92"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x93 }, GaiaUtils.convertHexaStringToByteArray("93"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x94 }, GaiaUtils.convertHexaStringToByteArray("94"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x95 }, GaiaUtils.convertHexaStringToByteArray("95"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x96 }, GaiaUtils.convertHexaStringToByteArray("96"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x97 }, GaiaUtils.convertHexaStringToByteArray("97"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x98 }, GaiaUtils.convertHexaStringToByteArray("98"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x99 }, GaiaUtils.convertHexaStringToByteArray("99"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x9A }, GaiaUtils.convertHexaStringToByteArray("9A"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x9B }, GaiaUtils.convertHexaStringToByteArray("9B"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x9C }, GaiaUtils.convertHexaStringToByteArray("9C"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x9D }, GaiaUtils.convertHexaStringToByteArray("9D"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x9E }, GaiaUtils.convertHexaStringToByteArray("9E"));
			Assert.assertArrayEquals(new byte[] { (byte) 0x9F }, GaiaUtils.convertHexaStringToByteArray("9F"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xA0 }, GaiaUtils.convertHexaStringToByteArray("A0"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xA1 }, GaiaUtils.convertHexaStringToByteArray("A1"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xA2 }, GaiaUtils.convertHexaStringToByteArray("A2"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xA3 }, GaiaUtils.convertHexaStringToByteArray("A3"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xA4 }, GaiaUtils.convertHexaStringToByteArray("A4"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xA5 }, GaiaUtils.convertHexaStringToByteArray("A5"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xA6 }, GaiaUtils.convertHexaStringToByteArray("A6"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xA7 }, GaiaUtils.convertHexaStringToByteArray("A7"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xA8 }, GaiaUtils.convertHexaStringToByteArray("A8"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xA9 }, GaiaUtils.convertHexaStringToByteArray("A9"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xAA }, GaiaUtils.convertHexaStringToByteArray("AA"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xAB }, GaiaUtils.convertHexaStringToByteArray("AB"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xAC }, GaiaUtils.convertHexaStringToByteArray("AC"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xAD }, GaiaUtils.convertHexaStringToByteArray("AD"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xAE }, GaiaUtils.convertHexaStringToByteArray("AE"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xAF }, GaiaUtils.convertHexaStringToByteArray("AF"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xB0 }, GaiaUtils.convertHexaStringToByteArray("B0"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xB1 }, GaiaUtils.convertHexaStringToByteArray("B1"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xB2 }, GaiaUtils.convertHexaStringToByteArray("B2"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xB3 }, GaiaUtils.convertHexaStringToByteArray("B3"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xB4 }, GaiaUtils.convertHexaStringToByteArray("B4"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xB5 }, GaiaUtils.convertHexaStringToByteArray("B5"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xB6 }, GaiaUtils.convertHexaStringToByteArray("B6"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xB7 }, GaiaUtils.convertHexaStringToByteArray("B7"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xB8 }, GaiaUtils.convertHexaStringToByteArray("B8"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xB9 }, GaiaUtils.convertHexaStringToByteArray("B9"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xBA }, GaiaUtils.convertHexaStringToByteArray("BA"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xBB }, GaiaUtils.convertHexaStringToByteArray("BB"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xBC }, GaiaUtils.convertHexaStringToByteArray("BC"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xBD }, GaiaUtils.convertHexaStringToByteArray("BD"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xBE }, GaiaUtils.convertHexaStringToByteArray("BE"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xBF }, GaiaUtils.convertHexaStringToByteArray("BF"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xC0 }, GaiaUtils.convertHexaStringToByteArray("C0"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xC1 }, GaiaUtils.convertHexaStringToByteArray("C1"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xC2 }, GaiaUtils.convertHexaStringToByteArray("C2"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xC3 }, GaiaUtils.convertHexaStringToByteArray("C3"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xC4 }, GaiaUtils.convertHexaStringToByteArray("C4"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xC5 }, GaiaUtils.convertHexaStringToByteArray("C5"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xC6 }, GaiaUtils.convertHexaStringToByteArray("C6"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xC7 }, GaiaUtils.convertHexaStringToByteArray("C7"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xC8 }, GaiaUtils.convertHexaStringToByteArray("C8"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xC9 }, GaiaUtils.convertHexaStringToByteArray("C9"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xCA }, GaiaUtils.convertHexaStringToByteArray("CA"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xCB }, GaiaUtils.convertHexaStringToByteArray("CB"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xCC }, GaiaUtils.convertHexaStringToByteArray("CC"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xCD }, GaiaUtils.convertHexaStringToByteArray("CD"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xCE }, GaiaUtils.convertHexaStringToByteArray("CE"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xCF }, GaiaUtils.convertHexaStringToByteArray("CF"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xD0 }, GaiaUtils.convertHexaStringToByteArray("D0"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xD1 }, GaiaUtils.convertHexaStringToByteArray("D1"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xD2 }, GaiaUtils.convertHexaStringToByteArray("D2"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xD3 }, GaiaUtils.convertHexaStringToByteArray("D3"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xD4 }, GaiaUtils.convertHexaStringToByteArray("D4"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xD5 }, GaiaUtils.convertHexaStringToByteArray("D5"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xD6 }, GaiaUtils.convertHexaStringToByteArray("D6"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xD7 }, GaiaUtils.convertHexaStringToByteArray("D7"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xD8 }, GaiaUtils.convertHexaStringToByteArray("D8"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xD9 }, GaiaUtils.convertHexaStringToByteArray("D9"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xDA }, GaiaUtils.convertHexaStringToByteArray("DA"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xDB }, GaiaUtils.convertHexaStringToByteArray("DB"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xDC }, GaiaUtils.convertHexaStringToByteArray("DC"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xDD }, GaiaUtils.convertHexaStringToByteArray("DD"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xDE }, GaiaUtils.convertHexaStringToByteArray("DE"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xDF }, GaiaUtils.convertHexaStringToByteArray("DF"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xE0 }, GaiaUtils.convertHexaStringToByteArray("E0"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xE1 }, GaiaUtils.convertHexaStringToByteArray("E1"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xE2 }, GaiaUtils.convertHexaStringToByteArray("E2"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xE3 }, GaiaUtils.convertHexaStringToByteArray("E3"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xE4 }, GaiaUtils.convertHexaStringToByteArray("E4"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xE5 }, GaiaUtils.convertHexaStringToByteArray("E5"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xE6 }, GaiaUtils.convertHexaStringToByteArray("E6"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xE7 }, GaiaUtils.convertHexaStringToByteArray("E7"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xE8 }, GaiaUtils.convertHexaStringToByteArray("E8"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xE9 }, GaiaUtils.convertHexaStringToByteArray("E9"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xEA }, GaiaUtils.convertHexaStringToByteArray("EA"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xEB }, GaiaUtils.convertHexaStringToByteArray("EB"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xEC }, GaiaUtils.convertHexaStringToByteArray("EC"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xED }, GaiaUtils.convertHexaStringToByteArray("ED"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xEE }, GaiaUtils.convertHexaStringToByteArray("EE"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xEF }, GaiaUtils.convertHexaStringToByteArray("EF"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xF0 }, GaiaUtils.convertHexaStringToByteArray("F0"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xF1 }, GaiaUtils.convertHexaStringToByteArray("F1"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xF2 }, GaiaUtils.convertHexaStringToByteArray("F2"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xF3 }, GaiaUtils.convertHexaStringToByteArray("F3"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xF4 }, GaiaUtils.convertHexaStringToByteArray("F4"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xF5 }, GaiaUtils.convertHexaStringToByteArray("F5"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xF6 }, GaiaUtils.convertHexaStringToByteArray("F6"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xF7 }, GaiaUtils.convertHexaStringToByteArray("F7"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xF8 }, GaiaUtils.convertHexaStringToByteArray("F8"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xF9 }, GaiaUtils.convertHexaStringToByteArray("F9"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xFA }, GaiaUtils.convertHexaStringToByteArray("FA"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xFB }, GaiaUtils.convertHexaStringToByteArray("FB"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xFC }, GaiaUtils.convertHexaStringToByteArray("FC"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xFD }, GaiaUtils.convertHexaStringToByteArray("FD"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xFE }, GaiaUtils.convertHexaStringToByteArray("FE"));
			Assert.assertArrayEquals(new byte[] { (byte) 0xFF }, GaiaUtils.convertHexaStringToByteArray("FF"));

			Assert.assertArrayEquals(
					new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
							0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
							0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52,
							0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
							0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, (byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83, (byte) 0x84,
							(byte) 0x85, (byte) 0x86, (byte) 0x87, (byte) 0x88, (byte) 0x89, (byte) 0x8A, (byte) 0x8B, (byte) 0x8C, (byte) 0x8D, (byte) 0x8E, (byte) 0x8F, (byte) 0x90, (byte) 0x91,
							(byte) 0x92, (byte) 0x93, (byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97, (byte) 0x98, (byte) 0x99, (byte) 0x9A, (byte) 0x9B, (byte) 0x9C, (byte) 0x9D, (byte) 0x9E,
							(byte) 0x9F, (byte) 0xA0, (byte) 0xA1, (byte) 0xA2, (byte) 0xA3, (byte) 0xA4, (byte) 0xA5, (byte) 0xA6, (byte) 0xA7, (byte) 0xA8, (byte) 0xA9, (byte) 0xAA, (byte) 0xAB,
							(byte) 0xAC, (byte) 0xAD, (byte) 0xAE, (byte) 0xAF, (byte) 0xB0, (byte) 0xB1, (byte) 0xB2, (byte) 0xB3, (byte) 0xB4, (byte) 0xB5, (byte) 0xB6, (byte) 0xB7, (byte) 0xB8,
							(byte) 0xB9, (byte) 0xBA, (byte) 0xBB, (byte) 0xBC, (byte) 0xBD, (byte) 0xBE, (byte) 0xBF, (byte) 0xC0, (byte) 0xC1, (byte) 0xC2, (byte) 0xC3, (byte) 0xC4, (byte) 0xC5,
							(byte) 0xC6, (byte) 0xC7, (byte) 0xC8, (byte) 0xC9, (byte) 0xCA, (byte) 0xCB, (byte) 0xCC, (byte) 0xCD, (byte) 0xCE, (byte) 0xCF, (byte) 0xD0, (byte) 0xD1, (byte) 0xD2,
							(byte) 0xD3, (byte) 0xD4, (byte) 0xD5, (byte) 0xD6, (byte) 0xD7, (byte) 0xD8, (byte) 0xD9, (byte) 0xDA, (byte) 0xDB, (byte) 0xDC, (byte) 0xDD, (byte) 0xDE, (byte) 0xDF,
							(byte) 0xE0, (byte) 0xE1, (byte) 0xE2, (byte) 0xE3, (byte) 0xE4, (byte) 0xE5, (byte) 0xE6, (byte) 0xE7, (byte) 0xE8, (byte) 0xE9, (byte) 0xEA, (byte) 0xEB, (byte) 0xEC,
							(byte) 0xED, (byte) 0xEE, (byte) 0xEF, (byte) 0xF0, (byte) 0xF1, (byte) 0xF2, (byte) 0xF3, (byte) 0xF4, (byte) 0xF5, (byte) 0xF6, (byte) 0xF7, (byte) 0xF8, (byte) 0xF9,
							(byte) 0xFA, (byte) 0xFB, (byte) 0xFC, (byte) 0xFD, (byte) 0xFE, (byte) 0xFF },
					GaiaUtils
							.convertHexaStringToByteArray("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"));

			Assert.assertArrayEquals(
					new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
							0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
							0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52,
							0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
							0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, (byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83, (byte) 0x84,
							(byte) 0x85, (byte) 0x86, (byte) 0x87, (byte) 0x88, (byte) 0x89, (byte) 0x8A, (byte) 0x8B, (byte) 0x8C, (byte) 0x8D, (byte) 0x8E, (byte) 0x8F, (byte) 0x90, (byte) 0x91,
							(byte) 0x92, (byte) 0x93, (byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97, (byte) 0x98, (byte) 0x99, (byte) 0x9A, (byte) 0x9B, (byte) 0x9C, (byte) 0x9D, (byte) 0x9E,
							(byte) 0x9F, (byte) 0xA0, (byte) 0xA1, (byte) 0xA2, (byte) 0xA3, (byte) 0xA4, (byte) 0xA5, (byte) 0xA6, (byte) 0xA7, (byte) 0xA8, (byte) 0xA9, (byte) 0xAA, (byte) 0xAB,
							(byte) 0xAC, (byte) 0xAD, (byte) 0xAE, (byte) 0xAF, (byte) 0xB0, (byte) 0xB1, (byte) 0xB2, (byte) 0xB3, (byte) 0xB4, (byte) 0xB5, (byte) 0xB6, (byte) 0xB7, (byte) 0xB8,
							(byte) 0xB9, (byte) 0xBA, (byte) 0xBB, (byte) 0xBC, (byte) 0xBD, (byte) 0xBE, (byte) 0xBF, (byte) 0xC0, (byte) 0xC1, (byte) 0xC2, (byte) 0xC3, (byte) 0xC4, (byte) 0xC5,
							(byte) 0xC6, (byte) 0xC7, (byte) 0xC8, (byte) 0xC9, (byte) 0xCA, (byte) 0xCB, (byte) 0xCC, (byte) 0xCD, (byte) 0xCE, (byte) 0xCF, (byte) 0xD0, (byte) 0xD1, (byte) 0xD2,
							(byte) 0xD3, (byte) 0xD4, (byte) 0xD5, (byte) 0xD6, (byte) 0xD7, (byte) 0xD8, (byte) 0xD9, (byte) 0xDA, (byte) 0xDB, (byte) 0xDC, (byte) 0xDD, (byte) 0xDE, (byte) 0xDF,
							(byte) 0xE0, (byte) 0xE1, (byte) 0xE2, (byte) 0xE3, (byte) 0xE4, (byte) 0xE5, (byte) 0xE6, (byte) 0xE7, (byte) 0xE8, (byte) 0xE9, (byte) 0xEA, (byte) 0xEB, (byte) 0xEC,
							(byte) 0xED, (byte) 0xEE, (byte) 0xEF, (byte) 0xF0, (byte) 0xF1, (byte) 0xF2, (byte) 0xF3, (byte) 0xF4, (byte) 0xF5, (byte) 0xF6, (byte) 0xF7, (byte) 0xF8, (byte) 0xF9,
							(byte) 0xFA, (byte) 0xFB, (byte) 0xFC, (byte) 0xFD, (byte) 0xFE, (byte) 0xFF },
					GaiaUtils
							.convertHexaStringToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));

		}
		catch ( GaiaException e )
		{
			e.printStackTrace();
			Assert.assertFalse(true);
		}
	}





	@Test
	public void test0011_convertHexaStringToByteArray_AbnormalTest()
	{
		try
		{
			GaiaUtils.convertHexaStringToByteArray(null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.convertHexaStringToByteArray("");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is empty String.", e.getMessage());
		}

		try
		{
			GaiaUtils.convertHexaStringToByteArray("0");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string length[1] is not even.", e.getMessage());
		}

		try
		{
			GaiaUtils.convertHexaStringToByteArray("0123456789A");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string length[11] is not even.", e.getMessage());
		}

		try
		{
			GaiaUtils.convertHexaStringToByteArray("0123456789AZ");
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string[11] is not a hexadigit.", e.getMessage());
		}
	}





	@Test
	public void test0012_oneAndZeroesPadding_NormalTest()
	{
		try
		{
			Assert.assertEquals("1280000000000000", GaiaUtils.oneAndZeroesPadding("12"));
			Assert.assertEquals("1280000000000000", GaiaUtils.oneAndZeroesPadding("12", 8));

			Assert.assertEquals("1234800000000000", GaiaUtils.oneAndZeroesPadding("1234"));
			Assert.assertEquals("1234800000000000", GaiaUtils.oneAndZeroesPadding("1234", 8));

			Assert.assertEquals("1234568000000000", GaiaUtils.oneAndZeroesPadding("123456"));
			Assert.assertEquals("1234568000000000", GaiaUtils.oneAndZeroesPadding("123456", 8));

			Assert.assertEquals("1234567880000000", GaiaUtils.oneAndZeroesPadding("12345678"));
			Assert.assertEquals("1234567880000000", GaiaUtils.oneAndZeroesPadding("12345678", 8));

			Assert.assertEquals("1234567890128000", GaiaUtils.oneAndZeroesPadding("123456789012"));
			Assert.assertEquals("1234567890128000", GaiaUtils.oneAndZeroesPadding("123456789012", 8));

			Assert.assertEquals("1234567890123480", GaiaUtils.oneAndZeroesPadding("12345678901234"));
			Assert.assertEquals("1234567890123480", GaiaUtils.oneAndZeroesPadding("12345678901234", 8));

			Assert.assertEquals("12345678901234568000000000000000", GaiaUtils.oneAndZeroesPadding("1234567890123456"));
			Assert.assertEquals("12345678901234568000000000000000", GaiaUtils.oneAndZeroesPadding("1234567890123456", 8));

			Assert.assertEquals("12345678901234567880000000000000", GaiaUtils.oneAndZeroesPadding("123456789012345678"));
			Assert.assertEquals("12345678901234567880000000000000", GaiaUtils.oneAndZeroesPadding("123456789012345678", 8));

			Assert.assertEquals("12345678901234567890800000000000", GaiaUtils.oneAndZeroesPadding("12345678901234567890"));
			Assert.assertEquals("12345678901234567890800000000000", GaiaUtils.oneAndZeroesPadding("12345678901234567890", 8));

			Assert.assertEquals("12345678901234567890128000000000", GaiaUtils.oneAndZeroesPadding("1234567890123456789012"));
			Assert.assertEquals("12345678901234567890128000000000", GaiaUtils.oneAndZeroesPadding("1234567890123456789012", 8));

			Assert.assertEquals("12345678901234567890123480000000", GaiaUtils.oneAndZeroesPadding("123456789012345678901234"));
			Assert.assertEquals("12345678901234567890123480000000", GaiaUtils.oneAndZeroesPadding("123456789012345678901234", 8));

			Assert.assertEquals("12345678901234567890123456800000", GaiaUtils.oneAndZeroesPadding("12345678901234567890123456"));
			Assert.assertEquals("12345678901234567890123456800000", GaiaUtils.oneAndZeroesPadding("12345678901234567890123456", 8));

			Assert.assertEquals("12345678901234567890123456788000", GaiaUtils.oneAndZeroesPadding("1234567890123456789012345678"));
			Assert.assertEquals("12345678901234567890123456788000", GaiaUtils.oneAndZeroesPadding("1234567890123456789012345678", 8));

			Assert.assertEquals("12345678901234567890123456789080", GaiaUtils.oneAndZeroesPadding("123456789012345678901234567890"));
			Assert.assertEquals("12345678901234567890123456789080", GaiaUtils.oneAndZeroesPadding("123456789012345678901234567890", 8));

			Assert.assertEquals("123456789012345678901234567890128000000000000000", GaiaUtils.oneAndZeroesPadding("12345678901234567890123456789012"));
			Assert.assertEquals("123456789012345678901234567890128000000000000000", GaiaUtils.oneAndZeroesPadding("12345678901234567890123456789012", 8));

			Assert.assertEquals("12800000", GaiaUtils.oneAndZeroesPadding("12", 4));
			Assert.assertEquals("12348000", GaiaUtils.oneAndZeroesPadding("1234", 4));
			Assert.assertEquals("12345680", GaiaUtils.oneAndZeroesPadding("123456", 4));
			Assert.assertEquals("1234567880000000", GaiaUtils.oneAndZeroesPadding("12345678", 4));

			Assert.assertEquals("12800000000000000000000000000000", GaiaUtils.oneAndZeroesPadding("12", 16));
			Assert.assertEquals("12348000000000000000000000000000", GaiaUtils.oneAndZeroesPadding("1234", 16));
			Assert.assertEquals("12345680000000000000000000000000", GaiaUtils.oneAndZeroesPadding("123456", 16));
			Assert.assertEquals("12345678800000000000000000000000", GaiaUtils.oneAndZeroesPadding("12345678", 16));
			Assert.assertEquals("12345678908000000000000000000000", GaiaUtils.oneAndZeroesPadding("1234567890", 16));
			Assert.assertEquals("12345678901280000000000000000000", GaiaUtils.oneAndZeroesPadding("123456789012", 16));
			Assert.assertEquals("12345678901234800000000000000000", GaiaUtils.oneAndZeroesPadding("12345678901234", 16));
			Assert.assertEquals("12345678901234568000000000000000", GaiaUtils.oneAndZeroesPadding("1234567890123456", 16));
			Assert.assertEquals("12345678901234567880000000000000", GaiaUtils.oneAndZeroesPadding("123456789012345678", 16));
			Assert.assertEquals("12345678901234567890800000000000", GaiaUtils.oneAndZeroesPadding("12345678901234567890", 16));
			Assert.assertEquals("12345678901234567890128000000000", GaiaUtils.oneAndZeroesPadding("1234567890123456789012", 16));
			Assert.assertEquals("12345678901234567890123480000000", GaiaUtils.oneAndZeroesPadding("123456789012345678901234", 16));
			Assert.assertEquals("12345678901234567890123456800000", GaiaUtils.oneAndZeroesPadding("12345678901234567890123456", 16));
			Assert.assertEquals("12345678901234567890123456788000", GaiaUtils.oneAndZeroesPadding("1234567890123456789012345678", 16));
			Assert.assertEquals("12345678901234567890123456789080", GaiaUtils.oneAndZeroesPadding("123456789012345678901234567890", 16));
			Assert.assertEquals("1234567890123456789012345678901280000000000000000000000000000000", GaiaUtils.oneAndZeroesPadding("12345678901234567890123456789012", 16));

			Assert.assertEquals("1234567890123456789012345678901280", GaiaUtils.oneAndZeroesPadding("12345678901234567890123456789012", 1));
			Assert.assertEquals("123456789012345678901234567890128000", GaiaUtils.oneAndZeroesPadding("12345678901234567890123456789012", 3));
			Assert.assertEquals("1234567890123456789012345678901280000000", GaiaUtils.oneAndZeroesPadding("12345678901234567890123456789012", 5));
			Assert.assertEquals("1234567890123456789012345678901280000000", GaiaUtils.oneAndZeroesPadding("12345678901234567890123456789012", 20));

			Assert.assertEquals("111111111122222222223333333333444444444455555580", GaiaUtils.oneAndZeroesPadding("1111111111222222222233333333334444444444555555", 1));
			Assert.assertEquals("111111111122222222223333333333444444444455555580", GaiaUtils.oneAndZeroesPadding("1111111111222222222233333333334444444444555555", 2));
			Assert.assertEquals("111111111122222222223333333333444444444455555580", GaiaUtils.oneAndZeroesPadding("1111111111222222222233333333334444444444555555", 3));
			Assert.assertEquals("111111111122222222223333333333444444444455555580", GaiaUtils.oneAndZeroesPadding("1111111111222222222233333333334444444444555555", 4));
			Assert.assertEquals("111111111122222222223333333333444444444455555580", GaiaUtils.oneAndZeroesPadding("1111111111222222222233333333334444444444555555", 6));
			Assert.assertEquals("111111111122222222223333333333444444444455555580", GaiaUtils.oneAndZeroesPadding("1111111111222222222233333333334444444444555555", 8));
			Assert.assertEquals("111111111122222222223333333333444444444455555580", GaiaUtils.oneAndZeroesPadding("1111111111222222222233333333334444444444555555", 12));
		}
		catch ( GaiaException e )
		{
			e.printStackTrace();
			Assert.assertFalse(true);
		}
	}





	@Test
	public void test0013_oneAndZeroesPadding_AbnormalTest()
	{
		try
		{
			GaiaUtils.oneAndZeroesPadding(null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.oneAndZeroesPadding(null, 8);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.oneAndZeroesPadding(null, 16);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.oneAndZeroesPadding("", 16);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is empty String.", e.getMessage());
		}

		try
		{
			GaiaUtils.oneAndZeroesPadding("0", 16);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string length[1] is not even.", e.getMessage());
		}

		try
		{
			GaiaUtils.oneAndZeroesPadding("012345678", 16);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("args[0] is invalid. string length[9] is not even.", e.getMessage());
		}

		try
		{
			GaiaUtils.oneAndZeroesPadding("0123456789", -1);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("blockSize[-1] is less than 1.", e.getMessage());
		}

		try
		{
			GaiaUtils.oneAndZeroesPadding("0123456789", 0);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("blockSize[0] is less than 1.", e.getMessage());
		}
	}





	@Test
	public void test0014_checkLength_NormalTest()
	{
		try
		{
			GaiaUtils.checkLength("1", 0, 2);
			GaiaUtils.checkLength("1", 1, 2);
			GaiaUtils.checkLength("1", 0, 1);
			GaiaUtils.checkLength("1", 1, 1);
			GaiaUtils.checkLength("12", 1, 3);
			GaiaUtils.checkLength("12", 2, 3);
			GaiaUtils.checkLength("12", 1, 2);
			GaiaUtils.checkLength("12", 2, 2);
			GaiaUtils.checkLength("1234", 3, 5);
			GaiaUtils.checkLength("123456789", 0, 20);
			GaiaUtils.checkLength("12345678901234567890", 20, 30);
			GaiaUtils.checkLength("123456789012345678901234567890", 20, 30);
			GaiaUtils.checkLength("123456789012345678901234567890", 30, 30);
		}
		catch ( GaiaException e )
		{
			e.printStackTrace();
			Assert.assertFalse(true);
		}
	}





	@Test
	public void test0015_checkLength_AbnormalTest()
	{
		try
		{
			GaiaUtils.checkLength(null, 0, 2);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkLength("", 0, 2);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0] is empty String.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkLength("1234", 2, 3);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("data length[4] is not between 2 and 3.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkLength("1234", 5, 6);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("data length[4] is not between 5 and 6.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkLength("1234", 5, 3);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("data length[4] is not between 5 and 3.", e.getMessage());
		}

		try
		{
			GaiaUtils.checkLength("1234", -9, 3);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("data length[4] is not between -9 and 3.", e.getMessage());
		}
	}





	@Test
	public void test0016_concateString_NomalTest()
	{
		try
		{
			Assert.assertEquals("01", GaiaUtils.concateString("0", "1"));
			Assert.assertEquals("1", GaiaUtils.concateString("", "1"));
			Assert.assertEquals("0", GaiaUtils.concateString("0", ""));
			Assert.assertEquals("", GaiaUtils.concateString("", ""));
			Assert.assertEquals("", GaiaUtils.concateString("", "", ""));
			Assert.assertEquals("012", GaiaUtils.concateString("012", "", ""));
			Assert.assertEquals("012", GaiaUtils.concateString("01", "2", ""));
			Assert.assertEquals("012", GaiaUtils.concateString("01", "", "2"));
			Assert.assertEquals("012", GaiaUtils.concateString("0", "12", ""));
			Assert.assertEquals("012", GaiaUtils.concateString("0", "", "12"));
			Assert.assertEquals("012", GaiaUtils.concateString("0", "1", "2"));
			Assert.assertEquals("012", GaiaUtils.concateString("", "012", ""));
			Assert.assertEquals("012", GaiaUtils.concateString("", "01", "2"));
			Assert.assertEquals("012", GaiaUtils.concateString("", "0", "12"));
			Assert.assertEquals("012", GaiaUtils.concateString("", "", "012"));
			Assert.assertEquals("01234567890123456789", GaiaUtils.concateString("0", "12", "345", "6789", "", "0123456789"));
		}
		catch ( GaiaException e )
		{
			e.printStackTrace();
			Assert.assertFalse(true);
		}
	}





	@Test
	public void test0017_concateString_AbnomalTest()
	{
		try
		{
			GaiaUtils.concateString(null, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1] is null.", e.getMessage());
		}

		try
		{
			String data = null;
			GaiaUtils.concateString(data, data);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.concateString("", null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.concateString("", null, "", null, "", null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[1,3,5] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.concateString("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[19] is null.", e.getMessage());
		}

		try
		{
			GaiaUtils.concateString(null, null, null, null, null, null, null, null, null, null);
			Assert.assertFalse(true);
		}
		catch ( GaiaException e )
		{
			Assert.assertEquals("Target objects[0,1,2,3,4,5,6,7,8,9] is null.", e.getMessage());
		}
	}
}
