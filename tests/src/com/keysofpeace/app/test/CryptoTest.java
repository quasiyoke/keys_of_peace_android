package com.keysofpeace.app.test;

import java.util.Arrays;

import junit.framework.TestCase;

import com.keysofpeace.app.backend.Crypto;
import com.keysofpeace.app.backend.CryptoException;

public class CryptoTest extends TestCase {
	Crypto instance;

	protected void setUp() throws Exception {
		super.setUp();
		instance = Crypto.getInstance();
		assertNotNull(instance);
	}

	public void testFromString() {
		byte[] bytes = { -36, 18, -74, 76, 114, 23, 99, -82, -7, -100, -77, -23, -74, -117, -46, -82, -116, 62, -6, 6, -84, 30, 61, 118, 114, 118, 23, 109, -93, 37, -125, 80 };
		assertTrue(Arrays.equals(bytes, instance.fromString("3BK2THIXY675nLPptovSrow++gasHj12cnYXbaMlg1A=")));
	}

	public void testEncryptAndDecrypt() throws CryptoException {
		byte[] key = { -36, 18, -74, 76, 114, 23, 99, -82, -7, -100, -77, -23, -74, -117, -46, -82, -116, 62, -6, 6, -84, 30, 61, 118, 114, 118, 23, 109, -93, 37, -125, 80 };
		String string = "MYFCrMCnTH3tHiyP7bBSKNq2XxGTjB3CVpnRYNQVsEu4U6VaNZmZQLGdMd7njCGUY7uP93XYX9G6uSdnZes2cTyPATsy6DAzpNQT";
		String ciphertext = instance.encrypt(string, key);
		assertEquals(string, instance.decrypt(ciphertext, key));
	}

	public void testGetSalt() {
		assertEquals(256 / 8, instance.getSalt().length);
	}

	public void testHashStringByteArray() {
		byte[] salt = { -36, 18, -74, 76, 114, 23, 99, -82, -7, -100, -77, -23, -74, -117, -46, -82, -116, 62, -6, 6, -84, 30, 61, 118, 114, 118, 23, 109, -93, 37, -125, 80 };
		byte[] expected = { -32, -13, -121, 97, 32, -3, -46, -109, 89, 78, 106, 82, -84, -25, 0, 79, 13, -33, 127, -12, -128, 47, -116, 1, 112, 46, -60, -11, 6, 5, 46, 78 };
		assertTrue(Arrays.equals(expected, instance.hash("MYFCrMCnTH3tHiyP7bBSKNq2XxGTjB3CVpnRYNQVsEu4U6VaNZmZQLGdMd7njCGUY7uP93XYX9G6uSdnZes2cTyPATsy6DAzpNQT", salt)));
	}

	public void testHashByteArrayByteArray() {
		byte[] bytes = { -38, -40, 31, 121, -63, 61, -10, 112, -96, -3, -88, -13, -9, -31, -64, 12, 28, 124, -6, -93, 31, -57, -105, 7, 10, -83, 87, 99, 30, 77, 31, -27 };
		byte[] salt = { -36, 18, -74, 76, 114, 23, 99, -82, -7, -100, -77, -23, -74, -117, -46, -82, -116, 62, -6, 6, -84, 30, 61, 118, 114, 118, 23, 109, -93, 37, -125, 80 };		
		byte[] expected = { 75, 101, -94, 111, -117, -38, 124, -54, 79, -38, 65, -66, -122, -122, 24, 80, -120, 14, -65, 59, 112, -53, -47, 87, -120, -87, 17, -58, -85, 84, -94, -16 };
		assertTrue(Arrays.equals(expected, instance.hash(bytes, salt)));
	}

	public void testToStringByteArray() {
		byte[] bytes = { -36, 18, -74, 76, 114, 23, 99, -82, -7, -100, -77, -23, -74, -117, -46, -82, -116, 62, -6, 6, -84, 30, 61, 118, 114, 118, 23, 109, -93, 37, -125, 80 };
		assertEquals("3BK2THIXY675nLPptovSrow++gasHj12cnYXbaMlg1A=", instance.toString(bytes));
	}

}
