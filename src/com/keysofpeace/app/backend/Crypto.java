package com.keysofpeace.app.backend;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.engines.RijndaelEngine;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.util.encoders.Base64;

public class Crypto {
	final static String[] ALPHABETS_BITS_KEYS = { "Digits", "latin", "LATIN", "Punctuation" };

	final static String[] ALPHABETS_BITS_VALUES = { "23456789", "abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "~!@#$;%^:&?*()-+=[]{}\\|/<>,." };

	final static Charset CHARSET = Charset.forName("UTF-8");

	final static int HASH_BITS_COUNT = 256;

	final static int HASH_ITERATIONS_COUNT = 1000;

	final static int SALT_BITS_COUNT = 256;

	private static Crypto instance;

	PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new RijndaelEngine(HASH_BITS_COUNT)));

	SecureRandom random = new SecureRandom();

	public byte[] fromString(String string) {
		return Base64.decode(string);
	}

	public static Crypto getInstance() {
		if (null == Crypto.instance) {
			Crypto.instance = new Crypto();
		}
		return Crypto.instance;
	}

	public String encrypt(String string, byte[] key) throws CryptoException {
		byte[] iv = getSalt();
		CipherParameters parameters = new ParametersWithIV(new KeyParameter(key), iv);
		cipher.reset();
		cipher.init(true, parameters);
		byte[] bytes = string.getBytes(Crypto.CHARSET);
		byte[] ciphertext = new byte[cipher.getOutputSize(bytes.length)];
		int i = cipher.processBytes(bytes, 0, bytes.length, ciphertext, 0);
		try {
			i += cipher.doFinal(ciphertext, i);
		} catch (DataLengthException e) {
			throw new CryptoException("DataLengthException during encryption");
		} catch (IllegalStateException e) {
			throw new CryptoException("IllegalStateException during encryption");
		} catch (InvalidCipherTextException e) {
			throw new CryptoException("InvalidCipherTextException during encryption");
		}
		if (ciphertext.length != i) {
			throw new CryptoException("Unexpected behaviour during encryption: getOutputSize value incorrect");
		}
		byte[] data = new byte[iv.length + ciphertext.length];
		System.arraycopy(iv, 0, data, 0, iv.length);
		System.arraycopy(ciphertext, 0, data, iv.length, ciphertext.length);
		return toString(data);
	}

	public String decrypt(String dataString, byte[] key) throws CryptoException {
		byte[] data = fromString(dataString);
		byte[] iv = new byte[Crypto.SALT_BITS_COUNT / 8];
		System.arraycopy(data, 0, iv, 0, iv.length);
		CipherParameters parameters = new ParametersWithIV(new KeyParameter(key), iv);
		cipher.reset();
		cipher.init(false, parameters);
		byte[] temp = new byte[cipher.getOutputSize(data.length - iv.length)];
		int length = cipher.processBytes(data, iv.length, data.length - iv.length, temp, 0);
		try {
			length += cipher.doFinal(temp, length);
		} catch (DataLengthException e) {
			throw new CryptoException("DataLengthException during decryption");
		} catch (IllegalStateException e) {
			throw new CryptoException("IllegalStateException during decryption");
		} catch (InvalidCipherTextException e) {
			throw new CryptoException("InvalidCipherTextException during decryption");
		}
		byte[] bytes = new byte[length];
		System.arraycopy(temp, 0, bytes, 0, length);
		return new String(bytes, Crypto.CHARSET);
	}

	public byte[] getSalt() {
		byte[] salt = new byte[Crypto.SALT_BITS_COUNT / 8];
		random.nextBytes(salt);
		return salt;
	}

	public byte[] hash(String string, byte[] salt) {
		return hash(string.getBytes(), salt);
	}

	public byte[] hash(byte[] bytes, byte[] salt) {
		PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
		generator.init(bytes, salt, Crypto.HASH_ITERATIONS_COUNT);
		KeyParameter key = (KeyParameter) generator.generateDerivedMacParameters(Crypto.HASH_BITS_COUNT);
		return key.getKey();
	}

	public String toString(byte[] bytes) {
		return Base64.toBase64String(bytes);
	}
}
