package com.keysofpeace.app.backend;

public class CryptoException extends Exception {
	private static final long serialVersionUID = 1L;
	
	public String message;

	public CryptoException(String message) {
		this.message = message;
	}
}
