package com.keysofpeace.app.backend;

public class APIException extends Exception {
	private static final long serialVersionUID = 1L;

	public String message;

	public APIException(String message) {
		this.message = message;
	}
}
