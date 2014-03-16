package com.keysofpeace.app.backend;

import java.io.IOException;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URISyntaxException;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

public class API {
	final static String URL = "https://keysofpeace.com/api/v1/";

	private static API instance;

	CookieManager cookieManager = new CookieManager();

	Crypto crypto = Crypto.getInstance();

	String csrfToken;

	public static API getInstance() {
		if (null == API.instance) {
			API.instance = new API();
		}
		return API.instance;
	}

	API() {
		CookieHandler.setDefault(cookieManager);
	}

	public void setEmail(String email) throws APIException {
		request("GET", "user");
	}

	public Object authorize(String email, String password) {
		/*byte[] masterSalt;
		byte[] oneTimeSalt;
		/*
		 * byte[] hash = crypto.hash(crypto.hash(password, masterSalt),
		 * oneTimeSalt); byte[] dataSalt; String dataString = ""; try { String
		 * json = crypto.decrypt(dataString, dataSalt); } catch (CryptoException
		 * e) { // TODO Auto-generated catch block e.printStackTrace(); }
		 */
		return null;
	}

	public void logout() {

	}

	Object request(String method, String resource) throws APIException {
		java.net.URL url;
		try {
			url = new java.net.URL(API.URL + resource);
		} catch (MalformedURLException e) {
			throw new APIException("MalformedURLException during requesting.");
		}

		HttpsURLConnection connection;
		try {
			connection = (HttpsURLConnection) url.openConnection();
		} catch (IOException e) {
			throw new APIException("IOException during opening connection.");
		}

		if (!"GET".equals(method)) {
			try {
				connection.setRequestMethod(method);
			} catch (ProtocolException e) {
				throw new APIException("ProtocolException during setting request method.");
			}
			if (null == csrfToken) {
				List<HttpCookie> cookies;
				try {
					cookies = cookieManager.getCookieStore().get(url.toURI());
				} catch (URISyntaxException e) {
					throw new APIException("URISyntaxException during getting CSRF token cookie.");
				}
				for (HttpCookie cookie : cookies) {
					if ("csrftoken".equals(cookie.getName())) {
						csrfToken = cookie.getValue();
						break;
					}
				}
				if (null == csrfToken) {
					throw new APIException("CSRF token cookie isn't ready.");
				}
			}
			connection.setRequestProperty("X-CSRFToken", csrfToken);
		}

		String response;
		try {
			connection.getResponseCode();
			response = connection.getResponseMessage();
		} catch (IOException e) {
			throw new APIException("IOException during response retrieval.");
		} finally {
			connection.disconnect();
		}
		return response;
	}
}
