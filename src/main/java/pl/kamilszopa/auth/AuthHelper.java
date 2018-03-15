package pl.kamilszopa.auth;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Calendar;
import java.util.Properties;
import java.util.UUID;

import javax.ws.rs.core.UriBuilder;

import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

public class AuthHelper {
	private static final String authority = "https://login.microsoftonline.com";
	private static final String authorizeUrl = authority + "/common/oauth2/v2.0/authorize";
	
	private static String clientId = null;
	private static String apiKey = null;
	private static String redirectUri = null;
	
	private static String getAppId() {
		if (clientId == null) {
			try {
				loadConfig();
			} catch (Exception e) {
				return null;
			}
		}
		return clientId;
	}
	
	private static String getAppPassword() {
		if (apiKey == null) {
			try {
				loadConfig();
			} catch (Exception e) {
				return null;
			}
		}
		return apiKey;
	}
	
	private static String getRedirectUrl() {
		if (redirectUri == null) {
			try {
				loadConfig();
			} catch (Exception e) {
				return null;
			}
		}
		return redirectUri;
	}
	
	private static void loadConfig() throws IOException {
		String authConfigFile = "auth.properties";
		InputStream authConfigStream = AuthHelper.class.getClassLoader().getResourceAsStream(authConfigFile);
		
		if (authConfigStream != null) {
			Properties authProps = new Properties();
			try {
				authProps.load(authConfigStream);
				clientId = authProps.getProperty("clientId");
				apiKey = authProps.getProperty("apiKey");
				redirectUri = authProps.getProperty("redirectUri");
			} finally {
				authConfigStream.close();
			}
		}
		else {
			throw new FileNotFoundException("Property file '" + authConfigFile + "' not found in the classpath.");
		}
	}
	
	public static String getLoginUrl(UUID state, UUID nonce) {
		
		UriBuilder urlBuilder = UriBuilder.fromPath(authorizeUrl);
		urlBuilder.queryParam("client_id", getAppId());
		urlBuilder.queryParam("redirect_uri", getRedirectUrl());
		urlBuilder.queryParam("response_type", "code id_token");
		urlBuilder.queryParam("state", state);
		urlBuilder.queryParam("nonce", nonce);
		urlBuilder.queryParam("response_mode", "form_post");
		
		return urlBuilder.toTemplate();
	}
	
	public static TokenResponse getTokenFromAuthCode(String authCode, String tenantId) {
		// Create a logging interceptor to log request and responses
		HttpLoggingInterceptor interceptor = new HttpLoggingInterceptor();
		interceptor.setLevel(HttpLoggingInterceptor.Level.BODY);
		
		OkHttpClient client = new OkHttpClient.Builder()
				.addInterceptor(interceptor).build();
		
		// Create and configure the Retrofit object
		Retrofit retrofit = new Retrofit.Builder()
				.baseUrl(authority)
				.client(client)
				.addConverterFactory(JacksonConverterFactory.create())
				.build();
		
		// Generate the token service
		TokenService tokenService = retrofit.create(TokenService.class);
		
		try {
			return tokenService.getAccessTokenFromAuthCode(tenantId, getAppId(), getAppPassword(), 
					"authorization_code", authCode, getRedirectUrl()).execute().body();
		} catch (IOException e) {
			TokenResponse error = new TokenResponse();
			error.setError("IOException");
			error.setErrorDescription(e.getMessage());
			return error;
		}
	}
	 
	public static TokenResponse ensureTokens(TokenResponse tokens, String tenantId) {
		// Are tokens still valid?
		Calendar now = Calendar.getInstance();
		if (now.getTime().after(tokens.getExpirationTime())) {
			// Still valid, return them as-is
			return tokens;
		}
		else {
			// Expired, refresh the tokens
			// Create a logging interceptor to log request and responses
			HttpLoggingInterceptor interceptor = new HttpLoggingInterceptor();
			interceptor.setLevel(HttpLoggingInterceptor.Level.BODY);
			
			OkHttpClient client = new OkHttpClient.Builder()
					.addInterceptor(interceptor).build();
			
			// Create and configure the Retrofit object
			Retrofit retrofit = new Retrofit.Builder()
					.baseUrl(authority)
					.client(client)
					.addConverterFactory(JacksonConverterFactory.create())
					.build();
			
			// Generate the token service
			TokenService tokenService = retrofit.create(TokenService.class);
			
			try {
				return tokenService.getAccessTokenFromRefreshToken(tenantId, getAppId(), getAppPassword(), 
						"refresh_token", tokens.getRefreshToken(), getRedirectUrl()).execute().body();
			} catch (IOException e) {
				TokenResponse error = new TokenResponse();
				error.setError("IOException");
				error.setErrorDescription(e.getMessage());
				return error;
			}
		}
	}
}
