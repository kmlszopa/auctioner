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
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

public class AuthHelper {
	private static final String authority = "https://allegro.pl";
	private static final String authorizeUrl = authority + "/auth/oauth/authorize";
	
	private static String clientId = null;
	private static String apiKey = null;
	private static String redirectUri = null;
	private static String responseType = null;
	
	private static String getClientId() {
		if (clientId == null) {
			try {
				loadConfig();
			} catch (Exception e) {
				return null;
			}
		}
		return clientId;
	}
	
	private static String getApiKey() {
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
				responseType = authProps.getProperty("reponseType");
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
	
	private static String getResponseType() {
		if (responseType == null) {
			try {
				loadConfig();
			} catch (Exception e) {
				return null;
			}
		}
		return responseType;
	}

	
	public static String getLoginUrl() {
		
		UriBuilder urlBuilder = UriBuilder.fromPath(authorizeUrl);
		urlBuilder.queryParam("response_type", getResponseType());
		urlBuilder.queryParam("client_id", getClientId());
		urlBuilder.queryParam("api-key", getApiKey());
		urlBuilder.queryParam("redirect_uri", getRedirectUrl());
		
		return urlBuilder.toTemplate();
	}
	
	
	public static TokenResponse getTokenFromAuthCode(String authCode) {
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
			String grantType = "authorization_code";
			Response<TokenResponse> execute = tokenService.getAccessTokenFromAuthCode(grantType, authCode, getApiKey(), getRedirectUrl()).execute();
			return execute.body();
		} catch (IOException e) {
			TokenResponse error = new TokenResponse();
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
				return tokenService.getAccessTokenFromRefreshToken(tenantId, getClientId(), getApiKey(), 
						"refresh_token", tokens.getRefreshToken(), getRedirectUrl()).execute().body();
			} catch (IOException e) {
				TokenResponse error = new TokenResponse();
				return error;
			}
		}
	}
}
