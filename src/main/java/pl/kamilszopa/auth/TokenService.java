package pl.kamilszopa.auth;

import retrofit2.Call;
import retrofit2.http.Field;
import retrofit2.http.FormUrlEncoded;
import retrofit2.http.Headers;
import retrofit2.http.POST;
import retrofit2.http.Path;

public interface TokenService {
	
	@FormUrlEncoded
	@Headers({
        "Authorization: Basic NmQxZDI3YzgtZGY5OS00ZjM3LTkzZGQtMGJlMWVjYmE5OTllOm81cUlmQlJ1U1VLWDhnVWtHaEJFT1J2dEtjb0c3V0tkaHc0MkZzS0wxUTVXd3ZnTHhNQThWYnhPSHhEdkk1eWY="
    })
	@POST("/auth/oauth/token")
	Call<TokenResponse> getAccessTokenFromAuthCode(
		@Field("grant_type") String grantType,
		@Field("code") String code,
		@Field("api-key") String apiKey,
		@Field("redirect_uri") String redirectUrl
	);
	
	@FormUrlEncoded
	@POST("/{tenantid}/oauth2/v2.0/token")
	Call<TokenResponse> getAccessTokenFromRefreshToken(
		@Path("tenantid") String tenantId,
		@Field("client_id") String clientId,
		@Field("client_secret") String clientSecret,
		@Field("grant_type") String grantType,
		@Field("refresh_token") String code,
		@Field("redirect_uri") String redirectUrl
	);
}
