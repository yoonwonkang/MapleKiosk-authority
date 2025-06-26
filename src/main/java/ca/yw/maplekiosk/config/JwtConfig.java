package ca.yw.maplekiosk.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtConfig {
  private String secret;
  private long accessTokenExpirationSeconds;
  private long refreshTokenExpirationSeconds;

  public void setSecret(String secret) {
    this.secret = secret;
  }

  public long getAccessTokenExpirationSeconds() {
    return accessTokenExpirationSeconds;
  }

  public void setAccessTokenExpirationSeconds(long accessTokenExpirationSeconds) {
    this.accessTokenExpirationSeconds = accessTokenExpirationSeconds;
  }

  public long getRefreshTokenExpirationSeconds() {
    return refreshTokenExpirationSeconds;
  }

  public void setRefreshTokenExpirationSeconds(long refreshTokenExpirationSeconds) {
    this.refreshTokenExpirationSeconds = refreshTokenExpirationSeconds;
  }

  public String getSecret() {
    return secret;
  }
}
