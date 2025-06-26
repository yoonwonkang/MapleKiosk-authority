package ca.yw.maplekiosk.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ca.yw.maplekiosk.config.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class JwtTokenProviderTest {
  
  private static final String ORIGIN_SHOP_USER_NAME =  "shop01";
  private static final String ORIGIN_SHOP_ROLE = "SHOP";
  private JwtTokenProvider jwtTokenProvider;
  private static final String TEST_SECRET_KEY = "this-is-a-very-secure-and-long-secret-key-1234567890";

  @BeforeEach
  void setUp() {
      JwtConfig jwtConfig = new JwtConfig();
      jwtConfig.setSecret(TEST_SECRET_KEY);
      jwtConfig.setAccessTokenExpirationSeconds(1);
      jwtConfig.setRefreshTokenExpirationSeconds(1);
      
      jwtTokenProvider = new JwtTokenProvider(jwtConfig);
  }

  @Test
  void createAccessToken_shouldReturnWrongNameToken() {
    String wrongName = "shQp1";
    String token = jwtTokenProvider.createAccessToken(wrongName, ORIGIN_SHOP_ROLE);

    assertTrue(jwtTokenProvider.validateToken(token));
    Claims claims = jwtTokenProvider.getClaims(token);
    assertNotEquals(ORIGIN_SHOP_USER_NAME, claims.getSubject());
    assertEquals(ORIGIN_SHOP_ROLE, claims.get("role"));
  }

  @Test
  void createAccessToken_shouldReturnWrongRoleToken() {
    String wrongRole = "SHQP";
    String token = jwtTokenProvider.createAccessToken(ORIGIN_SHOP_USER_NAME, wrongRole);

    assertTrue(jwtTokenProvider.validateToken(token));
    Claims claims = jwtTokenProvider.getClaims(token);
    assertEquals(ORIGIN_SHOP_USER_NAME, claims.getSubject());
    assertNotEquals(ORIGIN_SHOP_ROLE, claims.get("role"));
  }

  @Test
void validateToken_shouldReturnFalse_whenTokenIsExpired() {
  Key key = Keys.hmacShaKeyFor(TEST_SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    String expiredToken = Jwts.builder()
      .setSubject(ORIGIN_SHOP_USER_NAME)
      .claim("role", ORIGIN_SHOP_ROLE)
      .setIssuedAt(new Date(System.currentTimeMillis() - 1000 * 60 * 60)) // 1시간 전
      .setExpiration(new Date(System.currentTimeMillis() - 1000 * 30)) // 30초 전에 만료
      .signWith(key, SignatureAlgorithm.HS256)
      .compact();
    assertFalse(jwtTokenProvider.validateToken(expiredToken));
}

  @Test
  void validateToken_shouldReturnFalse_whenSignatureIsInvalid() {
      // 잘못된 Secret Key로 토큰 생성
    String wrongSecret = "wrongSecretWrongSecretWrongSecretWrongSecret";
    Key wrongKey = Keys.hmacShaKeyFor(wrongSecret.getBytes(StandardCharsets.UTF_8));
    String invalidToken = Jwts.builder()
            .setSubject(ORIGIN_SHOP_USER_NAME)
            .claim("role", ORIGIN_SHOP_ROLE)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30)) // 30분 유효
            .signWith(wrongKey, SignatureAlgorithm.HS256)
            .compact();

    // 검증 시 false가 나와야 함
    assertFalse(jwtTokenProvider.validateToken(invalidToken));
}

  @Test
  void createAccessToken_shouldReturnValidToken() {
    String token = jwtTokenProvider.createAccessToken(ORIGIN_SHOP_USER_NAME, ORIGIN_SHOP_ROLE);
    assertTrue(jwtTokenProvider.validateToken(token));
    Claims claims = jwtTokenProvider.getClaims(token);
    assertEquals(ORIGIN_SHOP_USER_NAME, claims.getSubject());
    assertEquals(ORIGIN_SHOP_ROLE, claims.get("role"));
  }
}

