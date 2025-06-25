package ca.yw.maplekiosk.provider;


import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import org.springframework.stereotype.Component;

import ca.yw.maplekiosk.config.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final JwtConfig jwtConfig;

    /**
     * 
     * @return
     */
    private Key getKey() {
        return Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public String createAccessToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtConfig.getAccessTokenExpirationMinutes() * 60 * 1000))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String createRefreshToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtConfig.getRefreshTokenExpirationDays() * 24 * 60 * 60 * 1000))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {

            Jwts.parserBuilder()
            .setSigningKey(getKey())
            .build()
            .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
        .setSigningKey(getKey()).build()
        .parseClaimsJws(token).getBody();
    }
}
