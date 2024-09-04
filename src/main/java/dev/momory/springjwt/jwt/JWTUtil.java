package dev.momory.springjwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * JWTUtil 클래스는 JWT 토큰을 생성, 파싱 및 검증하는 데 사용되는 유틸리티 클래스
 */
@Component
public class JWTUtil {

    // 대칭 키 암호화를 위한 SecretKey 객체로, JWT 서명 및 검증에 사용됩니다.
    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.security}") String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    /**
     * JWT 토큰에서 사용자이름(username)을 추출합니다.
     * @param token 사용자 인증에 사용되는 JWT토큰
     * @return 토큰에서 추출한 사용자 이름
     */
    public String getUsername(String token) {
        return Jwts.parser()// JWT 파서 생성
                .verifyWith(secretKey)// 시크릿 키로 서명을 검증
                .build() // 파서 빌드
                .parseSignedClaims(token) // 서명된 클레임을 포함하는 JWT를 파싱
                .getPayload() // 토큰에서 페이로드를 조회
                .get("username", String.class); // 페이로드에서 "username"클레임 조회
    }

    /**
     * JWT 토큰에서 사용자의 권한(role)를 추출
     * @param token 사용자 인증에 사용되는 JWT토큰
     * @return 토큰에서 추출한 사용자 권한
     */
    public String getRole(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role", String.class);
    }

    /**
     * JWT 토큰의 만료 여부를 확인
     * @param token
     * @return 토큰이 만료되었으면 true, 그렇지 않으면 false를 반환
     */
    public Boolean isExpired(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration()// 토큰의 만료 시간을 가져옴
                .before(new Date()); // 현재 시간과 비교하여 만료 여부 확인
    }

    /**
     * JWT 토큰에서 토큰 타입 추출
     * @param token 사용자 인증에 사용되는 JWT토큰
     * @return 토큰에서 추출한 토큰 타입
     */
    public String getCategory(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("category", String.class);
    }

    /**
     * 새로운 JWT 토큰을 생성
     * @param access 토큰 타입(access/refresh)
     * @param username 사용자이름
     * @param role 사용자 권한
     * @param expiredMs 토큰의 만료 시간
     * @return 생성된 JWT 토큰 문자열
     */
    public String createJwt(String access, String username, String role, Long expiredMs) {
        return Jwts.builder() //JWT 생성 빌더
                .claim("category", access) // 클레임추가
                .claim("username", username) // 클레임추가
                .claim("role", role) // 클레임추가
                .issuedAt(new Date(System.currentTimeMillis())) // 현재 시간을 발행 시간으로 설정
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // 만료 시간을 설정
                .signWith(secretKey) // 시크릿 키로 서명
                .compact(); // JWT 문자열로 조회
    }
}
