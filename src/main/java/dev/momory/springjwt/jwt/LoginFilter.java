package dev.momory.springjwt.jwt;

import dev.momory.springjwt.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

/**
 * LoginFilter 클래스는 사요요자의 로그인 요청을 처리하고
 * 인증이 성공적으로 완료된 후 JWT 토큰을 생성하여 응답에 추가함
 */
@RequiredArgsConstructor
@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    /**
     * 사용자의 로그인 요청을 처리합니다.
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @return Authentication 객체
     * @throws AuthenticationException 인증 실패 시 예외
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // 요청에서 사용자이름, 비밀번호 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        log.info("username = {}", username);
        log.info("password = {}", password);

        // 사용자 이름과 비밀번호를 포함한 인증 토큰 생성
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);

        // AuthenticationManager를 통해 인증 시도
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }


    /**
     * 인증이 성공적으로 완료된 후 호출됨
     * JWT 토큰을 생성하여 응답 헤더에 추가합니다.
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param chain 필터 체인
     * @param authentications 인증 정보
     * @throws IOException 입출력 예외
     * @throws ServletException 서블릿 예외
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentications) throws IOException, ServletException {
        log.info("login succeess");

        // 사용자 이름 추출
        String username = authentications.getName();

        // 사용자 권한 추출
        Collection<? extends GrantedAuthority> authorities = authentications.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        // JWT 토큰 생성
        String access = jwtUtil.createJwt("access", username, role, 600000L);
        String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        // 응답 설정
        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpServletResponse.SC_OK);


    }

    /**
     * 인증이 실패한 경우 호출됨
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param failed 인증 실패 예외
     * @throws IOException 입출력 예외
     * @throws ServletException 서블릿 예외
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        log.info("login faild ");

        // 응답코드 401 설정
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    /**
     * 쿠키 생성
     * @param key 쿠키 이름
     * @param val 쿠키 값
     * @return 생성된 쿠키
     */
    private Cookie createCookie(String key, String val) {
        Cookie cookie = new Cookie(key, val);
        cookie.setMaxAge(24*60*60);
//        cookie.setSecure(true);
//        cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}
