package dev.momory.springjwt.jwt;

import dev.momory.springjwt.dto.CustomUserDetails;
import dev.momory.springjwt.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

/**
 * JWTFilter 클래스는 HTTP 요청에서 JWT 토큰을 검증하고,
 * 인증 정보를 SEcurityContext에 설정하는 필터 클래스입니다.
 * Spring Security의 OnceePerRequestFilter를 확장하여 요청당 한번만 실행됨
 */
@RequiredArgsConstructor
@Slf4j
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    /**
     * HTTP 요청을 필터링하고 JWT 토큰을 검증합니다.
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param filterChain 필터 체인
     * @throws ServletException 서블릿 예외
     * @throws IOException 입출력 예외
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 요청 헤더에서 Authorization 헤더를 가져옴
        String authorization = request.getHeader("Authorization");

        // Authorization 헤더가 없거나 "Bearer "로 시작하지 않을 경우
        if (authorization == null || !authorization.startsWith("Bearer ")) {

            log.info("token null");

            filterChain.doFilter(request, response);;
            return;
        }

        // Bearer 부분을 제거한 토큰을 추출
        String token = authorization.split(" ")[1];

        // 토큰이 만료된 경우
        if (jwtUtil.isExpired(token)) {
            log.info("token expired");
            filterChain.doFilter(request, response);
            return;
        }

        // JWT 토큰에서 사용자 이름, 권한 추출
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // UserEntity 객체 생성후 사용자 정보 설정
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword"); // 비밀번호를 인증하지않아서 임시 값 사용
        userEntity.setRole(role);

        // CustomUserDetails 객체를 생성하여 사용자 세부 정보를 설정
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // UsernamePasswordAuthenticationToken 객체를 생성하여 인증 정보를 생성
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        // SecurityContext에 인증 정보를 설정
        SecurityContextHolder.getContext().setAuthentication(authToken);

        // 필터 체인을 계속 진행
        filterChain.doFilter(request, response);
    }
}
