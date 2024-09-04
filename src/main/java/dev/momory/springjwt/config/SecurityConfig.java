package dev.momory.springjwt.config;

import dev.momory.springjwt.jwt.JWTFilter;
import dev.momory.springjwt.jwt.JWTUtil;
import dev.momory.springjwt.jwt.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 인증 설정을 담고 있는 객체
    private AuthenticationConfiguration authenticationConfiguration;

    // JWT 토큰 생성 유틸
    private JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    /**
     * AuthenticationManager를 Bean으로 등록하여 스프링 컨텍스트에서 사용 가능하게 합니다.
     * AuthenticationManager는 사용자 인증을 관리하는 주요 인터페이스
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    /**
     * BCryptPasswordEncoder를 Bean으로 등록
     * BCryptPasswordEncoder는 비밀번호를 해싱하는데 사용하며, 보안성이 높은 알고리즘 제공
     * @return
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * SecurityFilterChain은 Bean으로 등록하여 HTTP 보안 설정을 정의
     * CORS, CSRF 보호, 인증 및 권한 부여, 세션관리 정의
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // CORS 설정 : 다른 도메인에서의 요청 허용하기위한 설정
        http.cors((corsCustomizer) -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                // CORS 정책을 정의하는 객체 생성
                CorsConfiguration configuration = new CorsConfiguration();

                // 허용할 출처 : 로컬, 개발서버
                configuration.setAllowedOrigins(Collections.singletonList("http://localhost:5173"));

                // 허용할 HTTP 메서드 설정(모든 메서드 허용)
                configuration.setAllowedMethods(Collections.singletonList("*"));

                // 인증 정보를 요청 헤더에 포함할 수 있도록 허용
                configuration.setAllowCredentials(true);

                // 클라이언트가 보낼 수 있는 헤더의 목록을 지정(모든 헤더 허용)
                configuration.setAllowedHeaders(Collections.singletonList("*"));

                // 브라우저가 CORS 결과를 캐시할 시간 설정(3600초)
                configuration.setMaxAge(3600L);

                // 클라이언트가 접근할 수 있는 응답 헤더 지정
                configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                return configuration;
            }
        }));

        // CORS 보호 기능을 비활성화
        http.csrf(csrf -> csrf.disable());

        // 기본적으로 제공되는 로그인 폼 기능 비활성화
        http.formLogin(auth -> auth.disable());

        // HTTP 기본 인증 비활성화
        http.httpBasic(auth -> auth.disable());

        // 요ㅛ청에 대한 접근 제어 규칙 정의
        http.authorizeHttpRequests(auth -> auth
                // "/", "/join", "/login" 인증 없이 접근 허용
                .requestMatchers("/", "/join", "/login").permitAll()
                .requestMatchers("/reissue").permitAll()
                // 나머지 모든 요청에 대해서는 인증을 요구합니다.
                .anyRequest().authenticated());

        // JWT 인증 필터를 LoginFilter 앞에 추가합니다.
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // 로그인 필터를 UsernamePasswordAuthenticationFilter 자리에 추가합니다.
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil)
                , UsernamePasswordAuthenticationFilter.class);

        // 세션 관리 정책을 설정합니다. 여기서는 STATELESS 모드로 설정하여 서버가 세션을 생성하거나 유지하지 않도록
        // 합니다.
        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

}
