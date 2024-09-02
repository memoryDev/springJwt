package dev.momory.springjwt.config;

import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * CorsMvcConfig 클래스는 Spring MVC의 전역 CORS 설정을 정의합니다.
 * WebMvcConfigurer 인터페이스를 구현하여 CORS 관련 설정을 커스터마이징합니다.
 */
public class CorsMvcConfig implements WebMvcConfigurer {

    /**
     * addCorsMappings 메서드는 CORS 매핑을 추가합니다.
     * 이 메서드를 통해 특정 경로에 대한 CORS 허용 정책을 설정할 수 있습니다.
     * @param registry CORS 설정을 등록할 수 있는 레지스트리 객체
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // 모든 경로에 대해 CORS를 허용합니다.ㄴ
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:5173");
    }
}
