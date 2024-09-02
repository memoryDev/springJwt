package dev.momory.springjwt.service;

import dev.momory.springjwt.dto.CustomUserDetails;
import dev.momory.springjwt.entity.UserEntity;
import dev.momory.springjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * UserDetailService 클래스는 Spring Security의 사용자 인증을 위한 사용자 정보를 로드하는 서비스
 * Spring Security 의 UserDetailService 인터페이스를 구한하여 사용자 이름을 기반으로 사용자 정보를 가져옵니다.
 */

@Service
@Slf4j
@RequiredArgsConstructor
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UserRepository userRepository;

    /**
     * loadUserByUsername 메서드는 주어진 사용자 이름(username)에 해당하는 사용자 정보를 로드합니다.
     * @param username 사용자 이름(로그인Id)
     * @return UserDetails 객체(사용자 정보가 포함된 객체)
     * @throws UsernameNotFoundException 사용자를 찾을 수 없는 경우 예외를 던집니다.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 데이터베이스에서 주어진 사용자 이름에 해당하는 사용자 엔티티를 조회합니다.
        UserEntity userEntity = userRepository.findByUsername(username);

        // 사용자가 존재할 경우 CustomUserDetails 객체를 생성하여 반환합니다.
        if (userEntity != null) {
            return new CustomUserDetails (userEntity); // 사용자 정보를 담은 UserDetails 구현체를 반환
        }

        return null;
    }
}
