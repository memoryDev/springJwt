package dev.momory.springjwt.dto;

import dev.momory.springjwt.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

/**
 * CustomUserDetails 클래는 Spring Security의 UserDetails 인터페이스를 구현하여
 * 사용자 정보를 커스터마이징하여 제공
 * 사용자 엔티티(UserEntity)를 기반으로 사용자 이름, 비밀번호, 권한 등을 반환
 */
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetails implements UserDetails {

    private final UserEntity userEntity;

    /**
     * 사용자의 권한 정보를 반환
     * @return GrantedAuthority의 컬렉션으로, 사용자의 권한 목록을 반환
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return userEntity.getRole(); // 사용자의 역할 반환
            }
        });

        return collection;
    }

    /**
     * 사용자의 비밀번호를 반환합니다.
     * @return 사용자 엔티티에 젖아된 암호화된 비밀번호
     */
    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    /**
     * 사용자의 이름(아이디)을 반환
     * @return 사용자 엔티티에 저장된 사용자 이름
     */
    @Override
    public String getUsername() {
        return userEntity.getUsername();
    }

    /**
     * 사용자의 계정이 만료되지 않았는지 반환
     * @return
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 사용자의 계정이 잠기지 않았는지를 반환
     * @return
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 사용자의 자격 증명이 만료되지 않았는지를 반환
     * @return
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 사용자의 계정이 활성화되어 있는지를 반환
     * @return
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
