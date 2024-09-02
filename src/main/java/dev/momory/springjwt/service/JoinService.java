package dev.momory.springjwt.service;

import dev.momory.springjwt.repository.UserRepository;
import dev.momory.springjwt.dto.JoinDTO;
import dev.momory.springjwt.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * JoinService 클래스는 사용자의 회원가입 요청을 처리하는 서비스 클래스
 */

@Service
@Slf4j
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    // 비밀번호 암호화하는 데 사용되는 객체
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * joinService 메서드는 사용자의 회원가입 요청을 처리합니다.
     * @param joinDTO 회원가입 요청 데이터를 담고 있는 DTO 객체
     */
    public void joinService(JoinDTO joinDTO) {

        // 회원가입 요청으로부터 사용자 이름, 비밀번호를 가져옵니다.
        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        // DB에 해당 사용자 이름이 이미 존재하는지 확인합니다.
        Boolean isExists = userRepository.existsByUsername(username);

        // 사용자 이름이 이미 존재할 경우, 메서드 종료
        if (isExists) {
            log.info("username 이 존재합니다.");
            return;
        }

        // 새로운 사용자 엔티티를 생성하고 사용자 정보를 설정합니다.
        UserEntity entity = new UserEntity();
        entity.setUsername(username);
        entity.setPassword(bCryptPasswordEncoder.encode(password)); // 비밀번호 암호화
        entity.setRole("ROLE_ADMIN");

        // 사용자 엔티티를 DB에 저장
        userRepository.save(entity);
    }
}
