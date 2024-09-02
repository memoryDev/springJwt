package dev.momory.springjwt.repository;

import dev.momory.springjwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * userRepository 인터페이스는 사요요자 엔티티에 대한 DB 작업 수행
 */
public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    /**
     * 주어진 사용자 이름이 DB에 존재하는지 확인
     * @param username 사용자 이름
     * @return 사용자 이름이 존재하면 true, 그렇지 않으면 false
     */
    Boolean existsByUsername(String username);

    /**
     * 주어진 사용자 이름으로 사용자 엔티티 조회
     * @param username 사용자 이름
     * @return 사용자 이름과 일치하는 사용자 엔티티, 없으면 null
     */
    UserEntity findByUsername(String username);
}
