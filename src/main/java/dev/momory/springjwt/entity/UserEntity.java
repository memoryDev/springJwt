package dev.momory.springjwt.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

import static jakarta.persistence.GenerationType.IDENTITY;

@Entity
@Getter
@Setter
public class UserEntity {

    @Id
    @GeneratedValue(strategy = IDENTITY)
    private int id; // 사용자 고유 식별자

    // 사용자 이름
    private String username;
    // 사용자 비밀번호
    private String password;

    // 사용자 권한
    private String role;
}
