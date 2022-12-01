package com.cos.security1.repository;

import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

// CRUD 함수를 JpaRepository 가 들고 있음.
// @Repository 어노테이션 생략 가능. 이유는 JpaRepository 를 상속해서.
public interface UserRepository extends JpaRepository<User, Integer> {

    // select * from user where username = ?
    User findByUsername(String username); // Jpa 쿼리 메서드
}
