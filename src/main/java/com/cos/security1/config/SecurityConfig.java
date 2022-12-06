package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

// 1. 코드받기(인증O) -> 2. 엑세스토큰(권한) -> 3. 사용자프로필 정보를 가져옴 -> 4. 그 정보를 토대로 회원가입을 자동으로 진행시킴
// 4-2(이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> (집주소), 백화점몰 -> (vip등급, 일반등급) => 추가정보 필요하면 그 페이지로 이동시켜서 받아내는 페이지 생성

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize 어노테이션 활성화, postAuthorize 어노테이션 활성화
public class SecurityConfig {

    private final PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm") // 로그인 완료된 뒤의 후처리 필요. Tip. 코드X (엑세스토큰+사용자 프로필 정보O)
                .userInfoEndpoint()
                .userService(principalOauth2UserService);

        return http.build();
    }
}
