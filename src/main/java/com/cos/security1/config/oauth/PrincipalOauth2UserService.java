package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.auth.provider.FacebookUserInfo;
import com.cos.security1.config.auth.provider.GoogleUserInfo;
import com.cos.security1.config.auth.provider.NaverUserInfo;
import com.cos.security1.config.auth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("getClientRegistration: {}", userRequest.getClientRegistration()); // registrationId 로 어떤 Oauth 인지
        log.info("getAccessToken: {}", userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("getAttributes: {}", oAuth2User.getAttributes()); // 회원프로필(loadUser 함수)

        OAuth2UserInfo oAuth2UserInfo = null;

        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            log.info("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            log.info("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            log.info("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
        } else {
            log.info("우리는 구글과 페이스북만 지원해요");
        }
        
        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if (userEntity == null) {
            // 확인을 위해 로그 찍기
            log.info("Oauth 로그인이 최초입니다.");
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        } else {
            // 확인을 위해 로그 찍기
            log.info("로그인을 이미 한 적이 있습니다. 당신은 자동회원가입이 도어 있습니다.");
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
