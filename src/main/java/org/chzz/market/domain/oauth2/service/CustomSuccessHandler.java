package org.chzz.market.domain.oauth2.service;

import static org.chzz.market.common.util.CookieUtil.createTokenCookie;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.chzz.market.common.filter.HttpCookieOAuth2AuthorizationRequestRepository;
import org.chzz.market.domain.token.entity.TokenType;
import org.chzz.market.domain.token.service.TokenService;
import org.chzz.market.domain.user.dto.CustomUserDetails;
import org.chzz.market.domain.user.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

@Slf4j
@RequiredArgsConstructor
@Configuration
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private static final String REDIRECT_URL_SUCCESS = "/?status=success";
    private static final String REDIRECT_URL_ADDITIONAL_INFO = "/signup";

    @Value("${client.url}")
    private String clientUrl;


    private final TokenService tokenService;
    private final HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        authorizationRequestRepository.removeAuthorizationRequestCookies(response);
        User user = ((CustomUserDetails) authentication.getPrincipal()).getUser();
        if (user.isTempUser()) {
            // 임시 토큰 발급
            String tempToken = tokenService.createTempToken(user);
            createTokenCookie(response, tempToken, TokenType.TEMP);

            // 추가 입력 페이지로 리다이렉트
            response.sendRedirect(clientUrl + REDIRECT_URL_ADDITIONAL_INFO);
            log.info("임시 유저 인증 성공: user ID: {}", user.getId());
        } else {
            // 리프레쉬 토큰 발급
            String refresh = tokenService.createRefreshToken(user);
            createTokenCookie(response, refresh, TokenType.REFRESH);
            response.sendRedirect(clientUrl + REDIRECT_URL_SUCCESS);
            log.info("소셜로그인 성공 user ID: {}", user.getId());
        }
    }
}
