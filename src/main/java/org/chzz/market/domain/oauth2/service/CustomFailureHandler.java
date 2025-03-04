package org.chzz.market.domain.oauth2.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.chzz.market.common.filter.HttpCookieOAuth2AuthorizationRequestRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

@Slf4j
@RequiredArgsConstructor
@Configuration
public class CustomFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    private static final String REDIRECT_URL_FAILURE = "/?status=failure";

    @Value("${client.url}")
    private String clientUrl;
    private final HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        authorizationRequestRepository.removeAuthorizationRequestCookies(response);
        log.error("Social login failure - User-Agent: {}, Error: {}", request.getHeader("User-Agent"),
                exception.getMessage());
        response.sendRedirect(clientUrl + REDIRECT_URL_FAILURE);
    }
}
