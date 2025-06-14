package com.springboot.oauthjwt.oauth2;

import com.springboot.oauthjwt.dto.MyOAuth2UserDetails;
import com.springboot.oauthjwt.jwt.JwtTokenProvider;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Iterator;


@Component
public class AuthCallbackHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;

    public AuthCallbackHandler(JwtTokenProvider jwtTokenProvider) {

        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException, java.io.IOException {

        String token = generateToken(authentication);
        Cookie authCookie = generateCookie(token);

        response.addCookie(authCookie);
        response.sendRedirect("http://localhost:3000/");
    }

    private String generateToken(Authentication authentication) {
        MyOAuth2UserDetails user = (MyOAuth2UserDetails) authentication.getPrincipal();
        String username = user.getUsername();
        String role = authentication.getAuthorities().stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .orElse("ROLE_USER");

        return jwtTokenProvider.issueToken(username, role, 60 * 60 * 60L);
    }

    private Cookie generateCookie(String token) {
        Cookie cookie = new Cookie("Authorization", token);
        cookie.setMaxAge(60 * 60 * 60);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        return cookie;
    }
}


