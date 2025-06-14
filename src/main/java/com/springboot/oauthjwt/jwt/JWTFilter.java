package com.springboot.oauthjwt.jwt;

import com.springboot.oauthjwt.dto.MyOAuth2UserDetails;
import com.springboot.oauthjwt.dto.UserDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    public JWTFilter(JwtTokenProvider jwtTokenProvider) {

        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException, ServletException, IOException {


        String authorization = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {

            System.out.println(cookie.getName());
            if (cookie.getName().equals("Authorization")) {

                authorization = cookie.getValue();
            }
        }

        if (authorization == null) {

            System.out.println("token null");
            filterChain.doFilter(request, response);


            return;
        }


        String token = authorization;


        if (jwtTokenProvider.isTokenExpired(token)) {

            System.out.println("token expired");
            filterChain.doFilter(request, response);


            return;
        }


        String username = jwtTokenProvider.extractUsername(token);
        String role = jwtTokenProvider.extractRole(token);


        UserDTO userDTO = new UserDTO();
        userDTO.setUsername(username);
        userDTO.setRole(role);


        MyOAuth2UserDetails myOAuth2UserDetails = new MyOAuth2UserDetails(userDTO);


        Authentication authToken = new UsernamePasswordAuthenticationToken(myOAuth2UserDetails, null, myOAuth2UserDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}