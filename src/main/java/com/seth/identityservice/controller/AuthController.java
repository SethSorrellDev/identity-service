package com.seth.identityservice.controller;

import com.nimbusds.jwt.JWTClaimsSet;
import com.seth.identityservice.dto.*;
import com.seth.identityservice.model.User;
import com.seth.identityservice.repository.UserRepository;
import com.seth.identityservice.security.JwtService;
import com.seth.identityservice.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    public AuthController(UserService userService, UserRepository userRepository, JwtService jwtService) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@Valid @RequestBody RegisterRequest request) {
        User user = userService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(issueTokens(user));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        User user = userService.authenticate(request.email(), request.password());
        return ResponseEntity.ok(issueTokens(user));
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        JWTClaimsSet claims = jwtService.verifyAndParse(request.refreshToken());

        String type = (String) claims.getClaim("type");
        if (!"refresh".equals(type)) {
            throw new IllegalArgumentException("Token is not a refresh token");
        }

        UUID userId = UUID.fromString(claims.getSubject());
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User no longer exists"));

        if (!user.isActive()) {
            throw new IllegalArgumentException("Account is inactive");
        }

        return ResponseEntity.ok(issueTokens(user));
    }

    private TokenResponse issueTokens(User user) {
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        return TokenResponse.of(accessToken, refreshToken, jwtService.getAccessTokenTtlSeconds());
    }
}
