package org.example.googlelogin_backstudy.controller;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.example.googlelogin_backstudy.config.JwtTokenProvider;
import org.example.googlelogin_backstudy.domain.User;
import org.example.googlelogin_backstudy.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class LoginController {

    @Value("${google.oauth.client-id}")
    private String clientId;

    @Value("${google.oauth.client-secret}")
    private String clientSecret;



    private final String GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
    private final String REDIRECT_URI = "http://localhost:8080/complete.html"; // 프론트와 동일하게 설정
    private static final String GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo";

    private final UserRepository userRepository;
    private final RestTemplate restTemplate;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/api/auth/google/token")
    public ResponseEntity<?> googleLogin(@RequestParam("code") String authorizationCode) {
        RestTemplate restTemplate = new RestTemplate();

        // 요청 파라미터 설정 (application/x-www-form-urlencoded 형식)
        MultiValueMap<String, String> requestParams = new LinkedMultiValueMap<>();
        requestParams.add("code", authorizationCode);
        requestParams.add("client_id", clientId);
        requestParams.add("client_secret", clientSecret);
        requestParams.add("redirect_uri", REDIRECT_URI);
        requestParams.add("grant_type", "authorization_code");

        // HTTP 요청 헤더 설정
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // HTTP 요청 본문 설정
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestParams, headers);

        // 구글 OAuth 서버에 POST 요청 보내기
        ResponseEntity<Map> response = restTemplate.exchange(
                GOOGLE_TOKEN_URL,
                HttpMethod.POST,
                request,
                Map.class
        );

        // 응답에서 access_token 추출
        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            String access_token = (String) response.getBody().get("access_token");
            return ResponseEntity.ok(Collections.singletonMap("access_token", access_token));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Failed to get access token");
        }
    }

    @PostMapping("/userinfo")
    public ResponseEntity<?> getUserInfoFromAccessToken(@RequestParam String access_token) {
        try {
            // 1. 엑세스 토큰으로 유저 정보 가져오기
            Map<String, Object> userInfo = fetchUserInfo(access_token);
            String googleId = (String) userInfo.get("sub"); // Google 고유 ID
            String email = (String) userInfo.get("email");
            String name = (String) userInfo.get("name");

            if (email == null || googleId == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Invalid access token or insufficient scope");
            }

            // 2. 유저 정보 저장 또는 업데이트
            User user = saveOrUpdateUser(googleId, email, name);

            // 3. JWT 토큰 생성 (선택적)
            String jwtToken = jwtTokenProvider.generateToken(user);

            // 4. 응답
            Map<String, String> response = new HashMap<>();
            response.put("jwt_token", jwtToken);
            response.put("email", user.getEmail());
            response.put("name", user.getName());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error processing access token: " + e.getMessage());
        }
    }

    private Map<String, Object> fetchUserInfo(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken); // Authorization: Bearer <access_token>

        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<Map> response = restTemplate.exchange(
                GOOGLE_USERINFO_URL, HttpMethod.GET, entity, Map.class);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            return response.getBody();
        }
        throw new RuntimeException("Failed to fetch user info from Google");
    }

    @Transactional
    public User saveOrUpdateUser(String id, String email, String name) {
        return userRepository.findById(id)
                .map(existingUser -> {
                    existingUser.setEmail(email);
                    existingUser.setName(name);
                    return userRepository.save(existingUser);
                })
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setUserId(id);
                    newUser.setEmail(email);
                    newUser.setName(name);
                    return userRepository.save(newUser);
                });
    }

    @GetMapping("/api/user/info")
    public ResponseEntity<?> getUserInfo(@RequestHeader("Authorization") String authHeader) {
        try {
            // "Bearer " 접두사 제거
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
            }
            String token = authHeader.substring(7);

            // 토큰 유효성 검증
            if (!jwtTokenProvider.validateToken(token)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token expired or invalid");
            }

            // JWT에서 정보 추출
            String userId = jwtTokenProvider.getUserIdFromToken(token);
            String name = jwtTokenProvider.getNameFromToken(token);
            String email = jwtTokenProvider.getEmailFromToken(token);

            // 응답 생성
            Map<String, String> response = new HashMap<>();
            response.put("userId", userId);
            response.put("name", name);
            response.put("email", email);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error processing token: " + e.getMessage());
        }
    }

}