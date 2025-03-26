package org.example.googlelogin_backstudy;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;
import java.util.Map;

@RestController
public class LoginController {

    @Value("${google.oauth.client-id}")
    private String clientId;

    @Value("${google.oauth.client-secret}")
    private String clientSecret;

    private final String GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
    private final String REDIRECT_URI = "http://localhost:8080/complete.html"; // 프론트와 동일하게 설정

    @GetMapping("/api/auth/client-id")
    public ResponseEntity<String> getClientId() {
        return ResponseEntity.ok(clientId);
    }

    @PostMapping("/api/auth/google/token")
    public ResponseEntity<?> googleLogin(@RequestParam String authorizationCode) {
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
        System.out.println("error1");
        // 응답에서 access_token 추출
        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            System.out.println("error2");
            String accessToken = (String) response.getBody().get("access_token");
            System.out.println("accessToken >> " + accessToken);
            return ResponseEntity.ok(Collections.singletonMap("access_token", accessToken));
        } else {
            System.out.println("error3");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Failed to get access token");
        }
    }
}

