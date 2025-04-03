package org.example.googlelogin_backstudy.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Data;
import org.example.googlelogin_backstudy.domain.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Configuration
@Data
public class JwtTokenProvider {
    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private Long expTime;

    public String generateToken(User user) {

//      JWT header의 값을 담을 Map을 만들어 주었습니다.
        Map<String, Object> header = new HashMap<>();

//      만들어진 Map타입을 가지고있는 header 변수에 key value 방식으로 typ(key)와
//      JWT(value)를 넣어줍니다.
        header.put("typ", "JWT");

//      현재시간을 불러오기 위해 Date 클래스 호출합니다.
        Date ext = new Date();
        ext.setTime(ext.getTime() + expTime);

//      payload를 담을 Map을 만들어 주었습니다.
        Map<String, Object> payload = new HashMap<>();
        //Map 타입을 가지고있는 payload에 테스트 : 테스트입니다(key:value 방식) 을 넣어주었습니다.
        payload.put("sub", user.getUserId());         // 구글 사용자 ID
        payload.put("name", user.getName());      // 이름
        payload.put("email", user.getEmail());    // 이메일

//      JWT 만들어주는 메소드를 호출합니다.
        String jwt = Jwts.builder()
                .header().add(header).and()        // 헤더 설정 (setHeader 대신 최신 방식)
                .claims(payload)                   // 페이로드 설정 (setClaims 대신 최신 방식)
                .subject("test")                // 주제 설정 (setSubject 대신 최신 방식)
                .expiration(ext)                   // 만료 시간 설정 (setExpiration 대신 최신 방식)
                .signWith(getSecretKey())                     // 서명
                .compact();                        // JWT 문자열 생성

        return jwt;
    }

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes()); // Base64 디코딩 필요 시 별도 처리
    }

    // JWT에서 클레임 추출
    public Claims getClaimsFromToken(String token) {
        try {
            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token);
            return jws.getPayload();
        } catch (Exception e) {
            throw new RuntimeException("Invalid JWT token: " + e.getMessage());
        }
    }
    // 특정 클레임 가져오기
    public String getUserIdFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return (String) claims.get("sub");
    }

    public String getNameFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return (String) claims.get("name");
    }

    public String getEmailFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return (String) claims.get("email");
    }


    public boolean validateToken(String token) {
        try {
            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token);
            return !jws.getPayload().getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }
}

