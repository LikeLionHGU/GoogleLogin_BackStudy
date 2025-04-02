package org.example.googlelogin_backstudy.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Id;
import lombok.Data;

@Data
@Entity
public class User {
    @Id
    @Column(name = "user_id")
    private String userId;
    private String name;
    private String email;
}