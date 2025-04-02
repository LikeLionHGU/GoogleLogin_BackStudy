package org.example.googlelogin_backstudy.repository;

import org.example.googlelogin_backstudy.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, String> {

}
