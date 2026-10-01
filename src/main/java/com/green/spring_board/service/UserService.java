package com.green.spring_board.service;

import com.green.spring_board.dto.SignupRequest;
import com.green.spring_board.entity.User;
import com.green.spring_board.exceptions.ResourceConflictException;
import com.green.spring_board.exceptions.UserRequestException;
import com.green.spring_board.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password4j.BcryptPassword4jPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder
            = new BcryptPassword4jPasswordEncoder();

    public void signup(SignupRequest signupRequest) {

        // 이메일과 비밀번호가 공백인지 아닌지 확인
        if (signupRequest.getEmail().isBlank()
                || signupRequest.getPassword().isBlank()) {
            throw new UserRequestException(
                    "Email or password cannot be blank"
            );
        }

        // 이메일이 사용 중인지 확인
        if (userRepository.existByEmail(signupRequest.getEmail())) {
            throw new ResourceConflictException(
                    "Email already exists"
            );
        }

        // 비밀번호 해싱
        String hashedPassword =
                passwordEncoder.encode(signupRequest.getPassword());

        // db save
        User user = new User();

        user.setEmail(signupRequest.getEmail());
        user.setPassword(hashedPassword);
        user.setNickname(signupRequest.getNickname());

        userRepository.save(user);
    }
}