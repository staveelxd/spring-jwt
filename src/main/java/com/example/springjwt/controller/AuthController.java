package com.example.springjwt.controller;

import com.example.springjwt.dto.LoginRequest;
import com.example.springjwt.dto.RegisterRequest;
import com.example.springjwt.model.Role;
import com.example.springjwt.model.TokenBlacklistService;
import com.example.springjwt.model.User;
import com.example.springjwt.repository.UserRepository;
import com.example.springjwt.security.JwtUtil;
import com.example.springjwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final TokenBlacklistService tokenService;

    @PostMapping("/register")
    public String registerUserForm(
            @RequestParam String username,
            @RequestParam String email,
            @RequestParam String password,
            Model model) {

        try {
            userService.registerUser(username, email, password);
            return "redirect:/login";
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            return "register";
        }
    }


    @PostMapping("/login")
    public String loginUserForm(
            @RequestParam String username,
            @RequestParam String password,
            Model model,
            RedirectAttributes redirectAttributes) {

        User user = userService.authenticate(username, password);
        if (user == null) {
            model.addAttribute("error", "Неверный логин или пароль");
            return "login";
        }

        String token = jwtUtil.generateAccessToken(user);
        redirectAttributes.addAttribute("token", token);
        return "redirect:/home";
    }


    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        if (refreshToken == null) {
            return ResponseEntity.badRequest().body("Refresh token отсутствует");
        }

        try {
            UUID userId = jwtUtil.validateTokenAndGetUserId(refreshToken);
            User user = userService.findById(userId);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Пользователь не найден");
            }

            String newAccessToken = jwtUtil.generateAccessToken(user);
            return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Неверный или просроченный refresh token");
        }
    }


    @PostMapping("/revoke")
    public ResponseEntity<?> revoke(@RequestHeader("Authorization") String authHeader) {
        tokenService.revokeToken(authHeader.replace("Bearer ", ""));
        return ResponseEntity.ok("Токен отозван");
    }
}

