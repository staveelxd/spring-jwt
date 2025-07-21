package com.example.springjwt.controller;

import com.example.springjwt.service.UserService;
import com.example.springjwt.model.User;
import com.example.springjwt.security.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.stereotype.Controller;
import org.springframework.http.ResponseCookie;
import java.util.stream.Collectors;

@Controller
public class PageController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    public PageController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/")
    public String showLoginForm() {
        return "login";
    }

    @GetMapping("/login")
    public String showLoginForm2() {
        return "login";
    }

    @GetMapping("/register")
    public String showRegisterForm() {
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@RequestParam String username, @RequestParam String email, @RequestParam String password, Model model) {
        try {
            userService.registerUser(username, email, password);
            model.addAttribute("success", "Регистрация прошла успешно. Теперь вы можете войти.");
            return "login";
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            return "register";
        }
    }

    @PostMapping("/login")
    public String loginUser(@RequestParam String username, @RequestParam String password, Model model, HttpServletResponse response) {
        try {
            User user = userService.authenticate(username, password);
            if (user == null) {
                model.addAttribute("error", "Неверный логин или пароль");
                return "login";
            }
            
            Authentication authentication = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                user, 
                null, 
                user.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority(role.name()))
                    .collect(Collectors.toList())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            String accessToken = jwtUtil.generateAccessToken(user);
            String refreshToken = jwtUtil.generateRefreshToken(user);
            
            ResponseCookie accessCookie = ResponseCookie.from("accessToken", accessToken)
                    .httpOnly(true)
                    .path("/")
                    .maxAge(60 * 60)
                    .build();
            ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken)
                    .httpOnly(true)
                    .path("/")
                    .maxAge(7 * 24 * 60 * 60)
                    .build();
            response.addHeader("Set-Cookie", accessCookie.toString());
            response.addHeader("Set-Cookie", refreshCookie.toString());
            
            return "redirect:/home";
        } catch (Exception e) {
            model.addAttribute("error", "Неверный логин или пароль");
            return "login";
        }
    }

    @GetMapping("/home")
    public String showHome() {
        return "home";
    }

    @GetMapping("/logout")
    public String logout() {
        SecurityContextHolder.clearContext();
        return "redirect:/";
    }
}
