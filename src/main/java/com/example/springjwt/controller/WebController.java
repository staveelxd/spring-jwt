package com.example.springjwt.controller;

import com.example.springjwt.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class WebController {

    private final JwtUtil jwtUtil;

    @GetMapping("/auth/register")
    public String showRegister() {
        return "register";
    }

    @GetMapping("/auth/login")
    public String showLogin() {
        return "login";
    }

    @GetMapping({"/", "/home"})
    public String showHome(Model model, @RequestParam(required = false) String token) {
        model.addAttribute("token", token);
        return "home";
    }
}


