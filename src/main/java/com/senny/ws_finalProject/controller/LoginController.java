package com.senny.ws_finalProject.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/login")
    public String loginSubmit(@RequestParam String id, HttpSession session) {
        session.setAttribute("userId", id);  // 세션에 사용자 ID 저장

        if ("admin".equals(id)) {
            return "redirect:/profile-list";
        } else {
            // 새 프로필을 작성하는 페이지로 리다이렉트
            return "redirect:/create-profile";
        }
    }
}
