package com.senny.ws_finalProject.controller;

import com.senny.ws_finalProject.dto.Profile;
import com.senny.ws_finalProject.service.ProfileService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class ProfileController {

    @Autowired
    private ProfileService profileService;

    @GetMapping("/create-profile")
    public String createProfileForm(HttpSession session, Model model) {
        String id = (String) session.getAttribute("userId");
        if (id == null) {
            return "redirect:/login";
        }
        model.addAttribute("id", id);
        return "addProfile";
    }

    @PostMapping("/create-profile")
    public String createProfile(Profile profile, HttpSession session, Model model) {
        String id = (String) session.getAttribute("userId");
        if (id == null) {
            return "redirect:/login";
        }
        profile.setId(id);
        profileService.saveProfile(profile);
        System.out.println("Profile 저장 완료");
        model.addAttribute("message", "Profile created successfully!");
        return "submitProfile";
    }

    @GetMapping("/profile-list") // 프로필 리스트 페이지 출력
    public String profileList(Model model) {
        model.addAttribute("profiles", profileService.getAllProfiles());
        return "profileList";
    }
}
