package com.senny.ws_finalProject.dto;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
public class Profile implements Serializable {
    private String id;
    private String password;
    private String name;
    private int age;
    private String job;
    private String phone;
    private String mbti;

    public Profile(String id, String name, int age, String job, String phone, String mbti) {
        this.id = id;
        this.name = name;
        this.age = age;
        this.job = job;
        this.phone = phone;
        this.mbti = mbti;
    }
}
