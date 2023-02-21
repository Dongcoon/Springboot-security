package com.cos.security1.security1.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller //View 리턴
public class IndexController {

    // localhost:8080/
    // localhost:8080
    @GetMapping({"","/"})
    public String index(){
        // 머스테치 기본폴더 src/main/resouces/
        // 뷰리졸버 설정: template(prefix), .mustache(suffix) 생략가능
        return "index"; // src/main/resouces/templates/index.mustache
    }
    @GetMapping("/user")
    public @ResponseBody String user(){
        return "user" ;
    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin" ;
    }

    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }

    @GetMapping("/login")
    public @ResponseBody String login(){
        return "login";
    }

    @GetMapping("/join")
    public @ResponseBody String join(){
        return "join" ;
    }

    @GetMapping("/joinProc")
    public @ResponseBody String joinProc(){
        return "회원가입 완료됨" ;
    }

}
