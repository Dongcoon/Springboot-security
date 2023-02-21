package com.cos.security1.security1.controller;

import com.cos.security1.security1.model.User;
import com.cos.security1.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller //View 리턴
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;


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

    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user){
        System.out.println(user);
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        //회원가입 잘됨. 비밀번호 1234 => 시큐리티로 로그인을 할 수 없음. 패스워드가 암호화가 안되어서
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터정보";
    }

}
