package com.anshuman.oauthserver.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ControllerHello {

    @GetMapping("/hello")
    public ResponseEntity<String> sayHello() {
        System.out.println("hello");
        return ResponseEntity.ok("Hello");
    }

    @GetMapping("/admin")
    public ResponseEntity<String> sayHelloToAdmin() {
        System.out.println("admin");
        return ResponseEntity.ok("Hello Admin");
    }

    @GetMapping("/user")
    public ResponseEntity<String> sayHelloToUser() {
        System.out.println("user");
        return ResponseEntity.ok("Hello User");
    }
}
