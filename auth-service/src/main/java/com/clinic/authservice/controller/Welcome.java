package com.clinic.authservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Welcome {

    @GetMapping("/welcome")
    public ResponseEntity<?> welcome() {
        return new ResponseEntity<>("Welcome", HttpStatus.OK);
    }
}
