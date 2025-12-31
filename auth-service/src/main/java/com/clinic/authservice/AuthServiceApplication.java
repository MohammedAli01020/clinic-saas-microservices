package com.clinic.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication(scanBasePackages = {
        "com.clinic.authservice",     // الباكج الرئيسي
        "com.clinic.sharedinternaltokengen",
//        "com.clinic.sharedlib.jwt",    // الباكج اللي فيه JwtUtils
//        "com.clinic.sharedsecurity"
})
@EnableDiscoveryClient
@EnableFeignClients(basePackages = "com.clinic.authservice.client")
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }

}
