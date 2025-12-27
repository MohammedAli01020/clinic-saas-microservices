package com.clinic.authservice.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO لطلب تسجيل الدخول عبر Social Provider مثل Google
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SocialLoginRequest {

    private String idToken;   // الـ ID Token القادم من الـ provider (Google)
    private String device;    // اسم الجهاز أو نوعه (اختياري للتسجيل)
    private String ip;        // عنوان الـ IP المستخدم
}
