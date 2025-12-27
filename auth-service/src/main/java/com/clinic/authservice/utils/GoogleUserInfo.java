package com.clinic.authservice.utils;

import com.clinic.authservice.domain.enums.AuthProvider;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * DTO يمثل بيانات المستخدم بعد التحقق من Google ID Token
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GoogleUserInfo {

    private String sub;             // معرف فريد من Google (Subject)
    private String email;           // البريد الإلكتروني
    private boolean emailVerified;  // هل البريد مؤكد
    private String name;            // الاسم الكامل
    private String picture;         // رابط صورة الملف الشخصي
    private AuthProvider provider;  // نوع الـ provider (GOOGLE)
}
