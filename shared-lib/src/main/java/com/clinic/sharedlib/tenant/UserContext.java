package com.clinic.sharedlib.tenant;


import com.clinic.sharedlib.jwt.UserInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class UserContext {

    private static final ThreadLocal<UserInfo> USER = new ThreadLocal<>();

    public static void setUser(UserInfo info) {
        USER.set(info);
    }

    public static UserInfo getUser() {
        return USER.get();
    }

    public static void clear() {
        USER.remove();
    }

    public static String getCurrentUserId () {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null) return null;

        return auth.getName();
    }
}

