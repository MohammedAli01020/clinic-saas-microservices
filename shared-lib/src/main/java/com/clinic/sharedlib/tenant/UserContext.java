package com.clinic.sharedlib.tenant;


import com.clinic.sharedlib.jwt.CurrentUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class UserContext {

    private static final ThreadLocal<CurrentUser> USER = new ThreadLocal<>();

    public static void setUser(CurrentUser info) {
        USER.set(info);
    }

    public static CurrentUser getUser() {
        return USER.get();
    }

    public static void clear() {
        USER.remove();
    }

    public static String getCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.getPrincipal() instanceof CurrentUser) return
                ((CurrentUser) auth.getPrincipal()).userId();

        return null;
    }
}

