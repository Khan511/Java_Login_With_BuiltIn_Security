package com.userSecurity.security.utils;

public class EmailUtils {
    public static String getEmailMessage(String name, String host, String key) {
        return "Hello " + name
                + ",\n\nYour new account has been created. Please click on the link below to verify your account.\n\n"
                + getVerificationUrl(host, key) + "\n\nThe Support Teams";
    };

    public static String getResetPasswordMessage(String name, String host, String key) {
        return "Hello " + name
                + ",\n\nPlease use below link to reset your password.\n\n"
                + getResetPasswordUrl(host, key) + "\n\nThe Support Teams";
    };

    public static String getVerificationUrl(String host, String key) {
        return host + "/verify/account?key=" + key;
    }

    public static String getResetPasswordUrl(String host, String key) {
        return host + "/verify/password?key=" + key;
    }

}
