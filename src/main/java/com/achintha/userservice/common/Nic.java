package com.achintha.userservice.common;

import java.util.Locale;
import java.util.regex.Pattern;

/** Sri Lankan NIC helpers: old format (9 digits + V/X) or new format (12 digits). */
public final class Nic {

    /** Case-insensitive on the trailing letter; values are stored upper-case. */
    public static final String REGEX = "^(\\d{9}[VvXx]|\\d{12})$";
    private static final Pattern PATTERN = Pattern.compile(REGEX);

    private Nic() {
    }

    public static boolean isValid(String nic) {
        return nic != null && PATTERN.matcher(nic.trim()).matches();
    }

    public static String normalize(String nic) {
        return nic == null ? null : nic.trim().toUpperCase(Locale.ROOT);
    }

    /** Keeps the last 3 characters only, e.g. {@code *********45V}. Used in responses for non-owners and in logs. */
    public static String mask(String nic) {
        if (nic == null) {
            return null;
        }
        int visible = Math.min(3, nic.length());
        return "*".repeat(nic.length() - visible) + nic.substring(nic.length() - visible);
    }
}
