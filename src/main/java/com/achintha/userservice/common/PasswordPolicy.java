package com.achintha.userservice.common;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Locale;
import java.util.Set;

/**
 * Password policy (section 3.3): at least 12 characters, at most 128, not blank-padded, and not on a small deny
 * list of well-known passwords. Length beats composition rules, so there are no character-class requirements.
 */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 128;

    /** Lower-cased. Common choices that satisfy the length rule. */
    private static final Set<String> DENY_LIST = Set.of(
            "password1234", "password12345", "password123456", "passwordpassword", "123456789012",
            "1234567890123", "12345678901234", "qwertyuiop123", "qwertyuiopasdf", "qwerty123456",
            "letmein12345", "iloveyou1234", "welcome12345", "administrator", "admin1234567",
            "changeme1234", "abc123456789", "aaaaaaaaaaaa", "111111111111", "000000000000",
            "p@ssw0rd1234", "passw0rd1234", "superadmin123", "marketplace123", "sri lanka123",
            "srilanka1234", "colombo12345");

    private PasswordPolicy() {
    }

    /** @return a violation message, or {@code null} if the password is acceptable */
    public static String check(String password) {
        if (password == null || password.length() < MIN_LENGTH) {
            return "must be at least " + MIN_LENGTH + " characters";
        }
        if (password.length() > MAX_LENGTH) {
            return "must be at most " + MAX_LENGTH + " characters";
        }
        if (password.isBlank() || !password.equals(password.strip())) {
            return "must not start or end with whitespace";
        }
        if (DENY_LIST.contains(password.toLowerCase(Locale.ROOT))) {
            return "is too common, choose another one";
        }
        if (password.chars().distinct().count() < 4) {
            return "must use at least 4 different characters";
        }
        return null;
    }

    /** Bean Validation constraint backed by {@link PasswordPolicy#check}. */
    @Documented
    @Constraint(validatedBy = Validator.class)
    @Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
    @Retention(RetentionPolicy.RUNTIME)
    public @interface ValidPassword {

        String message() default "does not meet the password policy";

        Class<?>[] groups() default {};

        Class<? extends Payload>[] payload() default {};
    }

    public static class Validator implements ConstraintValidator<ValidPassword, String> {

        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            String violation = check(value);
            if (violation == null) {
                return true;
            }
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(violation).addConstraintViolation();
            return false;
        }
    }
}
