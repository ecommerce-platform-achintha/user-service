package com.achintha.userservice.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.achintha.userservice.common.PasswordPolicy;
import com.achintha.userservice.config.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

class PasswordHashingTest {

    private static final String RAW_PASSWORD = "Correct-Horse-Battery-9";

    private final PasswordEncoder passwordEncoder = SecurityConfig.createPasswordEncoder();

    @Test
    void encodesWithArgon2idByDefault() {
        String hash = passwordEncoder.encode(RAW_PASSWORD);

        assertThat(hash).startsWith("{argon2}$argon2id$").doesNotContain(RAW_PASSWORD);
        assertThat(passwordEncoder.matches(RAW_PASSWORD, hash)).isTrue();
        assertThat(passwordEncoder.matches(RAW_PASSWORD + "x", hash)).isFalse();
        assertThat(passwordEncoder.upgradeEncoding(hash)).isFalse();
    }

    @Test
    void saltsEachHash() {
        assertThat(passwordEncoder.encode(RAW_PASSWORD)).isNotEqualTo(passwordEncoder.encode(RAW_PASSWORD));
    }

    @Test
    void stillVerifiesBcryptHashesAndFlagsThemForUpgrade() {
        String bcrypt = new BCryptPasswordEncoder().encode(RAW_PASSWORD);

        assertThat(passwordEncoder.matches(RAW_PASSWORD, "{bcrypt}" + bcrypt)).isTrue();
        assertThat(passwordEncoder.matches(RAW_PASSWORD, bcrypt)).isTrue(); // legacy, no {id} prefix
        assertThat(passwordEncoder.upgradeEncoding("{bcrypt}" + bcrypt)).isTrue();
    }

    @Test
    void policyRequiresTwelveCharactersAndRejectsCommonPasswords() {
        assertThat(PasswordPolicy.check("Short-1")).contains("at least 12");
        assertThat(PasswordPolicy.check("Password1234")).contains("too common");
        assertThat(PasswordPolicy.check("aaaaaaaaaaaaab")).contains("different characters");
        assertThat(PasswordPolicy.check(" padded-password ")).contains("whitespace");
        assertThat(PasswordPolicy.check("x".repeat(129))).contains("at most");
        assertThat(PasswordPolicy.check(RAW_PASSWORD)).isNull();
        assertThat(PasswordPolicy.check("long passphrase without digits")).isNull();
    }
}
