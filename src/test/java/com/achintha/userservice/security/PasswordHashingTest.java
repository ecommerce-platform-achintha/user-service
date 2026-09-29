package com.achintha.userservice.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.achintha.userservice.config.SecurityConfig;
import com.achintha.userservice.user.RegisterRequest;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserRepository;
import com.achintha.userservice.user.UserResponse;
import com.achintha.userservice.user.UserService;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class PasswordHashingTest {

    private static final String RAW_PASSWORD = "Str0ng!Passw0rd";

    private final PasswordEncoder passwordEncoder = new SecurityConfig().passwordEncoder();

    @Mock
    private UserRepository userRepository;

    @Test
    void encodesWithBcrypt() {
        String hash = passwordEncoder.encode(RAW_PASSWORD);

        assertThat(hash).isNotEqualTo(RAW_PASSWORD).startsWith("$2");
        assertThat(passwordEncoder.matches(RAW_PASSWORD, hash)).isTrue();
    }

    @Test
    void rejectsWrongPassword() {
        String hash = passwordEncoder.encode(RAW_PASSWORD);

        assertThat(passwordEncoder.matches("Str0ng!Passw0rD", hash)).isFalse();
        assertThat(passwordEncoder.matches("", hash)).isFalse();
    }

    @Test
    void saltsEachHash() {
        String first = passwordEncoder.encode(RAW_PASSWORD);
        String second = passwordEncoder.encode(RAW_PASSWORD);

        assertThat(first).isNotEqualTo(second);
        assertThat(passwordEncoder.matches(RAW_PASSWORD, first)).isTrue();
        assertThat(passwordEncoder.matches(RAW_PASSWORD, second)).isTrue();
    }

    @Test
    void registerStoresOnlyTheHashAndNeverReturnsIt() {
        UserService userService = new UserService(userRepository, passwordEncoder);
        when(userRepository.existsByEmail("jane@example.com")).thenReturn(false);
        when(userRepository.saveAndFlush(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(UUID.randomUUID());
            return u;
        });

        UserResponse response = userService.register(
                new RegisterRequest("  Jane@Example.com ", RAW_PASSWORD, "Jane", "Doe"));

        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(userRepository).saveAndFlush(saved.capture());
        String storedPassword = saved.getValue().getPassword();
        assertThat(storedPassword).isNotEqualTo(RAW_PASSWORD).startsWith("$2");
        assertThat(passwordEncoder.matches(RAW_PASSWORD, storedPassword)).isTrue();

        assertThat(response.email()).isEqualTo("jane@example.com");
        assertThat(response.roles()).containsExactly(Role.ROLE_CUSTOMER);
        assertThat(Arrays.stream(UserResponse.class.getRecordComponents()).map(RecordComponent::getName))
                .doesNotContain("password");
        assertThat(response.toString()).doesNotContain(RAW_PASSWORD).doesNotContain(storedPassword);
    }

    @Test
    void registerRequestToStringMasksPassword() {
        RegisterRequest request = new RegisterRequest("jane@example.com", RAW_PASSWORD, "Jane", "Doe");

        assertThat(request.toString()).doesNotContain(RAW_PASSWORD);
    }
}
