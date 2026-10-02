package com.achintha.userservice.user;

import com.achintha.userservice.common.Nic;
import com.achintha.userservice.common.PublicIdGenerator;
import com.achintha.userservice.common.TextSanitizer;
import com.achintha.userservice.exception.EmailAlreadyExistsException;
import java.time.Clock;
import java.util.Locale;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/** Builds new accounts the same way for every role: normalized email, hashed password, sanitized names, public id. */
@Component
@RequiredArgsConstructor
public class UserAccountFactory {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PublicIdGenerator publicIdGenerator;
    private final Clock clock;

    /**
     * @param actorPublicId who created the account ({@code statusChangedBy}); the user's own id is used for
     *                      self-registration when {@code null}
     */
    public User newUser(Role role, UserStatus status, String email, String rawPassword, String firstName,
                        String lastName, String nic, String phone, String actorPublicId) {
        String normalizedEmail = normalizeEmail(email);
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new EmailAlreadyExistsException();
        }
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setPublicId(publicIdGenerator.generateUnique(PublicIdGenerator.USER_PREFIX,
                userRepository::existsByPublicId));
        user.setEmail(normalizedEmail);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setFirstName(TextSanitizer.cleanLine(firstName));
        user.setLastName(TextSanitizer.cleanLine(lastName));
        user.setNic(Nic.normalize(nic));
        user.setPhone(normalizePhone(phone));
        user.setRole(role);
        user.changeStatus(status, null, actorPublicId != null ? actorPublicId : user.getPublicId(), clock.instant());
        return user;
    }

    public static String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    public static String normalizePhone(String phone) {
        return phone == null ? null : phone.replaceAll("[\\s-]", "");
    }
}
