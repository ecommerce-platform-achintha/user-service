package com.achintha.userservice.user;

import com.achintha.userservice.common.TextSanitizer;
import com.achintha.userservice.exception.NotFoundException;
import com.achintha.userservice.merchant.MerchantApplicationService;
import com.achintha.userservice.outbox.UserEventPublisher;
import com.achintha.userservice.ports.VerificationPort;
import com.achintha.userservice.user.UserRequests.CustomerRegistrationRequest;
import com.achintha.userservice.user.UserRequests.MerchantRegistrationRequest;
import com.achintha.userservice.user.UserRequests.UpdateProfileRequest;
import com.achintha.userservice.user.UserResponses.ProfileResponse;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Self-service: registration (customer, merchant) and the caller's own profile. */
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final UserAccountFactory accountFactory;
    private final MerchantApplicationService merchantApplications;
    private final VerificationPort verificationPort;
    private final UserEventPublisher events;

    /** Customers need no approval: {@code ACTIVE} immediately (section 3.6). */
    @Transactional
    public ProfileResponse registerCustomer(CustomerRegistrationRequest request) {
        verify(request.email(), request.phone());
        User user = accountFactory.newUser(Role.ROLE_CUSTOMER, UserStatus.ACTIVE, request.email(),
                request.password(), request.firstName(), request.lastName(), request.nic(), request.phone(), null);
        save(user);
        events.userRegistered(user);
        return ProfileResponse.from(user);
    }

    /**
     * Merchants start in {@code PENDING_APPROVAL} and get their {@code storeId} now; it never changes afterwards
     * (store-service creates the store row under it).
     */
    @Transactional
    public ProfileResponse registerMerchant(MerchantRegistrationRequest request) {
        verify(request.email(), request.phone());
        User user = accountFactory.newUser(Role.ROLE_MERCHANT, UserStatus.PENDING_APPROVAL, request.email(),
                request.password(), request.firstName(), request.lastName(), request.nic(), request.phone(), null);
        user.setStoreId(UUID.randomUUID());
        save(user);
        merchantApplications.recordSubmission(user, request.businessName(), request.documentKeys());
        events.userRegistered(user);
        return ProfileResponse.from(user);
    }

    @Transactional(readOnly = true)
    public ProfileResponse getProfile(UUID userId) {
        return ProfileResponse.from(findUser(userId));
    }

    @Transactional
    public ProfileResponse updateProfile(UUID userId, UpdateProfileRequest request) {
        User user = findUser(userId);
        user.setFirstName(TextSanitizer.cleanLine(request.firstName()));
        user.setLastName(TextSanitizer.cleanLine(request.lastName()));
        if (request.phone() != null) {
            user.setPhone(UserAccountFactory.normalizePhone(request.phone()));
        }
        return ProfileResponse.from(user);
    }

    @Transactional(readOnly = true)
    public User findUser(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User not found"));
    }

    private void verify(String email, String phone) {
        verificationPort.verifyEmail(email);
        verificationPort.verifyPhone(phone);
    }

    private void save(User user) {
        try {
            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            throw UniqueConstraints.translate(e);
        }
    }
}
