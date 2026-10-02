package com.achintha.userservice.address;

import com.achintha.userservice.common.PageResponse;
import com.achintha.userservice.common.PublicIdGenerator;
import com.achintha.userservice.common.TextSanitizer;
import com.achintha.userservice.exception.ApiException;
import com.achintha.userservice.exception.ErrorCode;
import com.achintha.userservice.exception.NotFoundException;
import com.achintha.userservice.user.UserAccountFactory;
import com.achintha.userservice.user.UserRepository;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** The caller's addresses. The owner id always comes from the token (or, internally, from the path). */
@Service
public class AddressService {

    static final String DEFAULT_COUNTRY = "Sri Lanka";

    private final AddressRepository addressRepository;
    private final UserRepository userRepository;
    private final PublicIdGenerator publicIdGenerator;
    private final int maxAddresses;

    public AddressService(AddressRepository addressRepository, UserRepository userRepository,
                          PublicIdGenerator publicIdGenerator,
                          @Value("${app.max-addresses-per-user:20}") int maxAddresses) {
        this.addressRepository = addressRepository;
        this.userRepository = userRepository;
        this.publicIdGenerator = publicIdGenerator;
        this.maxAddresses = maxAddresses;
    }

    @Transactional
    public AddressResponse add(UUID userId, AddressRequest request) {
        if (!userRepository.existsById(userId)) {
            throw new NotFoundException("User not found");
        }
        if (addressRepository.countByUserId(userId) >= maxAddresses) {
            throw ApiException.conflict(ErrorCode.ADDRESS_LIMIT_REACHED,
                    "At most " + maxAddresses + " addresses can be saved");
        }
        Address address = new Address();
        address.setId(UUID.randomUUID());
        address.setPublicId(publicIdGenerator.generateUnique(PublicIdGenerator.ADDRESS_PREFIX,
                addressRepository::existsByPublicId));
        address.setUserId(userId);
        apply(address, request);
        return AddressResponse.from(addressRepository.saveAndFlush(address));
    }

    @Transactional(readOnly = true)
    public PageResponse<AddressResponse> list(UUID userId, Pageable pageable) {
        return PageResponse.from(addressRepository.findAllByUserId(userId, pageable), AddressResponse::from);
    }

    @Transactional(readOnly = true)
    public AddressResponse get(UUID userId, String publicId) {
        return AddressResponse.from(find(userId, publicId));
    }

    @Transactional
    public AddressResponse update(UUID userId, String publicId, AddressRequest request) {
        Address address = find(userId, publicId);
        apply(address, request);
        return AddressResponse.from(addressRepository.saveAndFlush(address));
    }

    @Transactional
    public void delete(UUID userId, String publicId) {
        addressRepository.delete(find(userId, publicId));
    }

    private Address find(UUID userId, String publicId) {
        return addressRepository.findByPublicIdAndUserId(publicId, userId)
                .orElseThrow(() -> new NotFoundException("Address not found"));
    }

    private static void apply(Address address, AddressRequest request) {
        address.setRecipientName(required(TextSanitizer.cleanLine(request.recipientName())));
        address.setPhone(UserAccountFactory.normalizePhone(request.phone()));
        address.setLine1(required(TextSanitizer.cleanLine(request.line1())));
        address.setLine2(TextSanitizer.cleanLine(request.line2()));
        address.setCity(required(TextSanitizer.cleanLine(request.city())));
        address.setDistrict(required(TextSanitizer.cleanLine(request.district())));
        address.setPostalCode(request.postalCode().trim());
        String country = TextSanitizer.cleanLine(request.country());
        address.setCountry(country == null ? DEFAULT_COUNTRY : country);
    }

    /** A field that was only markup is empty after sanitizing. */
    private static String required(String value) {
        if (value == null) {
            throw ApiException.badRequest(ErrorCode.VALIDATION_FAILED, "Address fields must contain plain text");
        }
        return value;
    }
}
