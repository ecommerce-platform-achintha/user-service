package com.achintha.userservice.admin;

import com.achintha.userservice.common.Pagination;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserStatus;
import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
import org.springframework.data.jpa.domain.Specification;

/** Admin user search: optional role, status and free-text (email, names, public id; LIKE wildcards escaped). */
final class UserSearch {

    private UserSearch() {
    }

    static Specification<User> matching(Role role, UserStatus status, String text) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (role != null) {
                predicates.add(cb.equal(root.get("role"), role));
            }
            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }
            if (text != null && !text.isBlank()) {
                String pattern = Pagination.likeContains(text);
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("email")), pattern, '\\'),
                        cb.like(cb.lower(root.get("firstName")), pattern, '\\'),
                        cb.like(cb.lower(root.get("lastName")), pattern, '\\'),
                        cb.like(cb.lower(root.get("publicId")), pattern, '\\')));
            }
            return cb.and(predicates.toArray(Predicate[]::new));
        };
    }
}
