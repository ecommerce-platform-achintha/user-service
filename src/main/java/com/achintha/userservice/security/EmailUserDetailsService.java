package com.achintha.userservice.security;

import com.achintha.userservice.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/** Loads users by email for the login flow (username = email). */
@Service
@RequiredArgsConstructor
public class EmailUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) {
        return userRepository.findByEmail(email.trim().toLowerCase())
                .map(user -> User.withUsername(user.getEmail())
                        .password(user.getPassword())
                        .authorities(user.getRoles().stream()
                                .map(role -> new SimpleGrantedAuthority(role.name()))
                                .toList())
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
