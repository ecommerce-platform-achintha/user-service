package com.achintha.userservice.auth;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ServiceClientRepository extends JpaRepository<ServiceClient, String> {
}
