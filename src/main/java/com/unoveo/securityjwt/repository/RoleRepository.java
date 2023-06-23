package com.unoveo.securityjwt.repository;


import com.unoveo.securityjwt.models.ERole;
import com.unoveo.securityjwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}
