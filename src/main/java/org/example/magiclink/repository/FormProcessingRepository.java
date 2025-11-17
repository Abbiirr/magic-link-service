package org.example.magiclink.repository;

import org.example.magiclink.entity.FormProcessingStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface FormProcessingRepository extends JpaRepository<FormProcessingStatus, Long> {
    Optional<FormProcessingStatus> findByToken(String token);
}
