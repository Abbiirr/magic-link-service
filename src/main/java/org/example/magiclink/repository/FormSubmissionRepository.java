package org.example.magiclink.repository;

import org.example.magiclink.entity.FormSubmissionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface FormSubmissionRepository extends JpaRepository<FormSubmissionEntity, Long> {
    Optional<FormSubmissionEntity> findBySubmissionId(String submissionId);
}
