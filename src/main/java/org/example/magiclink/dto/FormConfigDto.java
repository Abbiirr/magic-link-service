package org.example.magiclink.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FormConfigDto {
    private String email;
    private String token;
    private String title;
    private String description;
    private List<FormFieldDto> fields;
    private String submitButtonText;
    private Long tokenExpiresIn; // seconds remaining until token expires

    // Multi-page support
    private Boolean multiPage; // true if this is a multi-page form
    private List<PageConfigDto> pages; // all page configurations
    private Integer currentPage; // current page number (0-indexed)
}
