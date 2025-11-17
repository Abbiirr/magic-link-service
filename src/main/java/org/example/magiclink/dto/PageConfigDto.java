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
public class PageConfigDto {
    private Integer pageNumber;
    private String pageType; // "prompt", "form", "loading", "mfa", "success", "error"
    private String title;
    private String description;
    private String buttonText;
    private List<FormFieldDto> fields;
    private String nextAction; // "navigate", "submit", "poll"
}
