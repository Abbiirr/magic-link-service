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
public class FormFieldDto {
    private String name;
    private String label;
    private String type;
    private boolean required;
    private String placeholder;
    private List<FormFieldOption> options;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class FormFieldOption {
        private String value;
        private String label;
    }
}
