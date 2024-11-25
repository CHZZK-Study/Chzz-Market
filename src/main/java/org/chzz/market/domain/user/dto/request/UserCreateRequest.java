package org.chzz.market.domain.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class UserCreateRequest {
    public static final String NEWLINE_REGEX = "^(?:(?:[^\\n]*\\n){0,5}[^\\n]*$)"; // 개행문자 5개로 제한

    @NotBlank(message = "닉네임은 필수 입력 항목입니다.")
    @Size(max = 15, message = "닉네임은 15자 이내여야 합니다.")
    private String nickname;

    @Schema(description = "개행문자 포함 최대 100자, 개행문자 최대 5개")
    @Size(max = 100, message = "자기소개는 100자 이내여야 합니다.")
    @Pattern(regexp = NEWLINE_REGEX, message = "줄 바꿈 5번까지 가능합니다")
    private String bio;
}
