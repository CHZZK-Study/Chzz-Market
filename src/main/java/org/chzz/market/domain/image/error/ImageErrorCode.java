package org.chzz.market.domain.image.error;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.chzz.market.common.error.ErrorCode;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ImageErrorCode implements ErrorCode {
    IMAGE_UPLOAD_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "이미지 업로드를 실패했습니다."),
    IMAGE_DELETE_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "이미지 삭제를 실패했습니다. "),
    IMAGE_SAVE_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "이미지 저장을 실패했습니다."),
    IMAGE_URL_ENCODING_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "이미지 URL 인코딩을 실패했습니다."),
    INVALID_IMAGE_EXTENSION(HttpStatus.BAD_REQUEST, "지원하지 않는 이미지 확장자입니다.");

    private final HttpStatus httpStatus;
    private final String message;
}
