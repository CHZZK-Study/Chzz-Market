package org.chzz.market.domain.auction.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@Getter
@SuperBuilder
@NoArgsConstructor
public class PreRegisterRequest extends BaseRegisterRequest {
    @Override
    public void validate() {
        // TODO: 사전 등록 요청 검증 로직 추가
    }
}
