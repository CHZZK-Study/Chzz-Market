package org.chzz.market.domain.address.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.chzz.market.common.config.LoginUser;
import org.chzz.market.domain.address.dto.DeliveryRequest;
import org.chzz.market.domain.address.dto.DeliveryResponse;
import org.chzz.market.domain.address.service.AddressService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/addresses")
@RequiredArgsConstructor
public class AddressController {
    private final AddressService addressService;

    /**
     * 사용자의 주소 목록을 조회합니다.
     *
     * @param userId   현재 로그인한 사용자의 ID
     * @param pageable 페이징 정보
     * @return 주소 목록이 담긴 Page 객체
     */
    @GetMapping
    public ResponseEntity<Page<DeliveryResponse>> getAddresses(
            @LoginUser Long userId,
            Pageable pageable
    ) {
        return ResponseEntity.ok(addressService.getAddresses(userId, pageable));
    }

    /**
     * 새로운 배송지 주소를 추가합니다.
     *
     * @param userId          현재 로그인한 사용자의 ID
     * @param deliveryRequest 추가할 주소 정보
     * @return 생성된 주소의 ID
     */
    @PostMapping("/")
    public ResponseEntity<Void> addDelivery(
            @LoginUser Long userId,
            @Valid @RequestBody DeliveryRequest deliveryRequest
    ) {
        addressService.addDelivery(userId, deliveryRequest);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /**
     * 기존 배송지 주소를 수정합니다.
     *
     * @param userId          현재 로그인한 사용자의 ID
     * @param addressId       수정할 주소의 ID
     * @param deliveryRequest 수정할 주소 정보
     * @return 응답 상태
     */
    @PutMapping("/{addressId}")
    public ResponseEntity<Void> updateDelivery(
            @LoginUser Long userId,
            @PathVariable Long addressId,
            @Valid @RequestBody DeliveryRequest deliveryRequest
    ) {
        addressService.updateDelivery(userId, addressId, deliveryRequest);
        return ResponseEntity.ok().build();
    }

    /**
     * 배송지 주소를 삭제합니다. 기본 배송지로 설정된 주소는 삭제할 수 없습니다.
     *
     * @param userId    현재 로그인한 사용자의 ID
     * @param addressId 삭제할 주소의 ID
     * @return 응답 상태
     */
    @DeleteMapping("/{addressId}")
    public ResponseEntity<Void> deleteDelivery(
            @LoginUser Long userId,
            @PathVariable Long addressId
    ) {
        addressService.deleteDelivery(userId, addressId);
        return ResponseEntity.noContent().build();
    }
}
