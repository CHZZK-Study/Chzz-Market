package org.chzz.market.domain.auction.controller;

import lombok.RequiredArgsConstructor;
import org.chzz.market.domain.auction.service.AuctionService;
import org.chzz.market.domain.product.entity.Product.Category;
import org.chzz.market.domain.auction.entity.SortType;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/auctions")
public class AuctionController {
    private final AuctionService auctionService;

    @GetMapping
    public ResponseEntity<?> getAuctionList(@RequestParam Category category,
//                                            @AuthenticationPrincipal CustomUserDetails customUserDetails, // TODO: 추후에 인증된 사용자 정보로 수정 필요
                                            @RequestParam(defaultValue = "newest") SortType type,
                                            Pageable pageable) {
        return ResponseEntity.ok(auctionService.getAuctionListByCategory(category, type, 1L, pageable)); // 임의의 사용자 ID
    }
}
