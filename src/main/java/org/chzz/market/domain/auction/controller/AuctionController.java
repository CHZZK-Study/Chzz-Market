package org.chzz.market.domain.auction.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.chzz.market.common.config.LoginUser;
import org.chzz.market.domain.auction.dto.request.BaseRegisterRequest;
import org.chzz.market.domain.auction.dto.response.RegisterResponse;
import org.chzz.market.domain.auction.service.register.AuctionRegistrationService;
import org.chzz.market.domain.auction.service.AuctionRegistrationServiceFactory;
import org.chzz.market.domain.auction.service.AuctionService;
import org.chzz.market.domain.auction.dto.request.StartAuctionRequest;
import org.chzz.market.domain.auction.dto.response.StartAuctionResponse;
import org.chzz.market.domain.bid.service.BidService;
import org.chzz.market.domain.product.entity.Product.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RequiredArgsConstructor
@RestController
@RequestMapping("/auctions")
public class AuctionController {
    private static final Logger logger = LoggerFactory.getLogger(AuctionController.class);

    private final AuctionService auctionService;
    private final BidService bidService;
    private final AuctionRegistrationServiceFactory registrationServiceFactory;

    @GetMapping
    public ResponseEntity<?> getAuctionList(@RequestParam Category category,
                                            @LoginUser Long userId,
                                            Pageable pageable) {
        return ResponseEntity.ok(auctionService.getAuctionListByCategory(category, userId, pageable));
    }

    @GetMapping("/{auctionId}")
    public ResponseEntity<?> getAuctionDetails(@PathVariable Long auctionId, @LoginUser Long userId) {
        return ResponseEntity.ok(auctionService.getAuctionDetails(auctionId, userId));
    }

    /**
     * 상품 등록
     */
    @PostMapping(consumes = {MediaType.MULTIPART_FORM_DATA_VALUE}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<RegisterResponse> registerAuction(
            @RequestPart("request") @Valid BaseRegisterRequest request,
            @RequestPart(value = "images", required = true) List<MultipartFile> images) {

        AuctionRegistrationService auctionRegistrationService = registrationServiceFactory.getService(request.getAuctionRegisterType());
        RegisterResponse response = auctionRegistrationService.register(request, images);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * 경매 상품으로 전환
     */
    @PostMapping("/start")
    public ResponseEntity<StartAuctionResponse> startAuction(@RequestBody @Valid StartAuctionRequest request) {
        StartAuctionResponse response = auctionService.startAuction(request);
        logger.info("경매 상품으로 성공적으로 전환되었습니다. 상품 ID: {}", response.productId());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{auctionId}/bids")
    public ResponseEntity<?> getBids(@LoginUser Long userId, @PathVariable Long auctionId, Pageable pageable) {
        return ResponseEntity.ok(bidService.getBidsByAuctionId(userId, auctionId, pageable));
    }
}
