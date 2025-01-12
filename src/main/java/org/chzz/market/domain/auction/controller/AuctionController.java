package org.chzz.market.domain.auction.controller;

import io.swagger.v3.oas.annotations.Parameter;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.chzz.market.common.config.LoginUser;
import org.chzz.market.domain.auction.dto.AuctionRegisterType;
import org.chzz.market.domain.auction.dto.request.RegisterRequest;
import org.chzz.market.domain.auction.dto.response.CategoryResponse;
import org.chzz.market.domain.auction.dto.response.EndedAuctionResponse;
import org.chzz.market.domain.auction.dto.response.LostAuctionResponse;
import org.chzz.market.domain.auction.dto.response.PreAuctionResponse;
import org.chzz.market.domain.auction.dto.response.ProceedingAuctionResponse;
import org.chzz.market.domain.auction.dto.response.WonAuctionResponse;
import org.chzz.market.domain.auction.entity.AuctionStatus;
import org.chzz.market.domain.auction.entity.Category;
import org.chzz.market.domain.auction.service.AuctionCategoryService;
import org.chzz.market.domain.auction.service.AuctionLookupService;
import org.chzz.market.domain.auction.service.AuctionMyService;
import org.chzz.market.domain.auction.service.AuctionSearchService;
import org.chzz.market.domain.auction.service.AuctionTestService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Validated
public class AuctionController implements AuctionApi {
    private final AuctionLookupService auctionLookupService;
    private final AuctionCategoryService auctionCategoryService;
    private final AuctionTestService testService;
    private final AuctionMyService auctionMyService;
    private final AuctionSearchService auctionSearchService;

    /**
     * 경매 목록 조회
     */
    @Override
    @GetMapping
    public ResponseEntity<Page<?>> getAuctionList(@LoginUser Long userId,
                                                  @RequestParam(required = false) Category category,
                                                  @RequestParam(required = false, defaultValue = "proceeding") AuctionStatus status,
                                                  @Parameter(description = "경매 종료까지 남은 시간 (분) (1분 이상이어야 함)")
                                                  @RequestParam(required = false) @Min(value = 1, message = "minutes는 1 이상의 값이어야 합니다.") Integer minutes,
                                                  @PageableDefault(sort = "newest") Pageable pageable) {
        return ResponseEntity.ok(
                auctionLookupService.getAuctionList(userId, category, status, minutes, pageable));
    }

    @Override
    @GetMapping("/search")
    public ResponseEntity<?> searchAuctionList(@LoginUser Long userId,
                                               @RequestParam String keyword,
                                               @RequestParam AuctionStatus status,
                                               @PageableDefault(sort = "newest") Pageable pageable) {
        return ResponseEntity.ok(auctionSearchService.search(userId, keyword, status, pageable));
    }

    /**
     * 경매 카테고리 Enum 조회
     */
    @Override
    @GetMapping("/categories")
    public ResponseEntity<List<CategoryResponse>> getCategoryList() {
        return ResponseEntity.ok(auctionCategoryService.getCategories());
    }

    /**
     * 사용자가 등록한 진행중인 경매 목록 조회
     */
    @Override
    @GetMapping("/users/proceeding")
    public ResponseEntity<Page<ProceedingAuctionResponse>> getUserProceedingAuctionList(@LoginUser Long userId,
                                                                                        @PageableDefault(sort = "newest") Pageable pageable) {
        return ResponseEntity.ok(auctionMyService.getUserProceedingAuctionList(userId, pageable));
    }

    /**
     * 사용자가 등록한 종료된 경매 목록 조회
     */
    @Override
    public ResponseEntity<Page<EndedAuctionResponse>> getUserEndedAuctionList(@LoginUser Long userId,
                                                                              @PageableDefault(sort = "newest") Pageable pageable) {
        return ResponseEntity.ok(auctionMyService.getUserEndedAuctionList(userId, pageable));
    }

    /**
     * 사용자가 등록한 사전 경매 목록 조회
     */
    @Override
    @GetMapping("/users/pre")
    public ResponseEntity<Page<PreAuctionResponse>> getUserPreAuctionList(@LoginUser Long userId,
                                                                          @PageableDefault(sort = "newest") Pageable pageable) {
        return ResponseEntity.ok(auctionMyService.getUserPreAuctionList(userId, pageable));
    }

    /**
     * 사용자가 낙찰한 경매 목록 조회
     */
    @Override
    public ResponseEntity<Page<WonAuctionResponse>> getUserWonAuctionList(@LoginUser Long userId,
                                                                          @PageableDefault(sort = "newest") Pageable pageable) {
        return ResponseEntity.ok(auctionMyService.getUserWonAuctionList(userId, pageable));
    }

    /**
     * 사용자가 낙찰실패한 경매 목록 조회
     */
    @Override
    public ResponseEntity<Page<LostAuctionResponse>> getUserLostAuctionList(@LoginUser Long userId,
                                                                            @PageableDefault(sort = "newest") Pageable pageable) {
        return ResponseEntity.ok(auctionMyService.getUserLostAuctionList(userId, pageable));
    }

    /**
     * 사용자가 좋아요(찜)한 경매 목록 조회
     */
    @Override
    @GetMapping("/users/likes")
    public ResponseEntity<Page<PreAuctionResponse>> getLikedAuctionList(@LoginUser Long userId,
                                                                        @PageableDefault(sort = "newest") Pageable pageable) {
        return ResponseEntity.ok(auctionMyService.getLikedAuctionList(userId, pageable));
    }

    /**
     * 경매 등록
     */
    @Override
    @PostMapping
    public ResponseEntity<Void> registerAuction(@LoginUser Long userId,
                                                @RequestBody @Valid RegisterRequest request) {
        AuctionRegisterType type = request.auctionRegisterType();
        type.getService().register(userId, request);//요청 타입에 따라 다른 서비스 호출
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /**
     * 경매 테스트 등록
     */
    @Override
    @PostMapping("/test")
    public ResponseEntity<Void> testEndAuction(@LoginUser Long userId,
                                               @RequestParam("seconds") int seconds,
                                               @RequestParam String name,
                                               @RequestParam String description,
                                               @RequestParam AuctionStatus status,
                                               @RequestParam Integer minPrice) {
        testService.test(userId, seconds, name, description, status, minPrice);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/test2")
    public ResponseEntity<Void> testEndAuction(@LoginUser Long userId,
                                               @RequestParam("count") int count) {
        testService.testMulti(userId,count);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/test3")
    public ResponseEntity<Void> testPreAuction(@LoginUser Long userId,
                                               @RequestParam("count") int count) {
        testService.testMultiPre(userId,count);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
