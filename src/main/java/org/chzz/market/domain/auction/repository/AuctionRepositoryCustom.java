package org.chzz.market.domain.auction.repository;

import java.util.List;
import java.util.Optional;
import org.chzz.market.domain.auction.dto.response.AuctionDetailsResponse;
import org.chzz.market.domain.auction.dto.response.AuctionResponse;
import org.chzz.market.domain.auction.dto.response.MyAuctionResponse;
import org.chzz.market.domain.product.entity.Product.Category;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface AuctionRepositoryCustom {
    /**
     * 카테고리에 따라 경매 리스트를 조회합니다.
     *
     * @param category 카테고리
     * @param userId   사용자 ID
     * @param pageable 페이징 정보
     * @return 페이징된 경매 응답 리스트
     */
    Page<AuctionResponse> findAuctionsByCategory(Category category, Long userId, Pageable pageable);

    /**
     * 경매 ID와 사용자 ID로 경매 상세 정보를 조회합니다.
     *
     * @param auctionId 경매 ID
     * @param userId    사용자 ID
     * @return 경매 상세 응답
     */
    Optional<AuctionDetailsResponse> findAuctionDetailsById(Long auctionId, Long userId);

    /**
     * 사용자 ID에 따라 경매 리스트를 조회합니다.
     *
     * @param userId   사용자 ID
     * @param pageable 페이징 정보
     * @return 페이징된 사용자 경매 응답 리스트
     */
    Page<MyAuctionResponse> findAuctionsByUserId(Long userId, Pageable pageable);


    /**
     * 홈 화면의 베스트 경매 조회
     * @return 입찰 기록이 많은 10개의 경매 정보
     */
    List<AuctionResponse> findBestAuctions(Long userId);
}
