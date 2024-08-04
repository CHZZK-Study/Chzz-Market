package org.chzz.market.domain.auction.repository;

import org.chzz.market.domain.auction.dto.AuctionResponse;
import org.chzz.market.domain.product.entity.Product.Category;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface AuctionRepositoryCustom {
    Page<AuctionResponse> findAuctionsByCategory(Category category, Long userId, Pageable pageable);
}
