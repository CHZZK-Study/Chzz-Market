package org.chzz.market.domain.auction.service.policy;

import org.chzz.market.domain.auction.dto.request.BaseRegisterRequest;
import org.chzz.market.domain.auction.entity.Auction;
import org.chzz.market.domain.product.entity.Product;
import org.chzz.market.domain.user.entity.User;

public abstract class AuctionPolicy {
    public abstract Product createProduct(BaseRegisterRequest request, User user);

    public Auction createAuction(Product product, BaseRegisterRequest request) {
        return Auction.builder()
                .product(product)
                .minPrice(request.getMinPrice())
                .status(Auction.AuctionStatus.PROCEEDING)
                .build();
    }
}
