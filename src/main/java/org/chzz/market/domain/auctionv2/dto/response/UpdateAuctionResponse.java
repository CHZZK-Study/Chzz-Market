package org.chzz.market.domain.auctionv2.dto.response;

import java.util.List;
import org.chzz.market.domain.auctionv2.entity.AuctionV2;
import org.chzz.market.domain.auctionv2.entity.Category;
import org.chzz.market.domain.imagev2.dto.response.ImageResponse;

public record UpdateAuctionResponse(
        Long auctionId,
        String auctionName,
        String description,
        Category category,
        Integer minPrice,
        List<ImageResponse> imageUrls
) {
    public static UpdateAuctionResponse from(AuctionV2 auction) {
        return new UpdateAuctionResponse(
                auction.getId(),
                auction.getName(),
                auction.getDescription(),
                auction.getCategory(),
                auction.getMinPrice(),
                auction.getImages()
                        .stream()
                        .map(ImageResponse::from)
                        .toList()
        );
    }
}
