package org.chzz.market.domain.auction.dto.response;

import com.querydsl.core.annotations.QueryProjection;

import java.time.LocalDateTime;
import java.util.List;
import lombok.Getter;
import org.chzz.market.domain.auction.enums.AuctionStatus;

@Getter
public class AuctionDetailsResponse {
    private Long productId;
    private Long sellerId;
    private String sellerName;
    private String title;
    private String description;
    private Integer minPrice;
    private LocalDateTime endDateTime;
    private AuctionStatus status;
    private Boolean isSeller;
    private Long participantCount;
    private Boolean isParticipating;
    private Long bidId;
    private Long bidAmount;
    private int remainingBidCount;
    private List<String> imageList;

    @QueryProjection
    public AuctionDetailsResponse(Long productId, Long sellerId, String sellerName, String title, String description,
                                  Integer minPrice, LocalDateTime endDateTime, AuctionStatus status,
                                  Boolean isSeller,
                                  Long participantCount, Boolean isParticipating, Long bidId, Long bidAmount,
                                  int remainingBidCount) {
        this.productId = productId;
        this.sellerId = sellerId;
        this.sellerName = sellerName;
        this.title = title;
        this.description = description;
        this.minPrice = minPrice;
        this.endDateTime = endDateTime;
        this.status = status;
        this.isSeller = isSeller;
        this.participantCount = participantCount;
        this.isParticipating = isParticipating;
        this.bidId = bidId;
        this.bidAmount = bidAmount;
        this.remainingBidCount = remainingBidCount;
    }

    public void addImageList(List<String> imageList) {
        this.imageList = imageList;
    }
}
