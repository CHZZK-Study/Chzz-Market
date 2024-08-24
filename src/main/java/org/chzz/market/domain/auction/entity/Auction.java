package org.chzz.market.domain.auction.entity;

import static org.chzz.market.domain.auction.error.AuctionErrorCode.AUCTION_ENDED;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.chzz.market.domain.auction.error.AuctionException;
import org.chzz.market.domain.base.entity.BaseTimeEntity;
import org.chzz.market.domain.bid.entity.Bid;
import org.chzz.market.domain.product.entity.Product;

import static org.chzz.market.domain.auction.entity.Auction.AuctionStatus.*;

@Getter
@Entity
@Table(indexes = {
        @Index(columnList = "end_date_time")
})
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Auction extends BaseTimeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "auction_id")
    private Long id;

    @OneToOne
    @JoinColumn(name = "product_id")
    private Product product;

    @Column
    private Long winnerId;

    @Column
    private LocalDateTime endDateTime;

    @Column(columnDefinition = "varchar(20)")
    @Enumerated(EnumType.STRING)
    private AuctionStatus status;

    public Integer getMinPrice() {
        return product.getMinPrice();
    }

    public static Auction toEntity(Product product) {
        return Auction.builder()
                .product(product)
                .status(PROCEEDING)
                .endDateTime(LocalDateTime.now().plusHours(24))
                .build();
    }

    @OneToMany(mappedBy = "auction", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Bid> bids = new ArrayList<>();

    public void validateAuctionEndTime() {
        // 경매가 진행중이 아닐 때
        if (status != AuctionStatus.PROCEEDING || LocalDateTime.now().isAfter(endDateTime)) {
            throw new AuctionException(AUCTION_ENDED);
        }
    }

    // 입찰 금액이 최소 금액 이상인지 확인
    public boolean isAboveMinPrice(Long amount) {
        return amount >= getMinPrice();
    }


    public void registerBid(Bid bid) {
        bid.specifyAuction(this);
        bids.add(bid);
    }

    public void removeBid(Bid bid) {
        bid.cancelBid();
        bids.remove(bid);
    }

    @Getter
    @AllArgsConstructor
    public enum AuctionStatus {
        PENDING("대기 중"),
        PROCEEDING("진행 중"),
        ENDED("종료"),
        CANCELLED("취소 됨");

        private final String description;
    }
}
