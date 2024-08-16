package org.chzz.market.domain.auction.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.util.ArrayList;
import java.util.List;
import java.time.LocalDateTime;

import lombok.*;
import org.chzz.market.common.validation.annotation.ThousandMultiple;
import org.chzz.market.domain.base.entity.BaseTimeEntity;
import org.chzz.market.domain.bid.entity.Bid;
import org.chzz.market.domain.product.entity.Product;

import static org.chzz.market.domain.auction.entity.Auction.AuctionStatus.*;

@Getter
@Entity
@Table
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

    // 경매가 진행 중인지 확인
    public boolean isProceeding() {
        return status == PROCEEDING;
    }

    // 경매가 종료되었는지 확인
    public boolean isEnded() {
        return LocalDateTime.now().isAfter(endDateTime);
    }

    // 입찰 금액이 최소 금액 이상인지 확인
    public boolean isAboveMinPrice(Long amount) {
        return amount >= getMinPrice();
    }

    @OneToMany(mappedBy = "auction", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Bid> bids = new ArrayList<>();

    public void registerBid(Bid bid) {
        if (bids == null) {
            bids = new ArrayList<>();
        }
        boolean isParticipated = bids.stream()
                .anyMatch(bid1 -> bid1.getBidder().equals(bid.getBidder()));
        if (isParticipated) {
            bids.stream()
                    .filter(bid1 -> bid1.equals(bid))
                    .findFirst()
                    .ifPresent(bid1 -> bids.remove(bid));
        }
        bids.add(bid);
        bid.specifyAuction(this);
    }

    public void removeBid(Bid bid) {
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

    public void start(LocalDateTime endDateTime) {
        this.status = PROCEEDING;
        this.endDateTime = endDateTime;
    }
}
