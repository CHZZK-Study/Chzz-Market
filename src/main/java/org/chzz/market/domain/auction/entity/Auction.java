package org.chzz.market.domain.auction.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.chzz.market.domain.base.entity.BaseTimeEntity;
import org.chzz.market.domain.product.entity.Product;
import org.chzz.market.domain.user.entity.User;

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

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = true)
    private User winner;

    @Column
//    @Pattern(regexp = "^[1-9][0-9]*000$") // TODO: @Pattern은 문자열에서만 적용가능 해서 임시 주석 처리 추후 수정 필요
    private Long minPrice;

    @Column
    private LocalDateTime endDateTime;

    @Column(columnDefinition = "varchar(20)")
    @Enumerated(EnumType.STRING)
    private Status status;

    public enum Status {
        //TODO 2024 07 18 14:07:49 : 경매 상태 구체화
        PRE_ORDER, PENDING, PROCEEDING, COMPLETE, CANCEL
    }
}
