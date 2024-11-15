package org.chzz.market.domain.auctionv2.entity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.chzz.market.domain.auctionv2.error.AuctionErrorCode.AUCTION_ACCESS_FORBIDDEN;
import static org.chzz.market.domain.auctionv2.error.AuctionErrorCode.AUCTION_ALREADY_OFFICIAL;
import static org.chzz.market.domain.imagev2.error.ImageErrorCode.IMAGE_NOT_FOUND;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.List;
import org.chzz.market.domain.auctionv2.error.AuctionException;
import org.chzz.market.domain.image.entity.ImageV2;
import org.chzz.market.domain.imagev2.error.exception.ImageException;
import org.chzz.market.domain.user.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuctionV2Test {
    private static final String ERROR_CODE = "errorCode";

    private AuctionV2 auction;
    private User owner;
    private User otherUser;

    @BeforeEach
    void setUp() {
        owner = User.builder()
                .id(1L)
                .build();
        otherUser = User.builder()
                .id(2L)
                .build();

        auction = AuctionV2.builder()
                .seller(owner)
                .status(AuctionStatus.PRE)
                .build();
    }

    @Test
    void 소유자가_맞는경우_예외가_발생하지않는다() {
        assertDoesNotThrow(() -> auction.validateOwner(owner.getId()));
    }

    @Test
    void 소유자가_아닌경우_예외가_발생한다() {
        // 소유자가 아닌 경우 - 예외 발생
        assertThatThrownBy(() -> auction.validateOwner(otherUser.getId()))
                .isInstanceOf(AuctionException.class)
                .extracting(ERROR_CODE)
                .isEqualTo(AUCTION_ACCESS_FORBIDDEN);
    }

    @Test
    void 정식경매_전환성공() {
        assertThat(auction.getStatus()).isEqualTo(AuctionStatus.PRE);
        auction.startOfficialAuction();
        assertThat(auction.getStatus()).isEqualTo(AuctionStatus.PROCEEDING);
    }

    @Test
    void 전환할때_이미정식경매인_경우() {
        auction.startOfficialAuction();
        assertThatThrownBy(auction::startOfficialAuction)
                .isInstanceOf(AuctionException.class)
                .extracting(ERROR_CODE)
                .isEqualTo(AUCTION_ALREADY_OFFICIAL);
    }

    @Test
    void 첫번째이미지를_정상적으로_반환한다() {
        ImageV2 firstImage = ImageV2.builder()
                .cdnPath("cdn/path/to/first_image.jpg")
                .sequence(1)
                .build();
        ImageV2 secondImage = ImageV2.builder()
                .cdnPath("cdn/path/to/second_image.jpg")
                .sequence(2)
                .build();
        auction.getImages().addAll(List.of(firstImage, secondImage));
        assertThat(auction.getFirstImageCdnPath()).isEqualTo("cdn/path/to/first_image.jpg");
    }

    @Test
    void 예상치_못한_오류로_경매의_이미지가_없을시_예외가_발생한다() {
        assertThatThrownBy(auction::getFirstImageCdnPath)
                .isInstanceOf(ImageException.class)
                .extracting(ERROR_CODE)
                .isEqualTo(IMAGE_NOT_FOUND);
    }

    @Test
    void 낙찰자가_맞는경우() {
        AuctionV2 winnerAuction = AuctionV2.builder()
                .seller(owner)
                .status(AuctionStatus.PRE)
                .winnerId(owner.getId())
                .build();
        assertThat(winnerAuction.isWinner(owner.getId())).isTrue();
    }

    @Test
    void 낙찰자가_null_일때_조회하는경우_false_반환() {
        assertThat(auction.isWinner(1L)).isFalse();
    }

    @Test
    void 낙찰자가_아닐때_조회하는경우_false_반환() {
        AuctionV2 winnerAuction = AuctionV2.builder()
                .seller(owner)
                .status(AuctionStatus.PRE)
                .winnerId(owner.getId())
                .build();
        assertThat(winnerAuction.isWinner(owner.getId() + 1)).isFalse();
    }
}
