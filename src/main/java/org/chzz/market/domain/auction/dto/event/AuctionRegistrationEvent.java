package org.chzz.market.domain.auction.dto.event;

import java.time.LocalDateTime;

public record AuctionRegistrationEvent(
        Long auctionId,
        LocalDateTime endDateTime
) {
}
