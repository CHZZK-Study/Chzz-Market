package org.chzz.market.domain.auction.dto;

import java.util.List;
import org.chzz.market.domain.auction.entity.Auction;

public record ImageUploadEvent(Auction auction, List<String> objectKeys) {
}
