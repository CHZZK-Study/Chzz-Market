package org.chzz.market.domain.bid.repository;

import java.util.Optional;
import org.chzz.market.domain.auction.entity.Auction;
import org.chzz.market.domain.bid.entity.Bid;
import org.chzz.market.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BidRepository extends JpaRepository<Bid, Long> {
    Optional<Bid> findByAuctionAndBidder(Auction auction, User bidder);
}
