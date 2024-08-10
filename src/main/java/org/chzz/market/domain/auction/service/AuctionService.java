package org.chzz.market.domain.auction.service;

import static org.chzz.market.domain.auction.error.AuctionErrorCode.*;
import static org.chzz.market.domain.auction.error.AuctionErrorCode.AUCTION_NOT_ACCESSIBLE;
import static org.chzz.market.domain.auction.error.AuctionErrorCode.AUCTION_NOT_FOUND;
import org.chzz.market.domain.auction.dto.AuctionDetailsResponse;
import org.chzz.market.domain.auction.dto.StartResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import lombok.RequiredArgsConstructor;

import org.chzz.market.domain.auction.error.AuctionException;
import org.chzz.market.domain.auction.entity.Auction;
import org.chzz.market.domain.auction.dto.AuctionResponse;
import org.chzz.market.domain.auction.entity.SortType;
import org.chzz.market.domain.auction.repository.AuctionRepository;
import org.chzz.market.domain.product.entity.Product.Category;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuctionService {

    private static final Logger logger = LoggerFactory.getLogger(AuctionService.class);

    private final AuctionRepository auctionRepository;

    @Transactional
    public StartResponse startAuction(Long auctionId) {
        Auction auction = auctionRepository.findById(auctionId)
                .orElseThrow(() -> new AuctionException(AUCTION_NOT_FOUND));

        if (auction.getStatus() != Auction.AuctionStatus.PENDING) {
            throw new AuctionException(INVALID_AUCTION_STATE);
        }

        auction.start();
        auctionRepository.save(auction);

        return new StartResponse(auction);
    }

    public Auction getAuction(Long auctionId) {
        return auctionRepository.findById(auctionId)
                .orElseThrow(() -> new AuctionException(AUCTION_NOT_FOUND));
    }

    public Page<AuctionResponse> getAuctionListByCategory(Category category, SortType sortType, Long userId,
                                                      Pageable pageable) {
        return auctionRepository.findAuctionsByCategory(category, sortType, userId, pageable);
    }

    public AuctionDetailsResponse getAuctionDetails(Long auctionId, Long userId) {
        Optional<AuctionDetailsResponse> auctionDetails = auctionRepository.findAuctionDetailsById(auctionId, userId);
        return auctionDetails.orElseThrow(() -> new AuctionException(AUCTION_NOT_ACCESSIBLE));
    }

}
