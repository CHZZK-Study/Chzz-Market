package org.chzz.market.domain.auction.repository;

import static org.chzz.market.common.util.QuerydslUtil.nullSafeBuilder;
import static org.chzz.market.domain.auction.entity.QAuction.auction;
import static org.chzz.market.domain.auction.repository.AuctionRepositoryCustomImpl.AuctionOrder.POPULARITY;
import static org.chzz.market.domain.auction.type.AuctionStatus.ENDED;
import static org.chzz.market.domain.auction.type.AuctionStatus.PROCEEDING;
import static org.chzz.market.domain.bid.entity.Bid.BidStatus.ACTIVE;
import static org.chzz.market.domain.bid.entity.Bid.BidStatus.CANCELLED;
import static org.chzz.market.domain.bid.entity.QBid.bid;
import static org.chzz.market.domain.image.entity.QImage.image;
import static org.chzz.market.domain.product.entity.QProduct.product;
import static org.chzz.market.domain.user.entity.QUser.user;

import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.Ops.DateTimeOps;
import com.querydsl.core.types.OrderSpecifier;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.core.types.dsl.DateTimeOperation;
import com.querydsl.core.types.dsl.Expressions;
import com.querydsl.core.types.dsl.NumberExpression;
import com.querydsl.jpa.JPAExpressions;
import com.querydsl.jpa.JPQLQuery;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.chzz.market.common.util.QuerydslOrder;
import org.chzz.market.common.util.QuerydslOrderProvider;
import org.chzz.market.domain.auction.dto.response.AuctionDetailsResponse;
import org.chzz.market.domain.auction.dto.response.AuctionResponse;
import org.chzz.market.domain.auction.dto.response.LostAuctionResponse;
import org.chzz.market.domain.auction.dto.response.QAuctionDetailsResponse;
import org.chzz.market.domain.auction.dto.response.QAuctionResponse;
import org.chzz.market.domain.auction.dto.response.QLostAuctionResponse;
import org.chzz.market.domain.auction.dto.response.QSimpleAuctionResponse;
import org.chzz.market.domain.auction.dto.response.QUserAuctionResponse;
import org.chzz.market.domain.auction.dto.response.QWonAuctionResponse;
import org.chzz.market.domain.auction.dto.response.SimpleAuctionResponse;
import org.chzz.market.domain.auction.dto.response.UserAuctionResponse;
import org.chzz.market.domain.auction.dto.response.WonAuctionResponse;
import org.chzz.market.domain.image.entity.QImage;
import org.chzz.market.domain.product.entity.Product.Category;
import org.chzz.market.domain.user.dto.response.ParticipationCountsResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;

@RequiredArgsConstructor
public class AuctionRepositoryCustomImpl implements AuctionRepositoryCustom {
    private final JPAQueryFactory jpaQueryFactory;
    private final QuerydslOrderProvider querydslOrderProvider;

    /**
     * 카테고리와 정렬 조건에 따라 경매 리스트를 조회합니다.
     *
     * @param category 카테고리
     * @param userId   사용자 ID
     * @param pageable 페이징 정보
     * @return 페이징된 경매 응답 리스트
     */
    @Override
    public Page<AuctionResponse> findAuctionsByCategory(Category category, Long userId,
                                                        Pageable pageable) {
        JPAQuery<?> baseQuery = jpaQueryFactory.from(auction)
                .join(auction.product, product)
                .where(auction.product.category.eq(category).and(auction.status.eq(PROCEEDING)));

        List<AuctionResponse> content = baseQuery
                .select(new QAuctionResponse(
                        auction.id,
                        product.name,
                        image.cdnPath,
                        timeRemaining().longValue(),
                        product.minPrice.longValue(),
                        bid.countDistinct(),
                        isParticipating(userId)
                ))
                .leftJoin(bid).on(bid.auction.id.eq(auction.id).and(bid.status.eq(ACTIVE)))
                .leftJoin(image).on(image.product.id.eq(product.id).and(image.id.eq(getFirstImageId())))
                .groupBy(auction.id, product.name, image.cdnPath, auction.createdAt, product.minPrice)
                .orderBy(querydslOrderProvider.getOrderSpecifiers(pageable))
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        JPAQuery<Long> countQuery = baseQuery
                .select(auction.count());
        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchCount);
    }

    /**
     * 사용자의 경매 참여 기록을 조회합니다
     *
     * @param userId   사용자 ID
     * @param pageable 페이징 정보
     * @return 회원의 경매 참여 기록
     */
    @Override
    public Page<AuctionResponse> findParticipatingAuctionRecord(Long userId, Pageable pageable) {
        JPAQuery<?> baseQuery = getActualParticipatedAuction(userId)
                .join(auction.product, product);

        List<AuctionResponse> content = baseQuery
                .select(new QAuctionResponse(
                        auction.id,
                        product.name,
                        image.cdnPath,
                        timeRemaining().longValue(),
                        auction.product.minPrice.longValue(),
                        getBidCount()
                ))
                .leftJoin(image).on(image.product.id.eq(product.id).and(image.id.eq(getFirstImageId())))
                .groupBy(auction.id, product.name, image.cdnPath)
                .orderBy(querydslOrderProvider.getOrderSpecifiers(pageable))
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        JPAQuery<Long> countQuery = baseQuery
                .select(auction.id.countDistinct());
        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchCount);
    }

    /**
     * 경매 ID와 사용자 ID로 경매 상세 정보를 조회합니다.
     *
     * @param auctionId 경매 ID
     * @param userId    사용자 ID
     * @return 경매 상세 응답
     */
    @Override
    public Optional<AuctionDetailsResponse> findAuctionDetailsById(Long auctionId, Long userId) {
        Optional<AuctionDetailsResponse> auctionDetailsResponse = Optional.ofNullable(jpaQueryFactory
                .select(new QAuctionDetailsResponse(
                        product.id,
                        user.nickname,
                        product.name,
                        product.description,
                        product.minPrice,
                        timeRemaining().longValue(),
                        auction.status,
                        userIdEq(userId),
                        getBidCount(),
                        bid.id.isNotNull(),
                        bid.id,
                        bid.amount.coalesce(0L),
                        bid.count.coalesce(0)
                ))
                .from(auction)
                .join(auction.product, product)
                .join(product.user, user)
                .leftJoin(bid).on(bid.auction.id.eq(auctionId).and(bid.status.eq(ACTIVE)).and(bidderIdEq(userId)))
                .where(auction.id.eq(auctionId))
                .fetchOne());

        auctionDetailsResponse.ifPresent(response -> response.addImageList(getImageList(response.getProductId())));

        return auctionDetailsResponse;
    }

    /**
     * 경매 ID와 사용자 ID로 경매 간단 상세 정보를 조회합니다.
     *
     * @param auctionId 경매 ID
     * @return 경매 간단 상세정보 응답
     */
    @Override
    public Optional<SimpleAuctionResponse> findSimpleAuctionDetailsById(Long auctionId) {
        return Optional.ofNullable(jpaQueryFactory
                .select(new QSimpleAuctionResponse(
                        image.cdnPath,
                        product.name,
                        product.minPrice,
                        bid.countDistinct()
                ))
                .from(auction)
                .join(auction.product, product)
                .leftJoin(image).on(image.product.id.eq(product.id).and(image.id.eq(getFirstImageId())))
                .leftJoin(bid).on(bid.auction.id.eq(auctionId).and(bid.status.eq(ACTIVE)))
                .where(auction.id.eq(auctionId))
                .groupBy(product.name, image.cdnPath, product.minPrice)
                .fetchOne());
    }

    /**
     * 사용자 닉네임에 따라 경매 리스트를 조회합니다.
     *
     * @param nickname 사용자 닉네임
     * @param pageable 페이징 정보
     * @return 페이징된 사용자 경매 응답 리스트
     */
    @Override
    public Page<UserAuctionResponse> findAuctionsByNickname(String nickname, Pageable pageable) {
        JPAQuery<?> baseQuery = jpaQueryFactory.from(auction)
                .join(auction.product, product)
                .join(product.user, user)
                .where(user.nickname.eq(nickname));

        List<UserAuctionResponse> content = baseQuery
                .select(new QUserAuctionResponse(
                        auction.id,
                        product.name,
                        image.cdnPath,
                        timeRemaining().longValue(),
                        product.minPrice.longValue(),
                        getBidCount(),
                        auction.status,
                        auction.createdAt))
                .leftJoin(image).on(image.product.id.eq(product.id)
                        .and(image.id.eq(getFirstImageId())))
                .orderBy(querydslOrderProvider.getOrderSpecifiers(pageable))
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        JPAQuery<Long> countQuery = baseQuery
                .select(auction.count());

        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchCount);
    }

    /**
     * 홈 화면의 베스트 경매 조회
     *
     * @return 입찰 기록이 많은 10개의 경매 정보
     */
    @Override
    public List<AuctionResponse> findBestAuctions() {
        JPAQuery<?> baseQuery = jpaQueryFactory.from(auction)
                .join(auction.product, product)
                .where(auction.status.eq(PROCEEDING))
                .orderBy(POPULARITY.getOrderSpecifier());

        return baseQuery.select(new QAuctionResponse(
                        auction.id,
                        product.name,
                        image.cdnPath,
                        timeRemaining().longValue(),
                        product.minPrice.longValue(),
                        bid.countDistinct())
                )
                .leftJoin(image).on(image.product.id.eq(product.id).and(image.id.eq(getFirstImageId())))
                .leftJoin(bid).on(bid.auction.id.eq(auction.id).and(bid.status.ne(CANCELLED)))
                .groupBy(auction.id, product.name, image.cdnPath, auction.createdAt, product.minPrice)
                .offset(0)
                .limit(5)
                .fetch();
    }

    /**
     * 홈 화면의 임박 경매 조회
     *
     * @return 경매 종료까지 1시간 이내인 경매 정보
     */
    @Override
    public List<AuctionResponse> findImminentAuctions() {
        JPAQuery<?> baseQuery = jpaQueryFactory
                .from(auction)
                .join(auction.product, product)
                .where(
                        timeRemaining().between(0, 3600)
                                .and(auction.status.eq(PROCEEDING)))
                .orderBy(timeRemaining().asc(), POPULARITY.getOrderSpecifier());

        return baseQuery.select(new QAuctionResponse(
                        auction.id,
                        product.name,
                        image.cdnPath,
                        timeRemaining().longValue(),
                        product.minPrice.longValue(),
                        bid.countDistinct())
                )
                .leftJoin(image).on(image.product.id.eq(product.id).and(image.id.eq(getFirstImageId())))
                .leftJoin(bid).on(bid.auction.id.eq(auction.id).and(bid.status.ne(CANCELLED)))
                .groupBy(auction.id, product.name, image.cdnPath)
                .offset(0)
                .limit(5)
                .fetch();
    }

    /**
     * 사용자가 낙찰한 경매 이력을 조회합니다.
     *
     * @param userId   사용자 ID
     * @param pageable 페이징 정보
     * @return 페이징된 낙찰 경매 응답 리스트
     */
    @Override
    public Page<WonAuctionResponse> findWonAuctionHistoryByUserId(Long userId, Pageable pageable) {
        JPAQuery<?> baseQuery = getActualParticipatedAuction(userId)
                .join(auction.product, product)
//                .join(product.user, user)//?? 안쓰는데
                .where(auction.winnerId.eq(userId)
                        .and(auction.status.eq(ENDED)));

        List<WonAuctionResponse> content = baseQuery
                .select(new QWonAuctionResponse(
                        auction.id,
                        product.name,
                        image.cdnPath,
                        product.minPrice,
                        auction.endDateTime,
                        bid.amount
                ))
                .leftJoin(image).on(image.product.eq(product).and(image.id.eq(getFirstImageId())))
                .groupBy(auction.id, product.name, image.cdnPath, product.minPrice, bid.amount)
                .orderBy(querydslOrderProvider.getOrderSpecifiers(pageable))
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        JPAQuery<Long> countQuery = baseQuery
                .select(auction.count());

        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchCount);
    }

    /**
     * 사용자가 낙찰하지 못한 경매 이력을 조회합니다.
     *
     * @param userId   사용자 ID
     * @param pageable 페이징 정보
     * @return 페이징된 낙찰 경매 응답 리스트
     */
    @Override
    public Page<LostAuctionResponse> findLostAuctionHistoryByUserId(Long userId, Pageable pageable) {
        JPAQuery<?> baseQuery = getActualParticipatedAuction(userId)
                .join(auction.product, product)
                .where(auction.winnerId.ne(userId)
                        .or(auction.winnerId.isNull().and(auction.status.eq(ENDED))));

        List<LostAuctionResponse> content = baseQuery
                .select(new QLostAuctionResponse(
                        auction.id,
                        product.name,
                        image.cdnPath,
                        product.minPrice,
                        auction.endDateTime,
                        bid.amount
                ))
                .leftJoin(image).on(image.product.eq(product).and(image.id.eq(getFirstImageId())))
                .groupBy(auction.id, product.name, image.cdnPath, product.minPrice, bid.amount)
                .orderBy(querydslOrderProvider.getOrderSpecifiers(pageable))
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        JPAQuery<Long> countQuery = baseQuery
                .select(auction.count());

        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchCount);
    }

    @Override
    public Optional<ParticipationCountsResponse> getParticipationCounts(Long userId) {
        DateTimeOperation<LocalDateTime> now = Expressions.dateTimeOperation(LocalDateTime.class, DateTimeOps.CURRENT_TIMESTAMP);

        BooleanExpression isEnded = auction.status.eq(ENDED)
                .and(auction.endDateTime.before(now));

        // 사용자가 참여한 경매 ID 목록을 가져옵니다.
        List<Long> participatedAuctionIds = jpaQueryFactory
                .select(auction.id)
                .from(auction)
                .join(auction.bids, bid)
                .where(bid.bidder.id.eq(userId)
                        .and(bid.status.eq(ACTIVE)))
                .fetch();

        if (participatedAuctionIds.isEmpty()) {
            return Optional.of(new ParticipationCountsResponse(0L, 0L, 0L));
        }

        // 진행 중인 경매 수
        Long proceedingCount = jpaQueryFactory
                .select(auction.count())
                .from(auction)
                .where(auction.id.in(participatedAuctionIds)
                        .and(auction.status.eq(PROCEEDING))
                        .and(auction.endDateTime.after(now)))
                .fetchOne();

        // 성공한 경매 수 (사용자가 낙찰자)
        Long successCount = jpaQueryFactory
                .select(auction.count())
                .from(auction)
                .where(auction.id.in(participatedAuctionIds)
                        .and(auction.winnerId.eq(userId))
                        .and(isEnded))
                .fetchOne();

        // 실패한 경매 수 (사용자가 낙찰자가 아님)
        Long failureCount = jpaQueryFactory
                .select(auction.count())
                .from(auction)
                .where(auction.id.in(participatedAuctionIds)
                        .and(auction.winnerId.ne(userId))
                        .and(isEnded))
                .fetchOne();

        return Optional.of(new ParticipationCountsResponse(
                proceedingCount != null ? proceedingCount : 0L,
                successCount != null ? successCount : 0L,
                failureCount != null ? failureCount : 0L
        ));
    }

    /**
     * @param userId 사용자 pk
     * @return 실제 사용자가 참여한 경매(취소된 입찰 제외)
     */
    private JPAQuery<?> getActualParticipatedAuction(Long userId) {
        return jpaQueryFactory
                .from(auction)
                .join(auction.bids, bid)
                .on(bid.bidder.id.eq(userId)
                        .and(bid.status.eq(ACTIVE)));
    }

    /**
     * 사용자가 참여 중인 경매 수를 조회합니다.
     *
     * @param userId 사용자 ID
     * @return 참여 중인 경매 수
     */
//    private JPQLQuery<Long> getOngoingAuctionCount(Long userId) {
//        return JPAExpressions
//                .select(auction.id.count())
//                .from(auction)
//                .join(auction.bids, bid)
//                .where(auction.status.eq(PROCEEDING)
//                        .and(bid.bidder.id.eq(userId))
//                        .and(bid.status.ne(BidStatus.CANCELLED)));
//    }

    /**
     * 사용자의 낙찰 성공 경매 수를 조회합니다.
     *
     * @param userId 사용자 ID
     * @return 낙찰 경매 수
     */
//    private JPQLQuery<Long> getSuccessfulAuctionCount(Long userId) {
//        return JPAExpressions
//                .select(auction.id.count())
//                .from(auction)
//                .where(auction.status.eq(ENDED)
//                        .and(auction.winnerId.eq(userId)));
//    }

    /**
     * 사용자의 낙찰 실패 경매 수를 조회합니다.
     *
     * @param userId 사용자 ID
     * @return 낙찰 실패 경매 수
     */
//    private JPQLQuery<Long> getFailedAuctionCount(Long userId) {
//        return JPAExpressions
//                .select(auction.id.count())
//                .from(auction)
//                .join(auction.bids, bid)
//                .where(auction.status.eq(ENDED)
//                        .and(auction.winnerId.ne(userId))
//                        .and(bid.bidder.id.eq(userId))
//                        .and(bid.status.ne(BidStatus.CANCELLED)));
//    }

    /**
     * 사용자의 낙찰 취소 경매 수를 조회합니다.
     *
     * @param userId 사용자 ID
     * @return 낙찰 취소 경매 수
     */
//    private JPQLQuery<Long> getEndedAuctionCount(Long userId) {
//        return JPAExpressions
//                .select(auction.countDistinct())
//                .from(auction)
//                .join(auction.bids, bid)
//                .where(auction.status.eq(ENDED)
//                        .and(bid.bidder.id.eq(userId))
//                        .and(bid.status.ne(BidStatus.CANCELLED)));
//    }

    /**
     * 상품의 첫 번째 이미지를 조회합니다.
     *
     * @return 첫 번째 이미지 ID
     */
    private JPQLQuery<Long> getFirstImageId() {
        QImage imageSub = new QImage("imageSub");
        return JPAExpressions.select(imageSub.id.min())
                .from(imageSub)
                .where(imageSub.product.id.eq(product.id));
    }

    /**
     * 사용자가 참여 중인 경매인지 확인합니다.
     *
     * @param userId 사용자 ID
     * @return 사용자가 참여 중인 경우 true, 그렇지 않으면 false
     */
    private BooleanExpression isParticipating(Long userId) {
        return JPAExpressions.selectOne()
                .from(bid)
                .where(bid.auction.id.eq(auction.id).and(bid.status.eq(ACTIVE).and(bidderIdEq(userId))))
                .exists();
    }

    /**
     * 경매 참여자 수를 조회합니다.
     *
     * @return 참여자 수
     */
    private JPQLQuery<Long> getBidCount() {
        return JPAExpressions
                .select(bid.count())
                .from(bid)
                .where(bid.auction.id.eq(auction.id).and(bid.status.eq(ACTIVE)));
    }

    /**
     * 상품의 이미지 리스트를 조회합니다.
     *
     * @param productId 상품 ID
     * @return 이미지 경로 리스트
     */
    private List<String> getImageList(Long productId) {
        return jpaQueryFactory.select(image.cdnPath)
                .from(image)
                .where(image.product.id.eq(productId))
                .fetch();
    }

    private static NumberExpression<Integer> timeRemaining() {
        return Expressions.numberTemplate(Integer.class,
                "GREATEST(0, TIMESTAMPDIFF(SECOND, CURRENT_TIMESTAMP, {0}))", auction.endDateTime); // 음수면 0으로 처리
    }

    private BooleanBuilder userIdEq(Long userId) {
        return nullSafeBuilder(() -> user.id.eq(userId));
    }

    private BooleanBuilder bidderIdEq(Long userId) {
        return nullSafeBuilder(() -> bid.bidder.id.eq(userId));
    }

    @Getter
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public enum AuctionOrder implements QuerydslOrder {
        POPULARITY("popularity", auction.bids.size().desc()),
        EXPENSIVE("expensive", product.minPrice.desc()),
        CHEAP("cheap", product.minPrice.asc()),
        NEWEST("newest", auction.createdAt.desc());

        private final String name;
        private final OrderSpecifier<?> orderSpecifier;
    }
}
