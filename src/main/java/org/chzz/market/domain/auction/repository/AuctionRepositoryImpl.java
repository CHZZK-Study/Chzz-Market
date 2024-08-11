package org.chzz.market.domain.auction.repository;

import static org.chzz.market.domain.auction.entity.Auction.Status.ENDED;
import static org.chzz.market.domain.auction.entity.Auction.Status.PROCEEDING;
import static org.chzz.market.domain.auction.entity.QAuction.auction;
import static org.chzz.market.domain.auction.repository.AuctionRepositoryImpl.AuctionOrder.CHEAP;
import static org.chzz.market.domain.auction.repository.AuctionRepositoryImpl.AuctionOrder.EXPENSIVE;
import static org.chzz.market.domain.auction.repository.AuctionRepositoryImpl.AuctionOrder.NEWEST;
import static org.chzz.market.domain.bid.entity.QBid.bid;
import static org.chzz.market.domain.image.entity.QImage.image;
import static org.chzz.market.domain.product.entity.QProduct.product;
import static org.chzz.market.domain.user.entity.QUser.user;

import com.querydsl.core.types.OrderSpecifier;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.core.types.dsl.ComparableExpressionBase;
import com.querydsl.core.types.dsl.DateTimePath;
import com.querydsl.core.types.dsl.Expressions;
import com.querydsl.core.types.dsl.NumberExpression;
import com.querydsl.jpa.JPAExpressions;
import com.querydsl.jpa.JPQLQuery;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import java.util.List;
import java.util.Map;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.chzz.market.domain.auction.dto.AuctionDetailsResponse;
import org.chzz.market.common.util.QuerydslOrder;
import org.chzz.market.common.util.QuerydslOrderProvider;
import org.chzz.market.domain.auction.dto.AuctionResponse;
import org.chzz.market.domain.auction.dto.QAuctionDetailsResponse;
import org.chzz.market.domain.auction.dto.QAuctionResponse;
import org.chzz.market.domain.image.entity.QImage;
import org.chzz.market.domain.product.entity.Product.Category;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;

@RequiredArgsConstructor
public class AuctionRepositoryImpl implements AuctionRepositoryCustom {
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
                .leftJoin(bid).on(bid.auction.id.eq(auction.id))
                .where(auction.product.category.eq(category))
                .where(auction.status.eq(PROCEEDING));

        List<AuctionResponse> content = baseQuery
                .select(new QAuctionResponse(
                        auction.id,
                        product.name,
                        image.cdnPath,
                        timeRemaining().longValue(),
                        auction.minPrice.longValue(),
                        bid.countDistinct(),
                        isParticipating(userId)
                ))
                .leftJoin(image).on(image.product.id.eq(product.id).and(image.id.eq(getFirstImageId())))
                .groupBy(auction.id, product.name, image.cdnPath, auction.createdAt, auction.minPrice)
                .orderBy(querydslOrderProvider.getOrderSpecifiers(pageable))
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        JPAQuery<Long> countQuery = baseQuery
                .select(auction.id.count());
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
                        user.id,
                        user.nickname,
                        product.name,
                        product.description,
                        auction.minPrice,
                        auction.endDateTime,
                        auction.status,
                        user.id.eq(userId),
                        getBidCount(auctionId),
                        bid.id.isNotNull(),
                        bid.amount.coalesce(0L),
                        bid.count.coalesce(3)
                ))
                .from(auction)
                .join(auction.product, product)
                .join(product.user, user)
                .leftJoin(bid).on(bid.auction.id.eq(auctionId).and(bid.bidder.id.eq(userId)))
                .where(
                        auction.id.eq(auctionId)
                                .and(auction.status.eq(PROCEEDING).or(auction.status.eq(ENDED)))
                )
                .fetchOne());

        auctionDetailsResponse.ifPresent(response -> response.addImageList(getImageList(response.getProductId())));

        return auctionDetailsResponse;
    }


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
        return JPAExpressions.selectFrom(bid)
                .where(bid.auction.id.eq(auction.id).and(bid.bidder.id.eq(userId)))
                .exists();
    }

    /**
     * 경매 참여자 수를 조회합니다.
     *
     * @param auctionId 경매 ID
     * @return 참여자 수
     */
    private JPQLQuery<Long> getBidCount(Long auctionId) {
        return JPAExpressions.select(bid.count())
                .from(bid)
                .where(bid.auction.id.eq(auctionId));
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
        NumberExpression<Integer> created = auction.createdAt.second();
        NumberExpression<Integer> now = DateTimePath.currentDate().second();
        return created.add(Expressions.asNumber(24 * 60 * 60)).subtract(now);
    }

    /**
     * 정렬 조건에 따른 OrderSpecifier 반환
     * @deprecated
     * @return OrderSpecifier
     */
    private OrderSpecifier<?> getOrderSpecifier(AuctionOrder auctionOrder) {
        Map<AuctionOrder, OrderSpecifier<?>> orderSpecifierMap = Map.of(
                AuctionOrder.POPULARITY, bid.countDistinct().desc(),
                EXPENSIVE, auction.minPrice.desc(),
                CHEAP, auction.minPrice.asc(),
                NEWEST, auction.endDateTime.desc()
        );
        return orderSpecifierMap.getOrDefault(auctionOrder, auction.createdAt.desc());
    }

    @Getter
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public enum AuctionOrder implements QuerydslOrder {
        POPULARITY("popularity",auction.bids.size().multiply(-1)),
        EXPENSIVE("expensive",auction.minPrice.multiply(-1)),
        CHEAP("cheap",auction.minPrice),
        NEWEST("newest",timeRemaining());

        private final String name;
        private final ComparableExpressionBase<?> comparableExpressionBase;
    }
}
