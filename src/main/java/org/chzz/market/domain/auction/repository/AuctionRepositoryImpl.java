package org.chzz.market.domain.auction.repository;

import static org.chzz.market.common.util.QueryDslUtil.getOrderSpecifiers;
import static org.chzz.market.domain.auction.entity.Auction.Status.ENDED;
import static org.chzz.market.domain.auction.entity.Auction.Status.PROCEEDING;
import static org.chzz.market.domain.auction.entity.QAuction.auction;
import static org.chzz.market.domain.auction.entity.SortType.CHEAP;
import static org.chzz.market.domain.auction.entity.SortType.EXPENSIVE;
import static org.chzz.market.domain.auction.entity.SortType.NEWEST;
import static org.chzz.market.domain.auction.entity.SortType.POPULARITY;
import static org.chzz.market.domain.bid.entity.QBid.bid;
import static org.chzz.market.domain.image.entity.QImage.image;
import static org.chzz.market.domain.product.entity.QProduct.product;
import static org.chzz.market.domain.user.entity.QUser.user;

import com.querydsl.core.types.OrderSpecifier;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.JPAExpressions;
import com.querydsl.jpa.JPQLQuery;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.chzz.market.domain.auction.dto.response.AuctionDetailsResponse;
import org.chzz.market.domain.auction.dto.response.AuctionResponse;
import org.chzz.market.domain.auction.dto.response.MyAuctionResponse;
import org.chzz.market.domain.auction.dto.response.QAuctionDetailsResponse;
import org.chzz.market.domain.auction.dto.response.QAuctionResponse;
import org.chzz.market.domain.auction.dto.response.QMyAuctionResponse;
import org.chzz.market.domain.auction.entity.Auction.Status;
import org.chzz.market.domain.auction.entity.SortType;
import org.chzz.market.domain.image.entity.QImage;
import org.chzz.market.domain.product.entity.Product.Category;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;

@RequiredArgsConstructor
public class AuctionRepositoryImpl implements AuctionRepositoryCustom {
    private final JPAQueryFactory jpaQueryFactory;

    @Override
    public Page<AuctionResponse> findAuctionsByCategory(Category category, SortType sortType, Long userId,
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
                        auction.endDateTime,
                        auction.minPrice,
                        bid.countDistinct(),
                        isParticipating(userId)
                ))
                .leftJoin(image).on(image.product.id.eq(product.id).and(image.id.eq(getFirstImageId())))
                .groupBy(auction.id, product.name, image.cdnPath, auction.endDateTime, auction.minPrice)
                .orderBy(getOrderSpecifier(sortType))
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        JPAQuery<Long> countQuery = baseQuery
                .select(auction.count());
        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchCount);
    }

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
                        getBidCount(),
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

    @Override
    public Page<MyAuctionResponse> findAuctionsByUserId(Long userId, Pageable pageable) {
        JPAQuery<?> baseQuery = jpaQueryFactory.from(auction)
                .join(auction.product, product)
                .join(product.user, user)
                .where(auction.status.ne(Status.CANCELLED)
                        .and(user.id.eq(userId)));

        List<MyAuctionResponse> content = baseQuery
                .select(new QMyAuctionResponse(
                        auction.id,
                        product.name,
                        image.cdnPath,
                        auction.endDateTime,
                        auction.minPrice,
                        getBidCount(),
                        auction.status,
                        auction.createdAt))
                .join(image).on(image.product.id.eq(product.id)
                        .and(image.id.eq(getFirstImageId())))
                .orderBy(getOrderSpecifiers(auction, pageable.getSort()))
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        JPAQuery<Long> countQuery = baseQuery
                .select(auction.count());

        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchCount);
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
     * 정렬 조건에 따른 OrderSpecifier를 반환합니다.
     *
     * @param sortType 정렬 조건
     * @return OrderSpecifier 객체
     */
    private OrderSpecifier<?> getOrderSpecifier(SortType sortType) {
        Map<SortType, OrderSpecifier<?>> orderSpecifierMap = Map.of(
                POPULARITY, bid.countDistinct().desc(),
                EXPENSIVE, auction.minPrice.desc(),
                CHEAP, auction.minPrice.asc(),
                NEWEST, auction.endDateTime.desc()
        );
        return orderSpecifierMap.getOrDefault(sortType, auction.endDateTime.desc());
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
                .where(bid.auction.id.eq(auction.id));
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
}
