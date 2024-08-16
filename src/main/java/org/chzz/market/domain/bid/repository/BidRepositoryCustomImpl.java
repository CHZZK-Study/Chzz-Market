package org.chzz.market.domain.bid.repository;

import static org.chzz.market.domain.auction.entity.QAuction.auction;
import static org.chzz.market.domain.bid.entity.QBid.bid;
import static org.chzz.market.domain.image.entity.QImage.image;
import static org.chzz.market.domain.product.entity.QProduct.product;

import com.querydsl.core.types.dsl.ComparableExpressionBase;
import com.querydsl.core.types.dsl.DateTimePath;
import com.querydsl.core.types.dsl.Expressions;
import com.querydsl.core.types.dsl.NumberExpression;
import com.querydsl.jpa.JPAExpressions;
import com.querydsl.jpa.JPQLQuery;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import java.util.List;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.chzz.market.common.util.QuerydslOrder;
import org.chzz.market.common.util.QuerydslOrderProvider;
import org.chzz.market.domain.bid.dto.query.BiddingRecord;
import org.chzz.market.domain.bid.dto.query.QBiddingRecord;
import org.chzz.market.domain.image.entity.QImage;
import org.chzz.market.domain.user.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;

@RequiredArgsConstructor
public class BidRepositoryCustomImpl implements BidRepositoryCustom {
    private final JPAQueryFactory jpaQueryFactory;
    private final QuerydslOrderProvider querydslOrderProvider;

    public Page<BiddingRecord> findUsersBidHistory(User user, Pageable pageable) {
        QImage firstImage = new QImage("firstImage");

        JPQLQuery<BiddingRecord> baseQuery = getBaseQuery(firstImage, user);
        List<BiddingRecord> content = baseQuery
                .orderBy(querydslOrderProvider.getOrderSpecifiers(pageable))
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        return PageableExecutionUtils.getPage(content, pageable, getCount(user)::fetchOne);
    }

    private JPQLQuery<BiddingRecord> getBaseQuery(QImage firstImage, User user) {
        return jpaQueryFactory
                .select(new QBiddingRecord(
                        product.name,
                        product.minPrice.longValue(),
                        bid.amount,
                        auction.bids.size().longValue(),
                        firstImage.cdnPath,
                        timeRemaining().longValue()
                ))
                .from(bid)
                .join(bid.auction, auction)
                .on(bid.bidder.eq(user))
                .leftJoin(auction.product, product)
                .leftJoin(firstImage)
                .on(firstImage.product.eq(product).and(firstImage.id.eq(
                        JPAExpressions
                                .select(image.id.min())
                                .from(image)
                                .where(image.product.eq(product))
                )))
                .groupBy(product.name,
                        product.minPrice,
                        bid.amount,
                        auction.bids.size(),
                        firstImage.cdnPath,
                        auction.createdAt,
                        auction.id);
    }

    private JPAQuery<Long> getCount(User user) {
        return jpaQueryFactory
                .select(bid.count())
                .from(bid)
                .join(bid.auction, auction)
                .on(bid.bidder.eq(user));
    }


    private static NumberExpression<Integer> timeRemaining() {
        NumberExpression<Integer> created = auction.createdAt.second();
        NumberExpression<Integer> now = DateTimePath.currentDate().second();
        return created.add(Expressions.asNumber(24 * 60 * 60)).subtract(now);
    }

    @Getter
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public enum BidOrder implements QuerydslOrder {
        AMOUNT("amount", bid.amount),
        TIME_REMAINING("time remaining", timeRemaining().multiply(-1));

        private final String name;
        private final ComparableExpressionBase<?> comparableExpressionBase;
    }
}
