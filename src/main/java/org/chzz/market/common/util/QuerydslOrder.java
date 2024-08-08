package org.chzz.market.common.util;

import com.querydsl.core.types.OrderSpecifier;
import com.querydsl.core.types.dsl.ComparableExpressionBase;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.chzz.market.common.error.GlobalErrorCode;
import org.chzz.market.common.error.GlobalException;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort.Order;

public interface QuerydslOrder {
    String getName();

    ComparableExpressionBase<?> getComparableExpressionBase();

    static Optional<QuerydslOrder> getByName(String name, Class<? extends QuerydslOrder> clazz) {
        try {
            QuerydslOrder[] enumConstants = clazz.getEnumConstants();
            if (enumConstants != null) {
                for (QuerydslOrder enumConstant : enumConstants) {
                    Field nameField = enumConstant.getClass().getDeclaredField("name");
                    nameField.setAccessible(true);
                    String enumName = (String) nameField.get(enumConstant);
                    if (enumName.equals(name)) {
                        return Optional.of(enumConstant);
                    }
                }
            }
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new GlobalException(GlobalErrorCode.INTERNAL_SERVER_ERROR);
        }
        return Optional.empty();
    }

    ;


    static OrderSpecifier[] getOrderSpecifiers(Pageable pageable, Class<? extends QuerydslOrder> clazz) {
        List<OrderSpecifier<?>> orderSpecifiers = new ArrayList<>();
        if (!pageable.getSort().isEmpty()) {
            for (Order order : pageable.getSort()) {
                com.querydsl.core.types.Order direction =
                        order.getDirection().isAscending()
                                ? com.querydsl.core.types.Order.ASC
                                : com.querydsl.core.types.Order.DESC;

                getByName(order.getProperty(), clazz).ifPresent(querydslOrder ->
                        orderSpecifiers
                                .add(new OrderSpecifier<>(direction, querydslOrder.getComparableExpressionBase())));
            }
        } else {
            orderSpecifiers.add(OrderByNull.DEFAULT);
        }
        return orderSpecifiers.toArray(OrderSpecifier[]::new);
    }
}