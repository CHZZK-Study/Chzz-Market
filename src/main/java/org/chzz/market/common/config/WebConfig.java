package org.chzz.market.common.config;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.chzz.market.common.util.StringToEnumConverterFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {

    private static final String API_V1 = "/api/v1";

    private final StringToEnumConverterFactory stringToEnumConverterFactory;
    private final CustomPageableHandlerMethodArgumentResolver customSortHandlerMethodArgumentResolver;


    @Override
    public void addFormatters(final FormatterRegistry registry) {
        registry.addConverterFactory(stringToEnumConverterFactory);
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(customSortHandlerMethodArgumentResolver);
    }

    @Override
    public void configurePathMatch(PathMatchConfigurer configurer) {
        configurer.addPathPrefix(API_V1, c -> c.isAnnotationPresent(RestController.class));
    }
}
