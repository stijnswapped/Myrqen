package com.cartulary.dms.config;

import java.time.Duration;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.CacheControl;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * MVC configuration for the public catalogue.
 *
 * /api/v1/public/** is the only anonymous surface in the product: the record-class
 * dictionary, the retention-schedule glossary and the supported MIME types. It is
 * permitAll() in ApiSecurityConfiguration and no filter on that path ever reads a cookie or
 * an Authorization header, so any origin is welcome to read it — customers embed the
 * glossary in their own intranets and we do not want to maintain their origin list.
 *
 * Credentials are switched off explicitly rather than left to the default, because that is
 * the property which makes the wildcard above safe: without it the browser will not attach
 * the session cookie, so a page on any origin can only ever read what an anonymous curl
 * would have read anyway.
 */
@Configuration
public class PublicCatalogWebConfiguration implements WebMvcConfigurer {

    private static final Duration PREFLIGHT_CACHE = Duration.ofHours(24);

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/v1/public/**")
                .allowedOrigins("*")
                .allowedMethods("GET", "HEAD")
                .allowedHeaders("Accept", "Accept-Language", "If-None-Match")
                .exposedHeaders("ETag")
                .allowCredentials(false)
                .maxAge(PREFLIGHT_CACHE.toSeconds());
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/glossary/**")
                .addResourceLocations("classpath:/static/glossary/")
                .setCacheControl(CacheControl.maxAge(Duration.ofDays(30)).cachePublic());
    }
}
