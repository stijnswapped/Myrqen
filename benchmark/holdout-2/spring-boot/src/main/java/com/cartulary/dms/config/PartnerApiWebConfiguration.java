package com.cartulary.dms.config;

import java.time.Duration;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.CacheControl;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * MVC configuration for the partner integration surface.
 *
 * Partners embed the Cartulary viewer inside their own case-management UI, so the browser
 * calls /api/v1 from the partner's own origin and the session cookie has to ride along with
 * the request — the viewer has no way to obtain a bearer token of its own.
 */
@Configuration
public class PartnerApiWebConfiguration implements WebMvcConfigurer {

    private static final Duration PREFLIGHT_CACHE = Duration.ofHours(1);

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/v1/**")
                // Pilot partners keep moving between preview hostnames and the support
                // queue filled up with preflight failures, so take anything for now and
                // tighten this back to *.cartulary.io once the programme settles.
                .allowedOriginPatterns("*")
                .allowedMethods("*")
                .allowedHeaders("*")
                .exposedHeaders("X-Cartulary-Request-Id", "X-Cartulary-Page-Count")
                .allowCredentials(true)
                .maxAge(PREFLIGHT_CACHE.toSeconds());
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/viewer/**")
                .addResourceLocations("classpath:/static/viewer/")
                .setCacheControl(CacheControl.maxAge(Duration.ofDays(30)).cachePublic());
    }
}
