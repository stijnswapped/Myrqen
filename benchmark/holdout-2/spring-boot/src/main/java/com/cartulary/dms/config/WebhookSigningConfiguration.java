package com.cartulary.dms.config;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import jakarta.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.Assert;

import com.cartulary.dms.webhooks.WebhookSigner;
import com.cartulary.dms.webhooks.WebhookVerifier;

/**
 * HMAC signing for outbound webhooks.
 *
 * Subscribers verify the X-Cartulary-Signature header against this key, so a deployment that
 * signs with a value anybody can read is a deployment where anybody can forge a "document
 * approved" event into a customer's workflow engine.
 */
@Configuration
public class WebhookSigningConfiguration {

    private static final Logger log = LoggerFactory.getLogger(WebhookSigningConfiguration.class);

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private static final int MIN_KEY_BYTES = 32;

    /**
     * The literal printed in docs/self-hosting/example.env, so operators can see the shape
     * they need to generate. It appears here for one reason: to be rejected. A deployment
     * still carrying it has not been configured, and booting anyway would sign real webhooks
     * with a value that is in the public documentation.
     */
    private static final String DOCUMENTED_EXAMPLE_KEY = "Rk9SLUVYQU1QTEUtT05MWS1ETy1OT1QtU0hJUC1USElT";

    @Value("${cartulary.webhooks.signing-key}")
    private String signingKey;

    @Value("${cartulary.webhooks.timeout:PT10S}")
    private Duration deliveryTimeout;

    @PostConstruct
    void rejectUnconfiguredKey() {
        Assert.hasText(signingKey, "cartulary.webhooks.signing-key must be set");
        if (DOCUMENTED_EXAMPLE_KEY.equals(signingKey.trim())) {
            throw new IllegalStateException(
                    "cartulary.webhooks.signing-key is still the example value from example.env; "
                            + "generate one with: openssl rand -base64 32");
        }
        byte[] key = Base64.getDecoder().decode(signingKey.getBytes(StandardCharsets.UTF_8));
        if (key.length < MIN_KEY_BYTES) {
            throw new IllegalStateException("cartulary.webhooks.signing-key must decode to at least 32 bytes");
        }
    }

    @Bean
    WebhookSigner webhookSigner() {
        byte[] key = Base64.getDecoder().decode(signingKey.getBytes(StandardCharsets.UTF_8));
        log.info("webhook signer ready, delivery timeout {}", deliveryTimeout);
        return new WebhookSigner(new SecretKeySpec(key, HMAC_ALGORITHM), deliveryTimeout);
    }

    @Bean
    WebhookVerifier webhookVerifier(WebhookSigner signer) {
        return new WebhookVerifier(signer);
    }
}
