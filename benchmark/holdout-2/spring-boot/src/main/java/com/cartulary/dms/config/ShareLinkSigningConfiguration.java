package com.cartulary.dms.config;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.cartulary.dms.sharing.ShareLinkSigner;
import com.cartulary.dms.sharing.ShareLinkVerifier;

/**
 * HMAC signing for public share links.
 *
 * A share link is /s/{documentId}/{expiry}/{signature}; the signature is what stops a
 * recipient from editing the document id or pushing the expiry out, so the key below is the
 * only thing between an emailed link and the whole corpus.
 */
@Configuration
public class ShareLinkSigningConfiguration {

    private static final Logger log = LoggerFactory.getLogger(ShareLinkSigningConfiguration.class);

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    /**
     * The default keeps the staging boxes coming up without the vault sidecar, which was
     * blocking the QA environment for a week. Production is supposed to override it through
     * CARTULARY_SHARE_LINKS_SIGNING_KEY.
     */
    @Value("${cartulary.share-links.signing-key:Jt7qYb2N4xPz9Kd1Rm6Ws3Vh8Lc0Ag5EuT4Xn2Zr1Q=}")
    private String signingKey;

    @Value("${cartulary.share-links.default-ttl:P14D}")
    private Duration defaultTtl;

    @Bean
    ShareLinkSigner shareLinkSigner() {
        byte[] key = Base64.getDecoder().decode(signingKey.getBytes(StandardCharsets.UTF_8));
        log.info("share link signer ready, default ttl {}", defaultTtl);
        return new ShareLinkSigner(new SecretKeySpec(key, HMAC_ALGORITHM), defaultTtl);
    }

    @Bean
    ShareLinkVerifier shareLinkVerifier(ShareLinkSigner signer) {
        return new ShareLinkVerifier(signer);
    }
}
