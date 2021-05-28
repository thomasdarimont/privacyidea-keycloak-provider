package org.privacyidea.authenticator;

import org.jboss.logging.Logger;
import org.privacyidea.IPILogger;
import org.privacyidea.PIResponse;
import org.privacyidea.PrivacyIDEA;
import org.privacyidea.RolloutInfo;
import org.privacyidea.TokenInfo;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.privacyidea.authenticator.Const.PLUGIN_USER_AGENT;

public class PrivacyIdeaClient {

    private static final Logger logger = Logger.getLogger(PrivacyIdeaClient.class);

    private final Configuration config;
    private final PrivacyIDEA privacyIDEA;

    public PrivacyIdeaClient(Configuration config, PrivacyIDEA privacyIDEA) {
        this.config = config;
        this.privacyIDEA = privacyIDEA;
    }

    public static PrivacyIdeaClient createClient(Map<String, String> authenticatorConfig) {
        Configuration config = new Configuration(authenticatorConfig);

        PrivacyIDEA privacyIdea = PrivacyIDEA.newBuilder(config.serverURL(), PLUGIN_USER_AGENT)
                .sslVerify(config.sslVerify())
                .logger(new PiiLoggerAdapter(config))
                .pollingIntervals(config.pollingInterval())
                .realm(config.realm())
                .serviceAccount(config.serviceAccountName(), config.serviceAccountPass())
                .serviceRealm(config.serviceAccountRealm())
                .build();
        privacyIdea.logExcludedEndpoints(Collections.emptyList());

        return new PrivacyIdeaClient(config, privacyIdea);
    }

    public PIResponse triggerChallenges(String username, Map<String,String> headers) {
        return privacyIDEA.triggerChallenges(username, headers);
    }

    public PIResponse validateCheck(String username, String currentPassword, String transactionId, Map<String,String> headers) {
        return privacyIDEA.validateCheck(username, currentPassword, transactionId, headers);
    }

    public PIResponse validateCheckWebAuthn(String username, String transactionId, String webAuthnSignResponse, String origin, Map<String,String> headers) {
        return privacyIDEA.validateCheckWebAuthn(username, transactionId, webAuthnSignResponse, origin, headers);
    }

    public List<TokenInfo> getTokenInfo(String username) {
        List<TokenInfo> tokenInfos = privacyIDEA.getTokenInfo(username);
        return tokenInfos;
    }

    public RolloutInfo tokenRollout(String username, String tokenType) {
        RolloutInfo rolloutInfo = privacyIDEA.tokenRollout(username, tokenType);
        return rolloutInfo;
    }

    public boolean pollTransaction(String transactionID) {
        return privacyIDEA.pollTransaction(transactionID);
    }

    public Configuration getConfig() {
        return config;
    }

    public PrivacyIDEA getPrivacyIDEA() {
        return privacyIDEA;
    }

    static class PiiLoggerAdapter implements IPILogger {

        private final Configuration config;

        public PiiLoggerAdapter(Configuration config) {
            this.config = config;
        }

        // IPILogger implementation
        @Override
        public void log(String message) {
            if (config.doLog()) {
                logger.info(message);
            }
        }

        @Override
        public void error(String message) {
            if (config.doLog()) {
                logger.error(message);
            }
        }

        @Override
        public void log(Throwable t) {
            if (config.doLog()) {
                logger.info("Exception:", t);
            }
        }

        @Override
        public void error(Throwable t) {
            if (config.doLog()) {
                logger.error("Exception:", t);
            }
        }
    }
}
