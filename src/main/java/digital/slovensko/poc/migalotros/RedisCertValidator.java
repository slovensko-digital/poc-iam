package digital.slovensko.poc.migalotros;

import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.crypto.PasswordEncryptor;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Properties;
import java.util.regex.Pattern;

/**
 * Certificate validator that verifies certificate public key digests against a Redis allowlist.
 * Only certificates with public key digests registered in Redis are trusted.
 */
public class RedisCertValidator extends Merlin {

    public static final String REDIS_TEMPLATE_REF = "redis.bean";

    private final StringRedisTemplate stringRedisTemplate;

    public RedisCertValidator() throws WSSecurityException, java.io.IOException {
        this(new Properties(), null, null);
    }

    public RedisCertValidator(Properties properties, ClassLoader loader, PasswordEncryptor passwordEncryptor)
            throws WSSecurityException, java.io.IOException {
        super(properties, loader, passwordEncryptor);
        this.stringRedisTemplate = (StringRedisTemplate) properties.get(REDIS_TEMPLATE_REF);
    }

    @Override
    public void verifyTrust(X509Certificate[] certs, boolean enableRevocation,
                            Collection<Pattern> subjectDNPatterns,
                            Collection<Pattern> issuerDNPatterns) throws WSSecurityException {
        if (certs == null || certs.length == 0) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.SECURITY_ERROR, "Certificate not provided");
        }
        if (certs.length != 1) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.SECURITY_ERROR, "Too many certificates provided, expected exactly one");
        }
        try {
            X509Certificate cert = certs[0];
            cert.checkValidity();

            // Calculate SHA-256 digest of public key
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] publicKeyBytes = cert.getPublicKey().getEncoded();
            byte[] digest = md.digest(publicKeyBytes);

            // Convert to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : digest) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            String publicKeyDigest = hexString.toString();

            String key = "cert:digest:" + publicKeyDigest;
            String value = stringRedisTemplate.opsForValue().get(key);

            if (value == null) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.SECURITY_ERROR,
                        "Certificate not registered. Public Key Digest: " + publicKeyDigest
                );
            }
        } catch (WSSecurityException e) {
            throw e;
        } catch (Exception e) {
            WSSecurityException wse = new WSSecurityException(
                    WSSecurityException.ErrorCode.SECURITY_ERROR,
                    "Certificate verification failed: " + e.getMessage()
            );
            wse.initCause(e);
            throw wse;
        }
    }
}
