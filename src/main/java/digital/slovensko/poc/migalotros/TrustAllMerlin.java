package digital.slovensko.poc.migalotros;

import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.crypto.PasswordEncryptor;
import org.apache.wss4j.common.ext.WSSecurityException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Properties;
import java.util.regex.Pattern;

/**
 * A custom Merlin provider that trusts any certificate presented to it.
 * Use this ONLY for development/POC with self-signed certificates.
 */
public class TrustAllMerlin extends Merlin {
    public TrustAllMerlin(Properties properties, ClassLoader loader, PasswordEncryptor encryptor)
            throws WSSecurityException, java.io.IOException {
        super(properties, loader, encryptor);
    }

    @Override
    public void verifyTrust(X509Certificate[] certs, boolean enableRevocation,
                            Collection<Pattern> subjectDNPatterns,
                            Collection<Pattern> issuerDNPatterns) throws WSSecurityException {
        // Just return. No exception means the trust is verified.
        // TODO: validate against registered certificates in redis
        System.out.println(">>> TrustAllMerlin: Bypassing trust check for cert: "
                + certs[0].getSubjectX500Principal());
    }
}
