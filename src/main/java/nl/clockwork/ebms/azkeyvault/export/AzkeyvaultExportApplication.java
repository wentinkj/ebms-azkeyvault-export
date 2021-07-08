package nl.clockwork.ebms.azkeyvault.export;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.apache.commons.lang3.tuple.Triple;
import org.apache.logging.log4j.util.Strings;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.CertificateProperties;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;

@SpringBootApplication
public class AzkeyvaultExportApplication implements ApplicationRunner {
	private static Logger log = LoggerFactory.getLogger(AzkeyvaultExportApplication.class);
	
	public static void main(String[] args) {
		log.info("export start");
		SpringApplication.run(AzkeyvaultExportApplication.class, args);
		log.info("export end");
	}
	
	/**
	 * simple check and value return of commandline option
	 * 
	 * @param args
	 * @param name
	 * @param description
	 * @return
	 */
	private Optional<String> getCmdOption(ApplicationArguments args, String name) {
		if (args.containsOption(name))
			return Optional.ofNullable(args.getOptionValues(name).get(0));

		return Optional.empty();
	}
	
	/**
	 * 
	 *
	 */
	@Override
	public void run(ApplicationArguments args) throws Exception {
		String url = getCmdOption (args, "url")
				.orElseThrow(() -> new IllegalArgumentException("keyvault url missing"));
		String tennantid = getCmdOption(args, "tennantid")
				.orElseThrow(() -> new IllegalArgumentException("keyvault tennant id missing"));
		String clientid = getCmdOption(args, "clientid")
				.orElseThrow(() -> new IllegalArgumentException("keyvault client id missing"));
		String clientsecret = getCmdOption(args, "clientsecret")
				.orElseThrow(() -> new IllegalArgumentException("keyvault client secret missing"));
		String certname = getCmdOption(args, "name")
				.orElse(Strings.EMPTY);
		String keystore = getCmdOption(args, "keystore")
				.orElseThrow(() -> new IllegalArgumentException("keystore file missing"));
		String password = getCmdOption(args, "password")
				.orElseThrow(() -> new IllegalArgumentException("keystore password missing"));

		runExport(certname, url, tennantid, clientid, clientsecret, keystore, password);
	}
	
	
	public static Triple<String, Key, Certificate[]> exportCertificate(CertificateProperties cp, CertificateClient cc, SecretClient sc) {
		
        log.info("Export certificate with name {}, version {}", cp.getName(), cp.getVersion());

        KeyVaultCertificateWithPolicy kvcert = cc.getCertificate(cp.getName());
        KeyVaultSecret secret = sc.getSecret(kvcert.getName(), kvcert.getProperties().getVersion());
        log.debug("cert type is {}", secret.getProperties().getContentType() );
        try {
        	if ( "application/x-pkcs12".equalsIgnoreCase(secret.getProperties().getContentType()) )
        		return secretToKey(cp.getName(), secret.getValue());
        	if ( "application/x-pem-file".equalsIgnoreCase(secret.getProperties().getContentType()) )
        		return pemToKey(cp.getName(), secret.getValue());
        } catch (UnrecoverableKeyException e) {
        	log.error("certificate export failed", e);
		}
		
		return null;
	}
	
	public static void addToKeyStore(KeyStore ks, String password, Triple<String, Key, Certificate[]> cert) {
		try {
			ks.setKeyEntry(cert.getLeft(), cert.getMiddle(), password.toCharArray(), cert.getRight());
		} catch (KeyStoreException e) {
			log.error("failed to store certificate with alias {}", cert.getLeft());
		}
	}
	
	/**
	 * 
	 * loop through certificates in keyvault and export them to pcks12 keystore
	 * 
	 */
	void runExport(String name, String url, String tennantid, String clientid, String clientsecret, String keystore, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		ClientSecretCredential clientSecretCredential = new ClientSecretCredentialBuilder()
	            .clientId(clientid)
	            .clientSecret(clientsecret)
	            .tenantId(tennantid)
	            .build();
		CertificateClient certificateClient = new CertificateClientBuilder()
			    .vaultUrl(url)
			    .credential(clientSecretCredential)
			    .buildClient();
		SecretClient secretClient = new SecretClientBuilder()
			    .vaultUrl(url)
			    .credential(clientSecretCredential)
			    .buildClient();

		KeyStore ksout = KeyStore.getInstance("PKCS12");
		ksout.load(null,null);
		
		certificateClient.listPropertiesOfCertificates().stream()
			.filter(c -> c.isEnabled())
			.filter(c -> name.isEmpty() || c.getName().contentEquals(name))
			.map(c -> exportCertificate(c, certificateClient, secretClient) )
			.forEach(c -> addToKeyStore(ksout, password, c) );
		
		log.info("writing to {}", keystore);
		try (FileOutputStream fos = new FileOutputStream(new File(keystore)) ) {
			ksout.store(fos, password.toCharArray());
		};
	}
	

	/**
	 * convert pem found in secret to (private)key and public cert as chain
	 * 
	 * @param secret
	 * @return
	 * @throws UnrecoverableKeyException
	 */
	private static Triple<String, Key, Certificate[]> pemToKey(String alias, String secret) throws UnrecoverableKeyException {
		List<Certificate> pubcerts = new ArrayList<Certificate>();
		Key privatekey = null;
		
		try {
			PEMParser parser = new PEMParser(new StringReader(secret));
			Object readObject;
            while ((readObject = parser.readObject()) != null) {
            	log.debug("object {}", readObject.getClass());
            	
                if (readObject instanceof PrivateKeyInfo) {
                	privatekey = new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) readObject);
                } else if (readObject instanceof X509CertificateHolder) {
                	X509CertificateHolder certholder = (X509CertificateHolder) readObject;
                	pubcerts.add( (new JcaX509CertificateConverter()).getCertificate(certholder) );
                }
            }
		} catch (Exception e) {
			throw new UnrecoverableKeyException("Unable to extract key");
		}
		
		return Triple.of(alias, privatekey, pubcerts.toArray(new Certificate[pubcerts.size()]));
	}
	
	
	/**
	 * convert x509 key in secret to (private)key and public cert as chain
	 * 
	 * @param secret
	 * @return
	 * @throws UnrecoverableKeyException
	 */
	private static Triple<String, Key, Certificate[]> secretToKey(String alias, String secret) throws UnrecoverableKeyException {
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			
			ks.load(new ByteArrayInputStream(Base64.getDecoder().decode(secret)), "".toCharArray());
			String generatedAlias = ks.aliases().nextElement();
			ks.getCertificateChain(generatedAlias);

			return Triple.of(alias, ks.getKey(generatedAlias, "".toCharArray()), ks.getCertificateChain(generatedAlias));
		} catch (Exception e) {
			throw new UnrecoverableKeyException("Unable to extract key");
		}
	}
}
