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
import java.util.Base64;

import org.apache.commons.lang3.tuple.ImmutablePair;
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
	private String getRequiredOptionString(ApplicationArguments args, String name, String description) {
		if (args.containsOption(name)) {
			return args.getOptionValues(name).get(0);
		} else {
			log.error("missing argument --{} : {}", name, description);
		}
		
		return null;
	}
	
	/**
	 * 
	 *
	 */
	@Override
	public void run(ApplicationArguments args) throws Exception {
		String url = getRequiredOptionString(args, "url", "azure keyvault url");
		String tennantid = getRequiredOptionString(args, "tennantid", "azure tennant id");
		String clientid = getRequiredOptionString(args, "clientid", "azure keyvault url");
		String clientsecret = getRequiredOptionString(args, "clientsecret", "azure keyvault client id");
		String keystore = getRequiredOptionString(args, "keystore", "keystore file (including path)");
		String password = getRequiredOptionString(args, "password", "password to set on keystore and private certificates");

		if (url == null || tennantid == null || clientid == null || clientsecret == null || keystore == null || password == null)
			log.error("not executing");
		else
			runExport(url, tennantid, clientid, clientsecret, keystore, password);
	}
	
	/**
	 * 
	 * loop through certificates in keyvault and export them to pcks12 keystore
	 * 
	 * @param url
	 * @param tennantid
	 * @param clientid
	 * @param clientsecret
	 * @param keystore
	 * @param password
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	void runExport(String url, String tennantid, String clientid, String clientsecret, String keystore, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
//	    ManagedIdentityCredential managedIdentityCredential = new ManagedIdentityCredentialBuilder()
//	            .clientId("<USER ASSIGNED MANAGED IDENTITY CLIENT ID>") // only required for user assigned
//	            .build();
	
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
		
		for (CertificateProperties certificate : certificateClient.listPropertiesOfCertificates()) {
            log.info("Export certificate with name {}, version {}", certificate.getName(), certificate.getVersion());

            String alias = certificate.getName();
	        KeyVaultCertificateWithPolicy kvcert = certificateClient.getCertificate(alias);
	        
	        KeyVaultSecret secret = secretClient.getSecret(kvcert.getName(), kvcert.getProperties().getVersion());
	        log.debug("cert type is {}", secret.getProperties().getContentType() );
	        try {
	        	ImmutablePair<Key, Certificate[]> privkey = null;
	        	if ( "application/x-pkcs12".equalsIgnoreCase(secret.getProperties().getContentType()) )
	        		privkey = secretToKey(secret.getValue());
	        	if ( "application/x-pem-file".equalsIgnoreCase(secret.getProperties().getContentType()) )
	        		privkey = pemToKey(secret.getValue());
				ksout.setKeyEntry(alias, privkey.getLeft(), password.toCharArray(), privkey.getRight());
	        } catch (UnrecoverableKeyException e) {
	        	log.error("certificate export failed", e);
			} catch (KeyStoreException e) {
				log.error("certificate import in keystore failed", e);
			}
        }

		log.info("writing to {}", keystore);
        FileOutputStream fos = new FileOutputStream(new File(keystore));
		ksout.store(fos, password.toCharArray());
		fos.flush();
		fos.close();
	}
	

	/**
	 * convert pem found in secret to (private)key and public cert as chain
	 * 
	 * @param secret
	 * @return
	 * @throws UnrecoverableKeyException
	 */
	private ImmutablePair<Key, Certificate[]> pemToKey(String secret) throws UnrecoverableKeyException {
		Certificate[] pubcerts = new Certificate[1];
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
                	pubcerts[0] = (new JcaX509CertificateConverter()).getCertificate(certholder);
                }
            }
		} catch (Exception e) {
			throw new UnrecoverableKeyException("Unable to extract key");
		}
		
		return ImmutablePair.of(privatekey, pubcerts);
	}
	
	
	/**
	 * convert x509 key in secret to (private)key and public cert as chain
	 * 
	 * @param secret
	 * @return
	 * @throws UnrecoverableKeyException
	 */
	private ImmutablePair<Key, Certificate[]> secretToKey(String secret) throws UnrecoverableKeyException {
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			
			ks.load(new ByteArrayInputStream(Base64.getDecoder().decode(secret)), "".toCharArray());
			String generatedAlias = ks.aliases().nextElement();

			return ImmutablePair.of(ks.getKey(generatedAlias, "".toCharArray()), ks.getCertificateChain(generatedAlias));
		} catch (Exception e) {
			throw new UnrecoverableKeyException("Unable to extract key");
		}
	}
}
