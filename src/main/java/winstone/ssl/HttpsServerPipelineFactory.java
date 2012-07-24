package winstone.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Enumeration;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.handler.ssl.SslHandler;
import winstone.*;

/**
 *
 * @author raymond.mak
 */
public class HttpsServerPipelineFactory extends HttpServerPipelineFactory {
    private static final WinstoneResourceBundle SSL_RESOURCES = new WinstoneResourceBundle("winstone.ssl.LocalStrings");
    
    private SSLContext sslContext;
    
    public HttpsServerPipelineFactory(
        String keystore,
        String password,
        String keyManagerType,
        HostGroup hostGroup,
        boolean doHostNameLookups,
        boolean simulateModUniqueId,
        ChannelGroup channelGroup) throws Exception {        
        super(hostGroup, doHostNameLookups, simulateModUniqueId, channelGroup);         
        sslContext = createSSLContext(keystore, password, keyManagerType);
    }
    
    static private SSLContext createSSLContext(
        String keystore, 
        String password, 
        String keyManagerType) throws Exception {
        
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(keyManagerType);
        final KeyStore ks = KeyStore.getInstance("JKS");
        File ksFile = new File(keystore);
        if (!ksFile.exists() || !ksFile.isFile()) {
            throw new WinstoneException(SSL_RESOURCES.getString("HttpsListener.KeyStoreNotFound", ksFile.getPath()));
        }
        char[] passwordChars = password.toCharArray();
        ks.load(new FileInputStream(ksFile), passwordChars);
        kmf.init(ks, passwordChars);
        Logger.log(Logger.FULL_DEBUG, SSL_RESOURCES,
                "HttpsListener.KeyCount", ks.size() + "");
        for (Enumeration e = ks.aliases(); e.hasMoreElements();) {
            String alias = (String) e.nextElement();
            Logger.log(Logger.FULL_DEBUG, SSL_RESOURCES,
                    "HttpsListener.KeyFound", new String[] { alias,
                            ks.getCertificate(alias) + "" });
        }
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);
        return sslContext;
    }
    
    @Override
    protected void configurePipeline(ChannelPipeline pipeline) throws Exception {
        SSLEngine sslEngine = sslContext.createSSLEngine();
        sslEngine.setUseClientMode(false);
        pipeline.addLast("ssl", new SslHandler(sslEngine));        
        super.configurePipeline(pipeline);
    }    
    
    @Override
    protected String getScheme() {
        return "https";        
    }
}
