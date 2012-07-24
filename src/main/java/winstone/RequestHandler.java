package winstone;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.*;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;

/**
 * A Netty channel upstream handler class for routing HTTP requests to the 
 * appropriate servlet for processing. This has much of the logic that used
 * to reside in the RequestHandlerThread class.
 * @author raymond.mak
 */
public class RequestHandler extends SimpleChannelUpstreamHandler {
    
    private HostGroup hostGroup;
    private WinstoneRequest currentRequest;
    private WinstoneResponse currentResponse;
    private final AtomicBoolean browserChannelClosed = new AtomicBoolean(false);
    private volatile boolean readingChunks;
    private boolean doHostNameLookups;
    private String scheme;
    private boolean simulateModUniqueId;
    private ChannelGroup channelGroup;
    
    public RequestHandler(HostGroup hostGroup, boolean doHostNameLookups, 
        String scheme, boolean simulateModUniqueId, ChannelGroup channelGroup) {
        super();
        this.hostGroup = hostGroup;
        this.doHostNameLookups = doHostNameLookups;
        this.scheme = scheme;
        this.simulateModUniqueId = simulateModUniqueId;
        this.channelGroup = channelGroup;
    }
    
    // Track all opened channels so we can clean them all up on shutdown
    @Override
    public void channelOpen(final ChannelHandlerContext ctx, 
        final ChannelStateEvent cse) throws Exception {
        
        if (this.channelGroup != null) {
            this.channelGroup.add(cse.getChannel());
        }        
    }    
    
    @Override
    public void messageReceived(final ChannelHandlerContext ctx, 
        final MessageEvent me) throws Exception {
        
        if (browserChannelClosed.get()) {
            return;
        }
        
        if (!readingChunks) {
            processRequest(ctx, me);
        }
        else {
            processChunk(me);
        }
    }        
    
    private void processRequest(final ChannelHandlerContext ctx, 
        final MessageEvent me) throws Exception {
        
        HttpRequest request = (HttpRequest)me.getMessage();
        Channel channel = ctx.getChannel();        
        currentRequest = new WinstoneRequest(
                request, hostGroup, channel, doHostNameLookups, scheme, 5000);
        readingChunks = request.isChunked();
        currentResponse = new WinstoneResponse(currentRequest, channel);
        
        if (this.simulateModUniqueId) {
            currentRequest.setAttribute("UNIQUE_ID", Long.toString(System.currentTimeMillis()));            
        }
        
        HostConfiguration hostConfig = currentRequest.getHostGroup()
            .getHostByName(currentRequest.getServerName());
        final WebAppConfiguration webAppConfig = hostConfig.getWebAppByURI(
                currentRequest.getRequestURI());
        if (webAppConfig == null) {
            currentResponse.sendError(HttpResponseStatus.NOT_FOUND.getCode(), 
                Launcher.RESOURCES.getString("RequestHandlerThread.UnknownWebappPage", 
                    currentRequest.getRequestURI()));            
            
        }
        else {
            currentRequest.setWebAppConfig(webAppConfig);
            
            ServletRequestListener requestListeners[] = webAppConfig.getRequestListeners();
            final ServletRequestEvent event = new ServletRequestEvent(webAppConfig, currentRequest);
            EventSender.broadcastEvent(requestListeners, webAppConfig, 
                    new EventSender<ServletRequestListener>() {
                        @Override
                        public void sendEvent(ServletRequestListener target) {
                            target.requestInitialized(event);
                        }});
            
            dispatchRequest();
            
            // Close channel if keepalive is disabled            
            if (currentResponse.closeAfterRequest()) {
                channel.close();
            }
            
            EventSender.broadcastEvent(requestListeners, webAppConfig, 
                    new EventSender<ServletRequestListener>() {
                        @Override
                        public void sendEvent(ServletRequestListener listener) {
                            listener.requestDestroyed(event);
                        }});
           
        }
    }
    
    private void dispatchRequest() throws IOException {
        WebAppConfiguration webAppConfig = currentRequest.getWebAppConfig();
        String path = webAppConfig.getServletURIFromRequestURI(currentRequest.getRequestURI());        
        RequestDispatcher rd;
        RequestDispatcher rdError = null;
        try {
            rd = webAppConfig.getInitialDispatcher(path, currentRequest, currentResponse);
            if (rd != null) {
                rd.forward(currentRequest, currentResponse);
            }
        }
        catch (Throwable err) {
            rdError = webAppConfig.getErrorDispatcherByClass(err);
        }
        if (rdError != null) {
            try {
                if (currentResponse.isCommitted()) {
                    rdError.include(currentRequest, currentResponse);
                }
                else {
                    currentResponse.resetBuffer();
                    rdError.forward(currentRequest, currentResponse);
                }
            }
            catch (Throwable err) {
                Logger.log(Logger.ERROR, Launcher.RESOURCES, "RequestHandlerThread.ErrorInErrorServlet", err);
            }
        }
        currentResponse.flushBuffer();
        currentResponse.getWinstoneOutputStream().close();
        
    }
        
    private void processChunk(final MessageEvent me) {
        
        final HttpChunk chunk = (HttpChunk) me.getMessage();
        
        currentRequest.offerContentChunk(chunk.getContent());
        
        // Remember this will typically be a persistent connection, so we'll
        // get another request after we're read the last chunk. So we need to
        // reset it back to no longer read in chunk mode.
        if (chunk.isLast()) {
            currentRequest.offerContentChunk(ChannelBuffers.EMPTY_BUFFER);            
            this.readingChunks = false;
        }
        
    }
}
