package winstone;

import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import static org.jboss.netty.channel.Channels.pipeline;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.handler.codec.http.HttpRequestDecoder;
import org.jboss.netty.handler.codec.http.HttpResponseEncoder;

/**
 *
 * @author raymond.mak
 */
public class HttpServerPipelineFactory implements ChannelPipelineFactory {

    private HostGroup hostGroup;
    private boolean doHostNameLookups;
    private ChannelGroup channelGroup;
    private boolean simulateModUniqueId;
    
    public HttpServerPipelineFactory(
        HostGroup hostGroup,
        boolean doHostNameLookups,
        boolean simulateModUniqueId,
        ChannelGroup channelGroup) {
        this.hostGroup = hostGroup;
        this.doHostNameLookups = doHostNameLookups;
        this.simulateModUniqueId = simulateModUniqueId;
        this.channelGroup = channelGroup;
    }
    
    public ChannelPipeline getPipeline() throws Exception {
        final ChannelPipeline pipeline = pipeline(); 
        configurePipeline(pipeline);        
        return pipeline;
    }
    
    protected void configurePipeline(ChannelPipeline pipeline) throws Exception {
        // TODO: Add LoggingHandler to support access log
        pipeline.addLast("decoder", new HttpRequestDecoder());
        // Make aggregator configurable
        //pipeline.addLast("aggregator", new HttpChunkAggregator(maxPostContentSize));
        pipeline.addLast("encoder", new HttpResponseEncoder());
        
        // TODO: Add timeout handler
        //pipeline.addLast("idle", new IdleStateHandler(...));
        pipeline.addLast("handler", new RequestHandler(hostGroup, 
            doHostNameLookups, getScheme(), simulateModUniqueId, channelGroup));                
    }
    
    protected String getScheme() {
        return "http";
    }
}
