/*
 * Copyright 2003-2006 Rick Knowles <winstone-devel at lists sourceforge net>
 * Distributed under the terms of either:
 * - the common development and distribution license (CDDL), v1.0; or
 * - the GNU Lesser General Public License, v2.1 or later
 */
package winstone;

import java.io.IOException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.jboss.netty.buffer.ChannelBuffer;

/**
 * The request stream management class.
 * 
 * @author <a href="mailto:rick_knowles@hotmail.com">Rick Knowles</a>
 * @version $Id: WinstoneInputStream.java,v 1.4 2006/02/28 07:32:47 rickknowles Exp $
 */
public class WinstoneInputStream extends javax.servlet.ServletInputStream {
    private int contentLength = -1;
    private int readSoFar = 0;
    private long timeoutMillis;
    private LinkedBlockingQueue<ChannelBuffer> contentChunks = new LinkedBlockingQueue<ChannelBuffer>();
    
    final static private IOException MARKANDRESET_NOT_SUPPORTED = new IOException("mark() and reset() not supported");
    final static private IOException READ_TIMEOUT = new IOException("Read timeout");
    final static private IOException READ_INTERRUPTED = new IOException("Read interrupted");
    final static private IOException SKIP_NOT_SUPPORTED = new IOException("skip() not supported");
    
    /**
     * Constructor
     */
    public WinstoneInputStream(long timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
    }

    public void setContentLength(int length) {
        this.contentLength = length;
        this.readSoFar = 0;
    }

    private ChannelBuffer getCurrentChunk() throws IOException {
        boolean waitForNextChunk = false;
        ChannelBuffer currentChunk = contentChunks.peek();
        try {
            if (currentChunk != null && !currentChunk.readable() &&
                currentChunk.capacity() > 0) {
                contentChunks.poll();
                waitForNextChunk = true;
            }
            else if (currentChunk == null) {
                waitForNextChunk = true;
            }
            if (waitForNextChunk) {
                currentChunk = contentChunks.poll(timeoutMillis, TimeUnit.MILLISECONDS);
                if (currentChunk == null) {
                    throw READ_TIMEOUT;
                }
            }
        }
        catch (InterruptedException e) {
            throw READ_INTERRUPTED;
        }
        return currentChunk;
    }
    
    public void offerChunk(ChannelBuffer contentChunk) {
        // A chunk with 0 capacity will signal eof
        contentChunks.add(contentChunk);        
    }
    
    @Override
    public int available() {
        int available = 0;
        for (ChannelBuffer contentChunk : contentChunks) {
            available += contentChunk.readableBytes();
        }
        return available;
    }
    
    @Override
    public void close() throws IOException {}
    
    @Override
    public void mark(int readLimit) {}
    
    @Override
    public void reset() throws IOException {
        throw MARKANDRESET_NOT_SUPPORTED;
    }
    
    @Override
    public boolean markSupported() {
        return false;
    }
    
    @Override
    public int read() throws IOException {
        ChannelBuffer currentChunk = getCurrentChunk();        
        if (currentChunk.capacity() == 0 
            || (contentLength >= 0 && readSoFar >= contentLength)) {
            return -1;
        }
        readSoFar++;
        return currentChunk.readByte();    
    }
    
    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    } 

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int originalOffset = off;
        if (contentLength >= 0) {
            len = Math.min(contentLength - readSoFar, len);
        }        
        while (len > 0) {
            ChannelBuffer currentChunk = getCurrentChunk();
            if (currentChunk.capacity() == 0) {
                break;
            }
            int readableBytes = Math.min(len, currentChunk.readableBytes());
            currentChunk.readBytes(b, off, readableBytes);
            off += readableBytes;
            len -= readableBytes;                        
        }
        return (off - originalOffset);
    }    
    
    @Override
    public long skip(long n) throws IOException {
        throw SKIP_NOT_SUPPORTED;
    }
}
