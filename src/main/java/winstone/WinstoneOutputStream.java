/*
 * Copyright 2003-2006 Rick Knowles <winstone-devel at lists sourceforge net>
 * Distributed under the terms of either:
 * - the common development and distribution license (CDDL), v1.0; or
 * - the GNU Lesser General Public License, v2.1 or later
 */
package winstone;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.util.concurrent.atomic.AtomicBoolean;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.buffer.DynamicChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.handler.codec.http.HttpHeaders;

/**
 * Matches netty channel to the servlet output.
 * 
 * @author <a href="mailto:rick_knowles@hotmail.com">Rick Knowles</a>
 * @version $Id: WinstoneOutputStream.java,v 1.20 2008/02/28 00:01:38 rickknowles Exp $
 */
public class WinstoneOutputStream extends javax.servlet.ServletOutputStream {
    private static final int DEFAULT_BUFFER_SIZE = 8192;
    private int bufferSize;
    private int bytesCommitted;
    private boolean committed;
    private WinstoneResponse owner;
    private boolean disregardMode = false;
    private AtomicBoolean atomicClosed = new AtomicBoolean(false);
    
    private int contentLengthFromHeader = -1;
    private Channel channel;
    private ChannelBuffer channelBuffer = new DynamicChannelBuffer(DEFAULT_BUFFER_SIZE);
    
    /**
     * Constructor
     */
    public WinstoneOutputStream(
        Channel channel,
        WinstoneResponse owner) {
        this.channel = channel;
        this.bufferSize = DEFAULT_BUFFER_SIZE;
        this.committed = false;
        this.owner = owner;
    }

    public int getBufferSize() {
        return this.bufferSize;
    }
    
    public void setBufferSize(int bufferSize) {
        if (this.owner.isCommitted()) {
            throw new IllegalStateException(Launcher.RESOURCES.getString(
                    "WinstoneOutputStream.AlreadyCommitted"));
        }
        this.bufferSize = bufferSize;
    }

    public boolean isCommitted() {
        return this.committed;
    }

    public int getOutputStreamLength() {
        return this.bytesCommitted + this.channelBuffer.writerIndex();
    }

    public int getBytesCommitted() {
        return this.bytesCommitted;
    }
    
    public void setDisregardMode(boolean disregard) {
        this.disregardMode = disregard;
    }

    private byte[] conversionByteArray = new byte[6]; // A single utf-8 character can be at most 6 bytes
    private ByteBuffer conversionByteBuffer = ByteBuffer.wrap(conversionByteArray); 
    private CharsetEncoder encoder = Charset.forName("UTF-8").newEncoder();
    
    @Override
    public synchronized void write(int oneChar) throws IOException {
        
        if (this.disregardMode || this.atomicClosed.get()) {
            return;
        } else if ((this.contentLengthFromHeader != -1) && 
                (this.bytesCommitted >= this.contentLengthFromHeader)) {
            return;
        }
//        System.out.println("Out: " + this.bufferPosition + " char=" + (char)oneChar);
        encoder.encode(CharBuffer.wrap(Character.toChars(oneChar)), 
                conversionByteBuffer, true);
        
        if (conversionByteBuffer.position() > 0) {
            write(conversionByteArray, 0, conversionByteBuffer.position());            
        }
        conversionByteBuffer.clear();
    }

    @Override
    public synchronized void write(byte b[], int off, int len) throws IOException {
        if (this.disregardMode || this.atomicClosed.get()) {
            return;
        } else if ((this.contentLengthFromHeader != -1) && 
                (this.bytesCommitted >= this.contentLengthFromHeader)) {
            return;
        }
        // Enable "dangerous" direct-write to the channel if input bytes is
        // bigger than buffer size. "Dangerous" in the sense that we are going
        // to just wrap the input buffer without making a copy and assume that
        // the caller will not touch the content of the input buffer after the
        // write. We could make it safer by synchronizing with the completion
        // of the write.         
        if (len > this.bufferSize) {
            commit();
            if (this.contentLengthFromHeader != -1) {
                len = Math.min(len, contentLengthFromHeader - bytesCommitted);
            }
            if (len > 0) {
                channel.write(ChannelBuffers.wrappedBuffer(b, off, len));                
                bytesCommitted += len;
            }                        
        }
        else {
            while (len > 0) {
                int bytesToBuffer = Math.min(len, this.bufferSize - this.channelBuffer.writerIndex());
                this.channelBuffer.writeBytes(b, off, bytesToBuffer);
                if (channelBuffer.writerIndex() >= this.bufferSize) {
                    commit();
                }
                len -= bytesToBuffer;
                off += bytesToBuffer;
            }
        }
    }
    
    private void commit() throws IOException {

        // If we haven't written the headers yet, write them out
        if (!this.committed) {
            this.owner.validateHeaders();
            this.committed = true;
            String contentLengthHeader = this.owner.getHeader(HttpHeaders.Names.CONTENT_LENGTH);
            if (contentLengthHeader != null) {
                this.contentLengthFromHeader = Integer.parseInt(contentLengthHeader);
            }

            Logger.log(Logger.DEBUG, Launcher.RESOURCES, "WinstoneOutputStream.CommittingOutputStream");            
            channel.write(owner.getResponse());
         
        }       
        int commitLength = this.channelBuffer.writerIndex();
        if (this.contentLengthFromHeader != -1) {
            commitLength = Math.min(this.contentLengthFromHeader - this.bytesCommitted, commitLength);
        }
        if (commitLength > 0) {
            channelBuffer.writerIndex(commitLength);
            this.channel.write(channelBuffer);            
            this.bytesCommitted += commitLength;
            this.channelBuffer = new DynamicChannelBuffer(bufferSize);
        }        
        else {
            this.channelBuffer.resetWriterIndex();
            
        }
        Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES,
                "WinstoneOutputStream.CommittedBytes", 
                "" + (this.bytesCommitted + commitLength));

    }

    public void reset() {
        if (isCommitted())
            throw new IllegalStateException(Launcher.RESOURCES
                    .getString("WinstoneOutputStream.AlreadyCommitted"));
        else {
            Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES,
                    "WinstoneOutputStream.ResetBuffer", this.channelBuffer.writerIndex()
                            + "");
            this.channelBuffer.resetWriterIndex();
            this.bytesCommitted = 0;
        }
    }

    @Override
    public void flush() throws IOException {
        if (this.disregardMode) {
            return;
        }
        Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES, "WinstoneOutputStream.Flushing");
        this.commit();
    }

    @Override
    public void close() throws IOException {        
        if (!this.atomicClosed.getAndSet(true)) { 
            if (!this.disregardMode &&
                    (this.owner.getHeader(HttpHeaders.Names.CONTENT_LENGTH) == null)) {
                if ((this.owner != null)) {
                    this.owner.setContentLength(getOutputStreamLength());
                }
            }
            flush();        
            this.channel.write(ChannelBuffers.EMPTY_BUFFER);
        }
    }

}
