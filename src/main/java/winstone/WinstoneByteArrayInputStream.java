package winstone;

import java.io.IOException;
import javax.servlet.ServletInputStream;

/**
 * A ServletInputStream that wraps a byte array. 
 * @author raymond.mak
 */
public class WinstoneByteArrayInputStream extends ServletInputStream {

    private byte[] content;
    private int bytesRead = 0;

    final static private IOException MARKANDRESET_NOT_SUPPORTED = new IOException("mark() and reset() not supported");
    final static private IOException SKIP_NOT_SUPPORTED = new IOException("skip() not supported");
    
    public WinstoneByteArrayInputStream(byte[] content) {
        this.content = content;        
    }    

    @Override
    public int available() {
        return content.length - bytesRead;
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
        if (bytesRead >= content.length) {
            return -1;
        }
        else {
            return content[bytesRead++];
        }
    }

    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    } 
    
    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int bytesToBeRead = Math.min(len, content.length - bytesRead);
        if (bytesToBeRead > 0) {
            
        }
        return bytesToBeRead;
    }
    
    @Override
    public long skip(long n) throws IOException {
        throw SKIP_NOT_SUPPORTED;
    }
}
