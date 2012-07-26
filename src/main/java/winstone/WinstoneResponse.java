/*
 * Copyright 2003-2006 Rick Knowles <winstone-devel at lists sourceforge net>
 * Distributed under the terms of either:
 * - the common development and distribution license (CDDL), v1.0; or
 * - the GNU Lesser General Public License, v2.1 or later
 */
package winstone;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.handler.codec.http.*;

/**
 * Response for servlet
 * 
 * @author <a href="mailto:rick_knowles@hotmail.com">Rick Knowles</a>
 * @version $Id: WinstoneResponse.java,v 1.28 2005/04/19 07:33:41 rickknowles
 *          Exp $
 */
public class WinstoneResponse implements HttpServletResponse {

    private static final ThreadLocal<DateFormat> threadLocalHttpHeaderDateFormat = new ThreadLocal<DateFormat>() {
        @Override
        protected DateFormat initialValue() {
            DateFormat httpHeaderDateFormat = new SimpleDateFormat(
                "EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
            httpHeaderDateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
            return httpHeaderDateFormat;
        }        
    };    

    // Response header constants
    private static final String X_POWERED_BY_HEADER = "X-Powered-By";
    private static final String X_POWERED_BY_HEADER_VALUE = Launcher.RESOURCES.getString("PoweredByHeader");

    //private int statusCode;
    private WinstoneRequest req;
    private WebAppConfiguration webAppConfig;
    private WinstoneOutputStream outputStream;
    private PrintWriter outputWriter;
    
    private HttpResponse response;    
    private CookieEncoder cookieEncoder = new CookieEncoder(true);
    
    private String explicitEncoding;
    private String implicitEncoding;    
    
    private Locale locale;
    private String reqKeepAliveHeader;
    private Integer errorStatusCode;
    private int includeLevel = 0;    
    
    /**
     * Constructor
     */
    public WinstoneResponse(WinstoneRequest req, Channel channel) {
        
        this.response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        this.locale = null; //Locale.getDefault();
        this.explicitEncoding = null;
        this.reqKeepAliveHeader = null;
        this.req = req;
        this.reqKeepAliveHeader = req.getHeader(HttpHeaders.Names.CONNECTION);
        this.outputStream = new WinstoneOutputStream(channel, this);
        
        this.setHeader(HttpHeaders.Names.SERVER, Launcher.RESOURCES.getString("ServerVersion"));
    }

    /**
     * Resets the request to be reused
     */
    public void cleanUp() {
        this.req = null;
        this.webAppConfig = null;
        this.outputStream = null;
        this.outputWriter = null;
        this.response.clearHeaders();
        this.cookieEncoder = new CookieEncoder(true);
        this.reqKeepAliveHeader = null;

        this.response.setStatus(HttpResponseStatus.OK);
        this.errorStatusCode = null;
        this.locale = null; //Locale.getDefault();
        this.explicitEncoding = null;
        this.implicitEncoding = null;
    }

    private String getEncodingFromLocale(Locale loc) {
        String localeString = loc.getLanguage() + "_" + loc.getCountry();
        Map encMap = this.webAppConfig.getLocaleEncodingMap();
        Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES, 
                "WinstoneResponse.LookForLocaleEncoding",
                new String[] {localeString, encMap + ""});

        String fullMatch = (String) encMap.get(localeString);
        if (fullMatch != null) {
            Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES, 
                    "WinstoneResponse.FoundLocaleEncoding", fullMatch);
            return fullMatch;
        } else {
            localeString = loc.getLanguage();
            Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES, 
                    "WinstoneResponse.LookForLocaleEncoding",
                    new String[] {localeString, encMap + ""});
            String match = (String) encMap.get(localeString);
            if (match != null) {
                Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES, 
                        "WinstoneResponse.FoundLocaleEncoding", match);
            }
            return match;
        }
        
        
    }

    public void setErrorStatusCode(int statusCode) {
        this.errorStatusCode = new Integer(statusCode);
        this.response.setStatus(HttpResponseStatus.valueOf(statusCode));
    }
    
    public WinstoneOutputStream getWinstoneOutputStream() {
        return this.outputStream;
    }
    
    public void setOutputStream(WinstoneOutputStream outData) {
        this.outputStream = outData;
    }

    public void setWebAppConfig(WebAppConfiguration webAppConfig) {
        this.webAppConfig = webAppConfig;
    }

    public String getProtocol() {
        return this.req.getProtocol();
    }

/*
    public  getCookies() {
        return this.cookies;
    }
*/
    public WinstoneRequest getRequest() {
        return this.req;
    }

    public HttpResponse getResponse() {
        this.response.setHeader(HttpHeaders.Names.SET_COOKIE, cookieEncoder.encode());        
        return this.response;
    }
    
    public void startIncludeBuffer() {
         this.includeLevel++;
    }
    
    public void finishIncludeBuffer() throws IOException {
        if (isIncluding()) {
            if (this.outputWriter != null) {
                this.outputWriter.flush();
            }
            this.includeLevel--;
        }
    }
    
    public void clearIncludeStackForForward() throws IOException {
        this.includeLevel = 0;
    }

    protected static String getCharsetFromContentTypeHeader(String type, StringBuffer remainder) {
        if (type == null) {
            return null;
        }
        // Parse type to set encoding if needed
        StringTokenizer st = new StringTokenizer(type, ";");
        String localEncoding = null;
        while (st.hasMoreTokens()) {
            String clause = st.nextToken().trim();
            if (clause.startsWith("charset="))
                localEncoding = clause.substring(8);
            else {
                if (remainder.length() > 0) {
                    remainder.append(";");
                }
                remainder.append(clause);
            }
        }
        if ((localEncoding == null) || 
                !localEncoding.startsWith("\"") || 
                !localEncoding.endsWith("\"")) {
            return localEncoding;
        } else {
            return localEncoding.substring(1, localEncoding.length() - 1);
        }
    } 

    /**
     * This ensures the bare minimum correct http headers are present
     */
    public void validateHeaders() {        
        // Need this block for WebDAV support. "Connection:close" header is ignored
        String lengthHeader = getHeader(HttpHeaders.Names.CONTENT_LENGTH);
        if ((lengthHeader == null) && (this.response.getStatus().getCode() >= 300)) {
            int bodyBytes = this.outputStream.getOutputStreamLength();
            if (getBufferSize() > bodyBytes) {
                Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES, 
                        "WinstoneResponse.ForcingContentLength", "" + bodyBytes);
                forceHeader(HttpHeaders.Names.CONTENT_LENGTH, "" + bodyBytes);
            }
        }
        
        forceHeader(HttpHeaders.Names.CONNECTION, !closeAfterRequest() ? HttpHeaders.Values.KEEP_ALIVE : HttpHeaders.Values.CLOSE);
        String contentType = getHeader(HttpHeaders.Names.CONTENT_TYPE);
        if (this.response.getStatus().getCode() != SC_MOVED_TEMPORARILY) {
            if (contentType == null) {
                // Bypass normal encoding
                forceHeader(HttpHeaders.Names.CONTENT_TYPE, "text/html;charset=" + getCharacterEncoding());
            } else if (contentType.startsWith("text/")) {
                // replace charset in content
                StringBuffer remainder = new StringBuffer();
                getCharsetFromContentTypeHeader(contentType, remainder);
                forceHeader(HttpHeaders.Names.CONTENT_TYPE, remainder.toString() + ";charset=" + getCharacterEncoding());
            }
        }
        if (getHeader(HttpHeaders.Names.DATE) == null) {
            forceHeader(HttpHeaders.Names.DATE, formatHeaderDate(new Date()));
        }
        if (getHeader(X_POWERED_BY_HEADER) == null) {
            forceHeader(X_POWERED_BY_HEADER, X_POWERED_BY_HEADER_VALUE);
        }
        if (this.locale != null) {
            String lang = this.locale.getLanguage();
            if ((this.locale.getCountry() != null) && !this.locale.getCountry().equals("")) {
                lang = lang + "-" + this.locale.getCountry();
            }
            forceHeader(HttpHeaders.Names.CONTENT_LANGUAGE, lang);
        }
        
        // If we don't have a webappConfig, exit here, cause we definitely don't
        // have a session
        if (req.getWebAppConfig() == null) {
            return;
        }
        // Write out the new session cookie if it's present
        HostConfiguration hostConfig = req.getHostGroup().getHostByName(req.getServerName());
        for (Iterator i = req.getCurrentSessionIds().keySet().iterator(); i.hasNext(); ) {
            String prefix = (String) i.next();
            String sessionId = (String) req.getCurrentSessionIds().get(prefix);
            WebAppConfiguration ownerContext = hostConfig.getWebAppByURI(prefix);
            if (ownerContext != null) {
                WinstoneSession session = ownerContext.getSessionById(sessionId, true);
                if ((session != null) && session.isNew()) {
                    session.setIsNew(false);
                    Cookie cookie = new Cookie(WinstoneSession.SESSION_COOKIE_NAME, session.getId());
                    cookie.setMaxAge(-1);
                    cookie.setSecure(req.isSecure());
                    cookie.setVersion(0); //req.isSecure() ? 1 : 0);
                    cookie.setPath(req.getWebAppConfig().getContextPath().equals("") ? "/"
                                    : req.getWebAppConfig().getContextPath());
                    addCookieInternal(cookie); // don't call addCookie because we might be including
                }
            }
        }
        
        // Look for expired sessions: ie ones where the requested and current ids are different
        for (Iterator i = req.getRequestedSessionIds().keySet().iterator(); i.hasNext(); ) {
            String prefix = (String) i.next();
            String sessionId = (String) req.getRequestedSessionIds().get(prefix);
            if (!req.getCurrentSessionIds().containsKey(prefix)) {
                Cookie cookie = new Cookie(WinstoneSession.SESSION_COOKIE_NAME, sessionId);
                cookie.setMaxAge(0); // explicitly expire this cookie
                cookie.setSecure(req.isSecure());
                cookie.setVersion(0); //req.isSecure() ? 1 : 0);
                cookie.setPath(prefix.equals("") ? "/" : prefix);
                addCookieInternal(cookie); // don't call addCookie because we might be including
            }
        }
        
    }

    static private org.jboss.netty.handler.codec.http.Cookie servletToNettyCookie(Cookie cookie) {
        org.jboss.netty.handler.codec.http.Cookie nettyCookie = 
            new DefaultCookie(cookie.getName(), cookie.getValue());        
        nettyCookie.setComment(cookie.getComment());
        nettyCookie.setDomain(cookie.getDomain());
        nettyCookie.setMaxAge(cookie.getMaxAge());
        nettyCookie.setPath(cookie.getPath());
        nettyCookie.setSecure(cookie.getSecure());
        nettyCookie.setVersion(cookie.getVersion());
        return nettyCookie;        
    }
    
    private void addCookieInternal(Cookie cookie) {
        cookieEncoder.addCookie(servletToNettyCookie(cookie));                
    }    
    
    private static String formatHeaderDate(Date dateIn) {
        return threadLocalHttpHeaderDateFormat.get().format(dateIn);
    }
    
    /**
     * Quotes the necessary strings in a cookie header. The quoting is only
     * applied if the string contains special characters.
     */
    protected static void quote(String value, StringBuffer out) {
        if (value.startsWith("\"") && value.endsWith("\"")) {
            out.append(value);
        } else {
            boolean containsSpecial = false;
            for (int n = 0; n < value.length(); n++) {
                char thisChar = value.charAt(n);
                if ((thisChar < 32) || (thisChar >= 127)
                        || (specialCharacters.indexOf(thisChar) != -1)) {
                    containsSpecial = true;
                    break;
                }
            }
            if (containsSpecial)
                out.append('"').append(value).append('"');
            else
                out.append(value);
        }
    }

    private static final String specialCharacters = "()<>@,;:\\\"/[]?={} \t";

    /**
     * Based on request/response headers and the protocol, determine whether or
     * not this connection should operate in keep-alive mode.
     */
    public boolean closeAfterRequest() {
        String inKeepAliveHeader = this.reqKeepAliveHeader;
        String outKeepAliveHeader = getHeader(HttpHeaders.Names.CONNECTION);
        boolean hasContentLength = (getHeader(HttpHeaders.Names.CONTENT_LENGTH) != null);
        if (this.req.getProtocol().startsWith("HTTP/0"))
            return true;
        else if ((inKeepAliveHeader == null) && (outKeepAliveHeader == null))
            return this.req.getProtocol().equals("HTTP/1.0") ? true : !hasContentLength;
        else if (outKeepAliveHeader != null)
            return outKeepAliveHeader.equalsIgnoreCase(HttpHeaders.Values.KEEP_ALIVE) || !hasContentLength;
        else if (inKeepAliveHeader != null)
            return inKeepAliveHeader.equalsIgnoreCase(HttpHeaders.Values.CLOSE) || !hasContentLength;
        else
            return false;
    }
    
    // ServletResponse interface methods
    public void flushBuffer() throws IOException {
        if (this.outputWriter != null) {
            this.outputWriter.flush();
        }
        this.outputStream.flush();
    }

    public void setBufferSize(int size) {
        this.outputStream.setBufferSize(size);
    }

    public int getBufferSize() {
        return this.outputStream.getBufferSize();
    }

    public String getCharacterEncoding() {
        String enc = getCurrentEncoding();
        return (enc == null ? "ISO-8859-1" : enc);
    }

    public void setCharacterEncoding(String encoding) {
        if ((this.outputWriter == null) && !isCommitted()) {
            Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES, "WinstoneResponse.SettingEncoding", encoding);
            this.explicitEncoding = encoding;
            correctContentTypeHeaderEncoding(encoding);
        }
    }

    private void correctContentTypeHeaderEncoding(String encoding) {
        String contentType = getContentType();
        if (contentType != null) {
            StringBuffer remainderHeader = new StringBuffer();
            getCharsetFromContentTypeHeader(contentType, remainderHeader);
            if (remainderHeader.length() != 0) {
                forceHeader(HttpHeaders.Names.CONTENT_TYPE, remainderHeader + ";charset=" + encoding);
            }
        }
    }
    
    public String getContentType() {
        return getHeader(HttpHeaders.Names.CONTENT_TYPE);
    }

    public void setContentType(String type) {
        setHeader(HttpHeaders.Names.CONTENT_TYPE, type);
    }

    public Locale getLocale() {
        return this.locale == null ? Locale.getDefault() : this.locale;
    }

    private boolean isIncluding() {
        return includeLevel > 0;
    }
    
    public void setLocale(Locale loc) {
        if (isIncluding()) {
            return;
        } else if (isCommitted()) {
            Logger.log(Logger.WARNING, Launcher.RESOURCES,
                    "WinstoneResponse.SetLocaleTooLate");
        } else {
            if ((this.outputWriter == null) && (this.explicitEncoding == null)) {
                String localeEncoding = getEncodingFromLocale(loc);
                if (localeEncoding != null) {
                    this.implicitEncoding = localeEncoding;
                    correctContentTypeHeaderEncoding(localeEncoding);
                }
            }
            this.locale = loc;
        }
    }

    public ServletOutputStream getOutputStream() throws IOException {
        Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES, "WinstoneResponse.GetOutputStream");
        return this.outputStream;
    }

    public PrintWriter getWriter() throws IOException {
        Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES, "WinstoneResponse.GetWriter");
        if (this.outputWriter != null)
            return this.outputWriter;
        else {
            this.outputWriter = new WinstoneResponseWriter(this.outputStream, this);
            return this.outputWriter;
        }
    }

    public boolean isCommitted() {
        return this.outputStream.isCommitted();
    }

    public void reset() {
        if (!isIncluding()) {
            resetBuffer();
            this.response.setStatus(HttpResponseStatus.OK);
            this.response.clearHeaders();
            this.cookieEncoder = new CookieEncoder(true);
        }
    }

    public void resetBuffer() {
        if (!isIncluding()) {
            if (isCommitted())
                throw new IllegalStateException(Launcher.RESOURCES
                        .getString("WinstoneResponse.ResponseCommitted"));
            
            // Disregard any output temporarily while we flush
            this.outputStream.setDisregardMode(true);
            
            if (this.outputWriter != null) {
                this.outputWriter.flush();
            }
            
            this.outputStream.setDisregardMode(false);
            this.outputStream.reset();
        }
    }

    public void setContentLength(int len) {
        setIntHeader(HttpHeaders.Names.CONTENT_LENGTH, len);
    }

    // HttpServletResponse interface methods
    public void addCookie(Cookie cookie) {
        if (!isIncluding()) {
            addCookieInternal(cookie);
        }
    }

    public boolean containsHeader(String name) {
        return this.response.containsHeader(name);
    }

    public void addDateHeader(String name, long date) {
        addHeader(name, formatHeaderDate(new Date(date)));
    } // df.format(new Date(date)));}

    public void addIntHeader(String name, int value) {
        addHeader(name, "" + value);
    }

    public void addHeader(String name, String value) {
        if (isIncluding()) {
            Logger.log(Logger.DEBUG, Launcher.RESOURCES, "WinstoneResponse.HeaderInInclude", 
                    new String[] {name, value});  
        } else if (isCommitted()) {
            Logger.log(Logger.DEBUG, Launcher.RESOURCES, "WinstoneResponse.HeaderAfterCommitted", 
                    new String[] {name, value});  
        } else if (value != null) {
            if (HttpHeaders.Names.CONTENT_TYPE.equals(name)) {
                StringBuffer remainderHeader = new StringBuffer();
                String headerEncoding = getCharsetFromContentTypeHeader(value, remainderHeader);
                if (this.outputWriter != null) {
                    value = remainderHeader + ";charset=" + getCharacterEncoding();
                } else if (headerEncoding != null) {
                    this.explicitEncoding = headerEncoding;
                }
            }
            this.response.addHeader(name, value);
        }
    }

    public void setDateHeader(String name, long date) {
        setHeader(name, formatHeaderDate(new Date(date)));
    }

    public void setIntHeader(String name, int value) {
        setHeader(name, "" + value);
    }

    final public void setHeader(String name, String value) {
        if (isIncluding()) {
            Logger.log(Logger.DEBUG, Launcher.RESOURCES, "WinstoneResponse.HeaderInInclude", 
                    new String[] {name, value});  
        } else if (isCommitted()) {
            Logger.log(Logger.DEBUG, Launcher.RESOURCES, "WinstoneResponse.HeaderAfterCommitted", 
                    new String[] {name, value});
        } else {
            if (name != null) {
                if (value == null) {
                    response.removeHeader(name);                
                }
                else {
                    if (HttpHeaders.Names.CONTENT_TYPE.equals(name)) {
                        StringBuffer remainderHeader = new StringBuffer();
                        String headerEncoding = getCharsetFromContentTypeHeader(
                            value, remainderHeader);
                        if (this.outputWriter != null) {
                            value = remainderHeader + ";charset=" + getCharacterEncoding();
                        } else if (headerEncoding != null) {
                            this.explicitEncoding = headerEncoding;                            
                        }
                    }
                }
                response.setHeader(name, value);
            }
        }
    }

    private void forceHeader(String name, String value) {
        response.setHeader(name, value);
    }
    
    private String getCurrentEncoding() {
        if (this.explicitEncoding != null) {
            return this.explicitEncoding;
        } else if (this.implicitEncoding != null) {
            return this.implicitEncoding;
        } else if ((this.req != null) && (this.req.getCharacterEncoding() != null)) {
            try {
                "0".getBytes(this.req.getCharacterEncoding());
                return this.req.getCharacterEncoding();
            } catch (UnsupportedEncodingException err) {
                return null;
            }
        } else {
            return null;
        }
    }
    
    public String getHeader(String name) {
        return response.getHeader(name);
    }

    public String encodeRedirectURL(String url) {
        return url;
    }

    public String encodeURL(String url) {
        return url;
    }

    public int getStatus() {
        return response.getStatus().getCode();
    }

    public Integer getErrorStatusCode() {
        return this.errorStatusCode;
    }

    public void setStatus(int sc) {
        if (!isIncluding() && (this.errorStatusCode == null)) {
//        if (!isIncluding()) {
            response.setStatus(HttpResponseStatus.valueOf(sc));            
//            if (this.errorStatusCode != null) {
//                this.errorStatusCode = new Integer(sc);
//            }
        }
    }

    public void sendRedirect(String location) throws IOException {
        if (isIncluding()) {
            Logger.log(Logger.ERROR, Launcher.RESOURCES, "IncludeResponse.Redirect",
                    location);
            return;
        } else if (isCommitted()) {
            throw new IllegalStateException(Launcher.RESOURCES.getString("WinstoneOutputStream.AlreadyCommitted"));
        }
        resetBuffer();
        
        // Build location
        StringBuilder fullLocation = new StringBuilder();
        if (location.startsWith("http://") || location.startsWith("https://")) {
            fullLocation.append(location);
        } else {
            if (location.trim().equals(".")) {
                location = "";
            }
            
            fullLocation.append(this.req.getScheme()).append("://");
            fullLocation.append(this.req.getServerName());
            if (!((this.req.getServerPort() == 80) && this.req.getScheme().equals("http"))
                    && !((this.req.getServerPort() == 443) && this.req.getScheme().equals("https")))
                fullLocation.append(':').append(this.req.getServerPort());
            if (location.startsWith("/")) {
                fullLocation.append(location);
            } else {
                fullLocation.append(this.req.getRequestURI());
                int questionPos = fullLocation.toString().indexOf("?"); 
                if (questionPos != -1) {
                    fullLocation.delete(questionPos, fullLocation.length());
                }
                fullLocation.delete(
                        fullLocation.toString().lastIndexOf("/") + 1,
                        fullLocation.length());
                fullLocation.append(location);
            }
        }
        this.response.setStatus(HttpResponseStatus.TEMPORARY_REDIRECT);
        setHeader(HttpHeaders.Names.LOCATION, fullLocation.toString());
        setContentLength(0);
        getWriter().flush();
    }

    public void sendError(int sc) throws IOException {
        sendError(sc, null);
    }

    public void sendError(int sc, String msg) throws IOException {
        if (isIncluding()) {
            Logger.log(Logger.ERROR, Launcher.RESOURCES, "IncludeResponse.Error",
                    new String[] { "" + sc, msg });
            return;
        }
        
        Logger.log(Logger.DEBUG, Launcher.RESOURCES,
                "WinstoneResponse.SendingError", new String[] { "" + sc, msg });

        if ((this.webAppConfig != null) && (this.req != null)) {
            
            RequestDispatcher rd = this.webAppConfig
                    .getErrorDispatcherByCode(sc, msg, null);
            if (rd != null) {
                try {
                    rd.forward(this.req, this);
                    return;
                } catch (IllegalStateException err) {
                    throw err;
                } catch (IOException err) {
                    throw err;
                } catch (Throwable err) {
                    Logger.log(Logger.WARNING, Launcher.RESOURCES,
                            "WinstoneResponse.ErrorInErrorPage", new String[] {
                                    rd.getName(), sc + "" }, err);
                    return;
                }
            }
        }
        // If we are here there was no webapp and/or no request object, so 
        // show the default error page
        if (this.errorStatusCode == null) {
            this.response.setStatus(HttpResponseStatus.valueOf(sc));
        }
        String output = Launcher.RESOURCES.getString("WinstoneResponse.ErrorPage",
                new String[] { sc + "", (msg == null ? "" : msg), "",
                        Launcher.RESOURCES.getString("ServerVersion"),
                        "" + new Date() });
        setContentLength(output.getBytes(getCharacterEncoding()).length);
        Writer out = getWriter();
        out.write(output);
        out.flush();
    }

    /**
     * @deprecated
     */
    public String encodeRedirectUrl(String url) {
        return encodeRedirectURL(url);
    }

    /**
     * @deprecated
     */
    public String encodeUrl(String url) {
        return encodeURL(url);
    }

    /**
     * @deprecated
     */
    public void setStatus(int sc, String sm) {
        setStatus(sc);
    }
  
    public Collection<String> getHeaders(String string) {
        return this.response.getHeaders(string);
    }

    public Collection<String> getHeaderNames() {
        return this.response.getHeaderNames();
    }
    
    
}
