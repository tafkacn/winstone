/*
 * Copyright 2003-2006 Rick Knowles <winstone-devel at lists sourceforge net>
 * Distributed under the terms of either:
 * - the common development and distribution license (CDDL), v1.0; or
 * - the GNU Lesser General Public License, v2.1 or later
 */
package winstone;

import com.google.common.base.Predicate;
import com.google.common.collect.Collections2;
import com.google.common.collect.Iterables;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;
import javax.servlet.*;
import javax.servlet.http.*;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpRequest;


/**
 * Implements the request interface required by the servlet spec.
 * 
 * @author <a href="mailto:rick_knowles@hotmail.com">Rick Knowles</a>
 * @version $Id: WinstoneRequest.java,v 1.41 2011/12/17 10:09:11 rickknowles Exp $
 */
public class WinstoneRequest implements HttpServletRequest {
    final protected static DateFormat headerDF = new SimpleDateFormat(
            "EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
    protected static Random rnd = null;
    static {
        headerDF.setTimeZone(TimeZone.getTimeZone("GMT"));
        rnd = new Random(System.currentTimeMillis());
    }

    // Request header constants
    static final String IN_COOKIE_HEADER2 = "Cookie2";
    static final String METHOD_HEAD = "HEAD";
    static final String METHOD_GET = "GET";
    static final String METHOD_POST = "POST";
    static final String POST_PARAMETERS = "application/x-www-form-urlencoded";

    static final private Cookie[] EMPTY_COOKIE_ARRAY = new Cookie[0];
    static final Pattern colonPattern = Pattern.compile(":");
    static final Pattern rightSquareBracketPattern = Pattern.compile("]");
    protected Map<String, Object> attributes;
    protected Map<String, String> parameters;
    protected Stack<Map<String, Object>> attributesStack;
    protected Stack<Map<String, String>> parametersStack;

    private HttpRequest request;
    
    protected boolean parsedCookies = false;
    protected Cookie cookies[];
    
    protected String method;
    protected String scheme;
    protected String serverName;
    protected String requestURI;
    protected String servletPath;
    protected String pathInfo;
    protected String queryString;
    protected int contentLength;
    protected String contentType;
    protected String encoding;

    protected int serverPort = -1;
    protected String remoteIP;
    protected String remoteName;
    protected int remotePort;
    protected String localAddr;
    protected String localName;
    protected int localPort;
    protected Boolean parsedParameters;
    protected Map<String, String> requestedSessionIds;
    protected Map<String, String> currentSessionIds;
    protected String deadRequestedSessionId;
    protected List<Locale> locales;
    protected boolean isSecure = false;
    
    protected WinstoneInputStream inputData;
    protected BufferedReader inputReader;
    protected ServletConfiguration servletConfig;
    protected WebAppConfiguration webappConfig;
    protected HostGroup hostGroup;

    protected AuthenticationPrincipal authenticatedUser;
    protected ServletRequestAttributeListener requestAttributeListeners[];
    protected ServletRequestListener requestListeners[];
    
    private MessageDigest md5Digester;
    
    private Set usedSessions;
    
    /**
     * InputStream factory method.
     */
    public WinstoneRequest(
        HttpRequest request, 
        HostGroup hostGroup,
        Channel channel,
        boolean doHostNameLookup,
        String scheme,
        long readTimeoutMillis) {
        this.attributes = new HashMap<String, Object>();
        this.parameters = new HashMap<String, String>();
        this.locales = new ArrayList();
        this.attributesStack = new Stack<Map<String, Object>>();
        this.parametersStack = new Stack<Map<String, String>>();
        this.requestedSessionIds = new HashMap<String, String>();
        this.currentSessionIds = new HashMap<String, String>();
        this.usedSessions = new HashSet();
        this.contentLength = -1;
        try {
            this.md5Digester = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException err) {
            throw new WinstoneException(
                    "MD5 digester unavailable - what the ...?");
        }
        
        this.request = request;
        this.inputData = new WinstoneInputStream(readTimeoutMillis);
        this.isSecure = "https".equalsIgnoreCase(scheme);
        // Parse contentLength and deposit first chunk in content input stream
        this.contentLength = -1;
        try {
            this.contentLength = Integer.parseInt(request.getHeader(HttpHeaders.Names.CONTENT_LENGTH));
        }
        catch (NumberFormatException e) {}
        inputData.setContentLength(contentLength);
        ChannelBuffer firstChunk = request.getContent();
        if (firstChunk.capacity() > 0 || !request.isChunked()) {        
            inputData.offerChunk(firstChunk);
        }
        
        // Parse contentType
        contentType = request.getHeader(HttpHeaders.Names.CONTENT_TYPE);
        if (contentType != null) {
            int indexOfSemiColon = contentType.lastIndexOf(";");
            if (indexOfSemiColon != -1) {
                String encodingClause = contentType.substring(indexOfSemiColon + 1).trim();
                if (encodingClause.startsWith("charset=")) {
                    this.encoding = encodingClause.substring(8);
                }
            }
        }
        this.hostGroup = hostGroup;
        InetSocketAddress localAddress = (InetSocketAddress)channel.getLocalAddress();
        InetSocketAddress remoteAddress = (InetSocketAddress)channel.getRemoteAddress();
        serverPort = localAddress.getPort();
        localPort = localAddress.getPort();
        localAddr = localAddress.getAddress().getHostAddress();
        remoteIP = remoteAddress.getAddress().getHostAddress();
        remotePort = remoteAddress.getPort();
        if (doHostNameLookup) {
            serverName = localAddress.getHostName();
            remoteName = remoteAddress.getHostName();
            localName = serverName;
        }
        else {
            serverName = localAddress.getAddress().getHostAddress();
            remoteName = remoteAddress.getAddress().getHostAddress();
            localName = serverName;
        }
        this.scheme = scheme;
        
        int indexOfQuestionMark = request.getUri().indexOf("?");
        if (indexOfQuestionMark >= 0) {
            requestURI = request.getUri().substring(0, indexOfQuestionMark);
            queryString = request.getUri().substring(indexOfQuestionMark + 1);
        }
        else {
            requestURI = request.getUri();
        }
    }
    
    public void offerContentChunk(ChannelBuffer contentChunk) {
        inputData.offerChunk(contentChunk);
    }

    public Map getCurrentSessionIds() {
        return this.currentSessionIds;
    }
    
    public Map getRequestedSessionIds() {
        return this.requestedSessionIds;
    }
    
    public String getDeadRequestedSessionId() {
        return this.deadRequestedSessionId;
    }

    public HostGroup getHostGroup() {
        return this.hostGroup;
    }

    public WebAppConfiguration getWebAppConfig() {
        return this.webappConfig;
    }

    public ServletConfiguration getServletConfig() {
        return this.servletConfig;
    }
    public void setWebAppConfig(WebAppConfiguration webAppConfig) {
        this.webappConfig = webAppConfig;
    }
    
    public void setServletConfig(ServletConfiguration servletConfig) {
        this.servletConfig = servletConfig;
    }
    
    public void setRequestURI(String requestURI) {
        this.requestURI = requestURI;
    }

    public void setServletPath(String servletPath) {
        this.servletPath = servletPath;
    }

    public void setPathInfo(String pathInfo) {
        this.pathInfo = pathInfo;
    }

    public void setRemoteUser(AuthenticationPrincipal user) {
        this.authenticatedUser = user;
    }

    public void setRequestAttributeListeners(
            ServletRequestAttributeListener ral[]) {
        this.requestAttributeListeners = ral;
    }

    /**
     * Gets parameters from the url encoded parameter string
     */
    public static void extractParameters(String urlEncodedParams,
            String encoding, Map outputParams, boolean overwrite) {
        Logger.log(Logger.DEBUG, Launcher.RESOURCES,
                "WinstoneRequest.ParsingParameters", new String[] {
                        urlEncodedParams, encoding });
        StringTokenizer st = new StringTokenizer(urlEncodedParams, "&", false);
        Set overwrittenParamNames = null;
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            int equalPos = token.indexOf('=');
            try {
                String decodedNameDefault = decodeURLToken(equalPos == -1 ? token 
                        : token.substring(0, equalPos));
                String decodedValueDefault = (equalPos == -1 ? "" 
                        : decodeURLToken(token.substring(equalPos + 1)));
                String decodedName = (encoding == null ? decodedNameDefault
                        : new String(decodedNameDefault.getBytes("8859_1"), encoding));
                String decodedValue = (encoding == null ? decodedValueDefault
                        : new String(decodedValueDefault.getBytes("8859_1"), encoding));

                Object already;
                if (overwrite) {
                    if (overwrittenParamNames == null) {
                        overwrittenParamNames = new HashSet();
                    }
                    if (!overwrittenParamNames.contains(decodedName)) {
                        overwrittenParamNames.add(decodedName);
                        outputParams.remove(decodedName);
                    }
                }
                already = outputParams.get(decodedName);
                if (already == null) {
                    outputParams.put(decodedName, decodedValue);
                } else if (already instanceof String) {
                    String pair[] = new String[2];
                    pair[0] = (String) already;
                    pair[1] = decodedValue;
                    outputParams.put(decodedName, pair);
                } else if (already instanceof String[]) {
                    String alreadyArray[] = (String[]) already;
                    String oneMore[] = new String[alreadyArray.length + 1];
                    System.arraycopy(alreadyArray, 0, oneMore, 0,
                            alreadyArray.length);
                    oneMore[oneMore.length - 1] = decodedValue;
                    outputParams.put(decodedName, oneMore);
                } else {
                    Logger.log(Logger.WARNING, Launcher.RESOURCES,
                            "WinstoneRequest.UnknownParameterType",
                            decodedName + " = " + decodedValue.getClass());
                }
            } catch (UnsupportedEncodingException err) {
                Logger.log(Logger.ERROR, Launcher.RESOURCES,
                        "WinstoneRequest.ErrorParameters", err);
            }
        }
    }

    /**
     * For decoding the URL encoding used on query strings
     */
    public static String decodeURLToken(String in) {
        int len = in.length();
        StringBuilder workspace = new StringBuilder(len);
        for (int n = 0; n < len; n++) {
            char thisChar = in.charAt(n);
            if (thisChar == '+') {
                workspace.append(' ');
            } else if (thisChar == '%') {
                String token;
                int inc = 2, beg = 1, end = 3;
                if ((n + 1 < len) && (in.charAt(n + 1) == 'u')) {
                    beg = 2;
                    end = 6;
                    inc = 5;
                }
                token = in.substring(Math.min(n + beg, len), Math.min(n + end, len));
                try {
                    workspace.append((char) (Integer.parseInt(token, 16)));
                    n += inc;
                } catch (RuntimeException err) {
                    Logger.log(Logger.WARNING, Launcher.RESOURCES,
                            "WinstoneRequest.InvalidURLTokenChar", token);
                    workspace.append(thisChar);
                }
            } else {
                workspace.append(thisChar);
            }
        }
        return workspace.toString();
    }    

    /**
     * This takes the parameters in the body of the request and puts them into
     * the parameters map.
     */
    public void parseRequestParameters() {
        if ((parsedParameters != null) && !parsedParameters.booleanValue()) {
            Logger.log(Logger.WARNING, Launcher.RESOURCES,
                    "WinstoneRequest.BothMethods");
            this.parsedParameters = Boolean.TRUE;
        } else if (parsedParameters == null) {
            Map workingParameters = new HashMap();
            try {
                // Parse query string from request
//                if ((method.equals(METHOD_GET) || method.equals(METHOD_HEAD) || 
//                        method.equals(METHOD_POST)) && 
                if (this.queryString != null) {
                    extractParameters(getQueryString(), this.encoding, workingParameters, false);
                    Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES,
                            "WinstoneRequest.ParamLine", "" + workingParameters);
                }
                 
                if (method.equals(METHOD_POST) && (contentType != null)
                        && (contentType.equals(POST_PARAMETERS)
                        || contentType.startsWith(POST_PARAMETERS + ";"))) {
                    Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES,
                            "WinstoneRequest.ParsingBodyParameters");

                    // Parse params
                    byte paramBuffer[] = new byte[contentLength];
                    int readCount = this.inputData.read(paramBuffer);
                    if (readCount != contentLength)
                        Logger.log(Logger.WARNING, Launcher.RESOURCES,
                                "WinstoneRequest.IncorrectContentLength",
                                new String[] { contentLength + "",
                                        readCount + "" });
                    String paramLine = (this.encoding == null ? new String(
                            paramBuffer) : new String(paramBuffer,
                            this.encoding));
                    extractParameters(paramLine.trim(), this.encoding, workingParameters, false);
                    Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES,
                            "WinstoneRequest.ParamLine", "" + workingParameters);
                } 
                
                this.parameters.putAll(workingParameters);
                this.parsedParameters = Boolean.TRUE;
            } catch (Throwable err) {
                Logger.log(Logger.ERROR, Launcher.RESOURCES,
                        "WinstoneRequest.ErrorBodyParameters", err);
                this.parsedParameters = null;
            }
        }
    }

    /**
     * Go through the list of headers, and build the headers/cookies arrays for
     * the request object.
     */
    

    private static String nextToken(StringTokenizer st) {
        if (st.hasMoreTokens()) {
            return st.nextToken();
        } else {
            return null;
        }
    }

    private void parseCookieLine(String headerValue, List<Cookie> cookieList) {
        StringTokenizer st = new StringTokenizer(headerValue, ";", false);
        int version = 0;
        String cookieLine = nextToken(st);

        // check cookie version flag
        if ((cookieLine != null) && cookieLine.startsWith("$Version=")) {
            int equalPos = cookieLine.indexOf('=');
            try {
                version = Integer.parseInt(extractFromQuotes(
                        cookieLine.substring(equalPos + 1).trim()));
            } catch (NumberFormatException err) {
                version = 0;
            }
            cookieLine = nextToken(st);
        }

        // process remainder - parameters
        while (cookieLine != null) {
            cookieLine = cookieLine.trim();
            int equalPos = cookieLine.indexOf('=');
            if (equalPos == -1) {
                // next token
                cookieLine = nextToken(st);
            } else {
                String name = cookieLine.substring(0, equalPos);
                String value = extractFromQuotes(cookieLine.substring(equalPos + 1));
                Cookie thisCookie = new Cookie(name, value);
                thisCookie.setVersion(version);
                thisCookie.setSecure(isSecure());
                cookieList.add(thisCookie);

                // check for path / domain / port
                cookieLine = nextToken(st);
                while ((cookieLine != null) && cookieLine.trim().startsWith("$")) {
                    cookieLine = cookieLine.trim();
                    equalPos = cookieLine.indexOf('=');
                    String attrValue = equalPos == -1 ? "" : cookieLine
                            .substring(equalPos + 1).trim();
                    if (cookieLine.startsWith("$Path")) {
                        thisCookie.setPath(extractFromQuotes(attrValue));
                    } else if (cookieLine.startsWith("$Domain")) {
                        thisCookie.setDomain(extractFromQuotes(attrValue));
                    }
                    cookieLine = nextToken(st);
                }

                Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES,
                        "WinstoneRequest.CookieFound", thisCookie.toString());
                if (thisCookie.getName().equals(WinstoneSession.SESSION_COOKIE_NAME)) {
                    // Find a context that manages this key
                    HostConfiguration hostConfig = this.hostGroup.getHostByName(this.serverName);
                    WebAppConfiguration ownerContext = hostConfig.getWebAppBySessionKey(thisCookie.getValue());
                    if (ownerContext != null) {
                        this.requestedSessionIds.put(ownerContext.getContextPath(), 
                                thisCookie.getValue());
                        this.currentSessionIds.put(ownerContext.getContextPath(), 
                                thisCookie.getValue());
                    }
                    // If not found, it was probably dead
                    else {
                        this.deadRequestedSessionId = thisCookie.getValue();
                    }
//                    this.requestedSessionId = thisCookie.getValue();
//                    this.currentSessionId = thisCookie.getValue();
                    Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES,
                            "WinstoneRequest.SessionCookieFound", 
                            new String[] {thisCookie.getValue(), 
                            ownerContext == null ? "" : "prefix:" + ownerContext.getContextPath()});
                }
            }
        }
    }

    private static String extractFromQuotes(String input) {
        if ((input != null) && input.startsWith("\"") && input.endsWith("\"")) {
            return input.substring(1, input.length() - 1);
        } else {
            return input;
        }
    }

    private List<Locale> parseLocales(String header) {
        // Strip out the whitespace
        StringBuilder lb = new StringBuilder();
        for (int n = 0; n < header.length(); n++) {
            char c = header.charAt(n);
            if (!Character.isWhitespace(c))
                lb.append(c);
        }

        // Tokenize by commas
        Map localeEntries = new HashMap();
        StringTokenizer commaTK = new StringTokenizer(lb.toString(), ",", false);
        for (; commaTK.hasMoreTokens();) {
            String clause = commaTK.nextToken();

            // Tokenize by semicolon
            Float quality = new Float(1);
            if (clause.indexOf(";q=") != -1) {
                int pos = clause.indexOf(";q=");
                try {
                    quality = new Float(clause.substring(pos + 3));
                } catch (NumberFormatException err) {
                    quality = new Float(0);
                }
                clause = clause.substring(0, pos);
            }

            // Build the locale
            String language;
            String country = "";
            String variant = "";
            int dpos = clause.indexOf('-');
            if (dpos == -1)
                language = clause;
            else {
                language = clause.substring(0, dpos);
                String remainder = clause.substring(dpos + 1);
                int d2pos = remainder.indexOf('-');
                if (d2pos == -1)
                    country = remainder;
                else {
                    country = remainder.substring(0, d2pos);
                    variant = remainder.substring(d2pos + 1);
                }
            }
            Locale loc = new Locale(language, country, variant);

            // Put into list by quality
            List localeList = (List) localeEntries.get(quality);
            if (localeList == null) {
                localeList = new ArrayList();
                localeEntries.put(quality, localeList);
            }
            localeList.add(loc);
        }

        // Extract and build the list
        Float orderKeys[] = (Float[]) localeEntries.keySet().toArray(new Float[0]);
        Arrays.sort(orderKeys);
        List outputLocaleList = new ArrayList();
        for (int n = 0; n < orderKeys.length; n++) {
            // Skip backwards through the list of maps and add to the output list
            int reversedIndex = (orderKeys.length - 1) - n;
            if ((orderKeys[reversedIndex].floatValue() <= 0)
                    || (orderKeys[reversedIndex].floatValue() > 1))
                continue;
            List localeList = (List) localeEntries.get(orderKeys[reversedIndex]);
            for (Iterator i = localeList.iterator(); i.hasNext();)
                outputLocaleList.add(i.next());
        }

        return outputLocaleList;
    }

    public void addIncludeQueryParameters(String queryString) {
        Map<String, String> lastParams = new HashMap<String, String>();
        if (!this.parametersStack.isEmpty()) {
            lastParams.putAll((Map) this.parametersStack.peek());
        }
        Map<String, String> newQueryParams = new HashMap<String, String>();
        if (queryString != null) {
            extractParameters(queryString, this.encoding, newQueryParams, false);
        }
        lastParams.putAll(newQueryParams);
        this.parametersStack.push(lastParams);
    }

    public void addIncludeAttributes(String requestURI, String contextPath,
            String servletPath, String pathInfo, String queryString) {
        Map includeAttributes = new HashMap();
        if (requestURI != null) {
            includeAttributes.put(RequestDispatcher.INCLUDE_REQUEST_URI, requestURI);
        }
        if (contextPath != null) {
            includeAttributes.put(RequestDispatcher.INCLUDE_CONTEXT_PATH, contextPath);
        }
        if (servletPath != null) {
            includeAttributes.put(RequestDispatcher.INCLUDE_SERVLET_PATH, servletPath);
        }
        if (pathInfo != null) {
            includeAttributes.put(RequestDispatcher.INCLUDE_PATH_INFO, pathInfo);
        }
        if (queryString != null) {
            includeAttributes.put(RequestDispatcher.INCLUDE_QUERY_STRING, queryString);
        }
        this.attributesStack.push(includeAttributes);
    }
    
    public void removeIncludeQueryString() {
        if (!this.parametersStack.isEmpty()) {
            this.parametersStack.pop(); 
        }
    }
    
    public void clearIncludeStackForForward() {
        this.parametersStack.clear();
        this.attributesStack.clear();
    }
    
    public void setForwardQueryString(String forwardQueryString) {
//        this.forwardedParameters.clear();
        
        // Parse query string from include / forward
        if (forwardQueryString != null) {
            String oldQueryString = this.queryString == null ? "" : this.queryString;
            boolean needJoiner = !forwardQueryString.equals("") && !oldQueryString.equals("");  
            this.queryString = forwardQueryString + (needJoiner ? "&" : "") + oldQueryString;
            
            if (this.parsedParameters != null) {
                Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES,
                        "WinstoneRequest.ParsingParameters", new String[] {
                        forwardQueryString, this.encoding });
                extractParameters(forwardQueryString, this.encoding, this.parameters, true);
                Logger.log(Logger.FULL_DEBUG, Launcher.RESOURCES,
                        "WinstoneRequest.ParamLine", "" + this.parameters);
            }
        }

    }
    
    public void removeIncludeAttributes() {
        if (!this.attributesStack.isEmpty()) {
            this.attributesStack.pop();
        }
    }
    
    // Implementation methods for the servlet request stuff
    @Override
    public Object getAttribute(String name) {
        if (!this.attributesStack.isEmpty()) {
            Map includedAttributes = (Map) this.attributesStack.peek();
            Object value = includedAttributes.get(name);
            if (value != null) {
                return value;
            }
        }
        return this.attributes.get(name);
    }    
    
    @Override
    public Enumeration getAttributeNames() {        
        Iterable attributeNames = attributes.keySet();
        if (!this.attributesStack.isEmpty()) {
            Map<String, Object> includedAttributes = this.attributesStack.peek();
            attributeNames = Iterables.concat(attributeNames, includedAttributes.keySet());
        }
        final Iterator attributeNamesIterator = attributeNames.iterator();
        return new Enumeration() {
            @Override
            public boolean hasMoreElements() {
                return attributeNamesIterator.hasNext(); 
            }

            @Override
            public Object nextElement() {
                return attributeNamesIterator.next();
            }
        };
    }

    
    
    @Override
    public void removeAttribute(final String name) {
        final Object value = attributes.get(name);
        if (value == null)
            return;

        // fire event
        if (this.requestAttributeListeners != null) {
            final ServletRequestAttributeEvent event = new ServletRequestAttributeEvent(
                webappConfig, this, name, value); 
            EventSender.broadcastEvent(this.requestAttributeListeners, webappConfig,
                    new EventSender<ServletRequestAttributeListener>(){
                        @Override
                        public void sendEvent(ServletRequestAttributeListener target) {
                            target.attributeRemoved(event);
                        }});
        }
        this.attributes.remove(name);
    }

    @Override
    public void setAttribute(String name, Object o) {
        if ((name != null) && (o != null)) {
            Object oldValue = attributes.get(name);
            attributes.put(name, o); // make sure it's set at the top level

            // fire event
            if (this.requestAttributeListeners != null) {
                final ServletRequestAttributeEvent event = new ServletRequestAttributeEvent(
                    webappConfig, this, name, o); 
                if (oldValue == null) {
                    EventSender.broadcastEvent(this.requestAttributeListeners, webappConfig,
                            new EventSender<ServletRequestAttributeListener>(){
                                @Override
                                public void sendEvent(ServletRequestAttributeListener target) {
                                    target.attributeAdded(event);
                                }});                    
                } else {
                    EventSender.broadcastEvent(this.requestAttributeListeners, webappConfig,
                            new EventSender<ServletRequestAttributeListener>(){
                                @Override
                                public void sendEvent(ServletRequestAttributeListener target) {
                                    target.attributeReplaced(event);
                                }});                    
                }
            }
        } else if (name != null) {
            removeAttribute(name);
        }
    }
    
    @Override
    public String getCharacterEncoding() {
        return this.encoding;
    }

    @Override
    public void setCharacterEncoding(String encoding) throws UnsupportedEncodingException {
        "blah".getBytes(encoding); // throws an exception if the encoding is unsupported
        if (this.inputReader == null) {
            Logger.log(Logger.DEBUG, Launcher.RESOURCES, "WinstoneRequest.SetCharEncoding",
                    new String[] { this.encoding, encoding });
            this.encoding = encoding;
        }
    }

    @Override
    public int getContentLength() {
        return this.contentLength;
    }

    @Override
    public String getContentType() {
        return this.contentType;
    }

    @Override
    public Locale getLocale() {
        getLocales();
        return locales.get(0);
    }

    @Override
    public Enumeration getLocales() {
        if (locales == null) {
            locales = parseLocales(getHeader(HttpHeaders.Names.ACCEPT_LANGUAGE));
            if (locales.isEmpty()) {
                locales.add(Locale.getDefault());
            }
        }
        return Collections.enumeration(locales);
    }

    @Override
    public String getProtocol() {
        return request.getProtocolVersion().toString();
    }

    @Override
    public String getScheme() {
        return this.scheme;
    }

    @Override
    public boolean isSecure() {
        return this.isSecure;
    }

    @Override
    public BufferedReader getReader() throws IOException {
        if (this.inputReader != null) {
            return this.inputReader;
        } else {
            if (this.parsedParameters != null) {
                if (this.parsedParameters.equals(Boolean.TRUE)) {
                    Logger.log(Logger.WARNING, Launcher.RESOURCES, "WinstoneRequest.BothMethodsReader");
                } else {
                    throw new IllegalStateException(Launcher.RESOURCES.getString(
                            "WinstoneRequest.CalledReaderAfterStream"));
                }
            }
            if (this.encoding != null) {
                this.inputReader = new BufferedReader(new InputStreamReader(
                        this.inputData, this.encoding));
            } else {
                this.inputReader = new BufferedReader(new InputStreamReader(
                        this.inputData));
            }
            this.parsedParameters = Boolean.FALSE;
            return this.inputReader;
        }
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        if (this.inputReader != null) {
            throw new IllegalStateException(Launcher.RESOURCES.getString(
                    "WinstoneRequest.CalledStreamAfterReader"));
        }
        if (this.parsedParameters != null) {
            if (this.parsedParameters.equals(Boolean.TRUE)) {
                Logger.log(Logger.WARNING, Launcher.RESOURCES, "WinstoneRequest.BothMethods");
            }
        }
        this.parsedParameters = Boolean.FALSE;
        return this.inputData;
    }

    @Override
    public String getParameter(String name) {
        parseRequestParameters();
        Object param = null;
        if (!this.parametersStack.isEmpty()) {
            param = ((Map) this.parametersStack.peek()).get(name);
        }
//        if ((param == null) && this.forwardedParameters.get(name) != null) {
//            param = this.forwardedParameters.get(name);
//        }
        if (param == null) {
            param = this.parameters.get(name);
        }
        if (param == null)
            return null;
        else if (param instanceof String)
            return (String) param;
        else if (param instanceof String[])
            return ((String[]) param)[0];
        else
            return param.toString();
    }

    @Override
    public Enumeration getParameterNames() {
        parseRequestParameters();
        Set parameterKeys = new HashSet(this.parameters.keySet());
//        parameterKeys.addAll(this.forwardedParameters.keySet());
        if (!this.parametersStack.isEmpty()) {
            parameterKeys.addAll(((Map) this.parametersStack.peek()).keySet());
        }
        return Collections.enumeration(parameterKeys);
    }

    @Override
    public String[] getParameterValues(String name) {
        parseRequestParameters();
        Object param = null;
        if (!this.parametersStack.isEmpty()) {
            param = ((Map) this.parametersStack.peek()).get(name);
        }
//        if ((param == null) && this.forwardedParameters.get(name) != null) {
//            param = this.forwardedParameters.get(name);
//        }
        if (param == null) {
            param = this.parameters.get(name);
        }
        if (param == null)
            return null;
        else if (param instanceof String) {
            return new String[] {(String) param};
        } else if (param instanceof String[])
            return (String[]) param;
        else
            throw new WinstoneException(Launcher.RESOURCES.getString(
                    "WinstoneRequest.UnknownParameterType", name + " - "
                            + param.getClass()));
    }

    @Override
    public Map getParameterMap() {
        Hashtable paramMap = new Hashtable();
        for (Enumeration names = this.getParameterNames(); names
                .hasMoreElements();) {
            String name = (String) names.nextElement();
            paramMap.put(name, getParameterValues(name));
        }
        return paramMap;
    }

    @Override
    public String getServerName() {
        if (serverName == null) {
            String hostName = HttpHeaders.getHost(request, "unknown");            
            int endOfHostName;
            if (hostName.startsWith("[")) {
                endOfHostName = hostName.indexOf("]", 1);
                if (endOfHostName < 0) {
                    endOfHostName = hostName.length();
                    serverName = hostName.substring(1);
                }
                else {
                    serverName = hostName.substring(1, endOfHostName);
                    endOfHostName++;
                }
            }
            else {
                endOfHostName = hostName.indexOf(":", 1);
                if (endOfHostName < 0) {
                    serverName = hostName;
                    endOfHostName = hostName.length();
                }
                else {
                    serverName = hostName.substring(0, endOfHostName);
                }
            }
            
            if (endOfHostName < hostName.length() 
                && hostName.charAt(endOfHostName) == ':') {
                // Port is included in host name
                try {
                    serverPort = Integer.parseInt(hostName.substring(endOfHostName + 1));
                }
                catch (NumberFormatException e) {}                
            }
            if (serverPort == -1) {
                if ("https".equalsIgnoreCase(scheme)) {
                    serverPort = 443;
                }
                else {
                    serverPort = 80; // Assume port 80 for all other cases
                }
                
            }
        }
        return serverName;
    }

    @Override
    public int getServerPort() {
        getServerName();
        return serverPort;
    }

    @Override
    public String getRemoteAddr() {
        return this.remoteIP;
    }

    @Override
    public String getRemoteHost() {
        return this.remoteName;
    }

    @Override
    public int getRemotePort() {
        return this.remotePort;
    }

    @Override
    public String getLocalAddr() {
        return this.localAddr;
    }

    @Override
    public String getLocalName() {
        return this.localName;
    }

    @Override
    public int getLocalPort() {
        return this.localPort;
    }

    @Override
    public javax.servlet.RequestDispatcher getRequestDispatcher(String path) {
        if (path.startsWith("/"))
            return this.webappConfig.getRequestDispatcher(path);

        // Take the servlet path + pathInfo, and make an absolute path
        String fullPath = getServletPath()
                + (getPathInfo() == null ? "" : getPathInfo());
        int lastSlash = fullPath.lastIndexOf('/');
        String currentDir = (lastSlash == -1 ? "/" : fullPath.substring(0,
                lastSlash + 1));
        return this.webappConfig.getRequestDispatcher(currentDir + path);
    }

    // Now the stuff for HttpServletRequest
    @Override
    public String getContextPath() {
        return this.webappConfig.getContextPath();
    }

    @Override
    public Cookie[] getCookies() {
        if (!parsedCookies) {            
            List<Cookie> cookieList = new ArrayList<Cookie>();
            for (String cookieString : Iterables.concat(
                    request.getHeaders(HttpHeaders.Names.COOKIE),
                    request.getHeaders(IN_COOKIE_HEADER2))) {
                parseCookieLine(cookieString, cookieList);
            }
            if (cookieList.size() > 0) {
                cookies = cookieList.toArray(EMPTY_COOKIE_ARRAY);                
            }            
            parsedCookies = true;
        }                
        return this.cookies;
    }

    @Override
    public long getDateHeader(String name) {
        String dateHeader = getHeader(name);
        if (dateHeader == null) {
            return -1;
        } else try {
            Date date;
            synchronized (headerDF) {
                date = headerDF.parse(dateHeader);
            }
            return date.getTime();
        } catch (java.text.ParseException err) {
            throw new IllegalArgumentException(Launcher.RESOURCES.getString(
                    "WinstoneRequest.BadDate", dateHeader));
        }
    }

    @Override
    public int getIntHeader(String name) {
        String header = getHeader(name);
        return header == null ? -1 : Integer.parseInt(header);
    }

    @Override
    public String getHeader(String name) {
        return request.getHeader(name);
    }

    @Override
    public Enumeration getHeaderNames() {
        return Collections.enumeration(Collections2.filter(request.getHeaderNames(),
            new Predicate<String>(){
                @Override
                public boolean apply(String t) {
                    return !HttpHeaders.Names.COOKIE.equalsIgnoreCase(t)
                        && !IN_COOKIE_HEADER2.equalsIgnoreCase(t);
                }
            }));
    }

    @Override
    public Enumeration getHeaders(String name) {
        return Collections.enumeration(request.getHeaders(name));
    }

    @Override
    public String getMethod() {
        return request.getMethod().getName();
    }

    @Override
    public String getPathInfo() {
        return this.pathInfo;
    }

    @Override
    public String getPathTranslated() {
        return this.webappConfig.getRealPath(this.pathInfo);
    }

    @Override
    public String getQueryString() {
        if (queryString == null) {
            queryString = "";
            String requestURI = getRequestURI();
            if (requestURI != null) {
                int indexOfQuestionMark = requestURI.indexOf("?");
                if (indexOfQuestionMark != -1) {
                    queryString = requestURI.substring(indexOfQuestionMark + 1);
                }
            }
        }        
        return queryString;
    }

    @Override
    public String getRequestURI() {
        return requestURI == null ? request.getUri() : requestURI;
    }

    @Override
    public String getServletPath() {
        return this.servletPath;
    }

    @Override
    public String getRequestedSessionId() {
        String actualSessionId = (String) this.requestedSessionIds.get(this.webappConfig.getContextPath());
        if (actualSessionId != null) {
            return actualSessionId;
        } else {
            return this.deadRequestedSessionId;
        }
    }

    @Override
    public StringBuffer getRequestURL() {
        StringBuffer url = new StringBuffer();
        url.append(getScheme()).append("://");
        url.append(getServerName());
        if (!((getServerPort() == 80) && getScheme().equals("http"))
                && !((getServerPort() == 443) && getScheme().equals("https")))
            url.append(':').append(getServerPort());
        url.append(getRequestURI()); // need encoded form, so can't use servlet path + path info
        return url;
    }

    @Override
    public Principal getUserPrincipal() {
        return this.authenticatedUser;
    }

    @Override
    public boolean isUserInRole(String role) {
        if (this.authenticatedUser == null)
            return false;
        else if (this.servletConfig.getSecurityRoleRefs() == null)
            return this.authenticatedUser.isUserIsInRole(role);
        else {
            String replacedRole = (String) this.servletConfig.getSecurityRoleRefs().get(role);
            return this.authenticatedUser
                    .isUserIsInRole(replacedRole == null ? role : replacedRole);
        }
    }

    @Override
    public String getAuthType() {
        return this.authenticatedUser == null ? null : this.authenticatedUser
                .getAuthType();
    }

    @Override
    public String getRemoteUser() {
        return this.authenticatedUser == null ? null : this.authenticatedUser
                .getName();
    }

    @Override
    public boolean isRequestedSessionIdFromCookie() {
        return (getRequestedSessionId() != null);
    }

    @Override
    public boolean isRequestedSessionIdFromURL() {
        return false;
    }

    @Override
    public boolean isRequestedSessionIdValid() {
        String requestedId = getRequestedSessionId();
        if (requestedId == null) {
            return false;
        }
        WinstoneSession ws = this.webappConfig.getSessionById(requestedId, false);
        return (ws != null);
//        if (ws == null) {
//            return false;
//        } else {
//            return (validationCheck(ws, System.currentTimeMillis(), false) != null);
//        }
    }

    @Override
    public HttpSession getSession() {
        return getSession(true);
    }

    @Override
    public HttpSession getSession(boolean create) {
        String cookieValue = (String) this.currentSessionIds.get(this.webappConfig.getContextPath());

        // Handle the null case
        if (cookieValue == null) {
            if (!create) {
                return null;
            } else {
                cookieValue = makeNewSession().getId();
            }
        }

        // Now get the session object
        WinstoneSession session = this.webappConfig.getSessionById(cookieValue, false);
        if (session != null) {
//            long nowDate = System.currentTimeMillis();
//            session = validationCheck(session, nowDate, create);
//            if (session == null) {
//                this.currentSessionIds.remove(this.webappConfig.getContextPath());
//            }
        }
        if (create && (session == null)) {
            session = makeNewSession();
        }
        if (session != null) {
            this.usedSessions.add(session);
            session.addUsed(this);
        }
        return session;
    }

    /**
     * Make a new session, and return the id
     */
    private WinstoneSession makeNewSession() {
        String cookieValue = "Winstone_" + this.remoteIP + "_"
                + this.serverPort + "_" + System.currentTimeMillis() + rnd.nextLong();
        byte digestBytes[] = this.md5Digester.digest(cookieValue.getBytes());

        // Write out in hex format
        char outArray[] = new char[32];
        for (int n = 0; n < digestBytes.length; n++) {
            int hiNibble = (digestBytes[n] & 0xFF) >> 4;
            int loNibble = (digestBytes[n] & 0xF);
            outArray[2 * n] = (hiNibble > 9 ? (char) (hiNibble + 87)
                    : (char) (hiNibble + 48));
            outArray[2 * n + 1] = (loNibble > 9 ? (char) (loNibble + 87)
                    : (char) (loNibble + 48));
        }

        String newSessionId = new String(outArray);
        this.currentSessionIds.put(this.webappConfig.getContextPath(), newSessionId);
        return this.webappConfig.makeNewSession(newSessionId);
    }

    public void markSessionsAsRequestFinished(long lastAccessedTime, boolean saveSessions) {
        for (Iterator i = this.usedSessions.iterator(); i.hasNext(); ) {
            WinstoneSession session = (WinstoneSession) i.next();
            session.setLastAccessedDate(lastAccessedTime);
            session.removeUsed(this);
            if (saveSessions) {
                session.saveToTemp();
            }
        }
        this.usedSessions.clear();
    }
    
    /**
     * @deprecated
     */
    public String getRealPath(String path) {
        return this.webappConfig.getRealPath(path);
    }

    /**
     * @deprecated
     */
    public boolean isRequestedSessionIdFromUrl() {
        return isRequestedSessionIdFromURL();
    }

    @Override
    public boolean authenticate(HttpServletResponse hsr) throws IOException, ServletException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void login(String string, String string1) throws ServletException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void logout() throws ServletException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Collection<Part> getParts() throws IOException, ServletException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Part getPart(String string) throws IOException, ServletException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ServletContext getServletContext() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public AsyncContext startAsync() throws IllegalStateException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public AsyncContext startAsync(ServletRequest sr, ServletResponse sr1) throws IllegalStateException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean isAsyncStarted() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean isAsyncSupported() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public AsyncContext getAsyncContext() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public DispatcherType getDispatcherType() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
