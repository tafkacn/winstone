package winstone;

/**
 * Generic wrapper for dispatching events to various servlet event listeners. 
 * @author raymond.mak
 */
abstract public class EventSender<T> {
    abstract public void sendEvent(T target);
    public static <E> void broadcastEvent(
        E[] listeners, 
        WebAppConfiguration webAppConfig,
        EventSender<E> eventSender) {
        if (listeners != null && listeners.length > 0) {
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            try {
                Thread.currentThread().setContextClassLoader(webAppConfig.getLoader());
                for (int i = 0; i < listeners.length; i++) {
                    eventSender.sendEvent(listeners[i]);
                }
            }
            finally {
                Thread.currentThread().setContextClassLoader(classLoader);
            }
        }
    }
}
