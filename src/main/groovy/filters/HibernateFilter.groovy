package filters

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.filter.Filter;
import ch.qos.logback.core.spi.FilterReply;

public class HibernateFilter extends Filter<ILoggingEvent> {

    @Override
    public FilterReply decide(ILoggingEvent event) {
        if (event.getMessage().contains("HHH90000022")) {
            return FilterReply.DENY;
        }
        else if (event.getMessage().contains("Accessing config key")) {
            return FilterReply.DENY;
        }
        else if (event.getMessage().contains("batch acquisition of 0")) {
            return FilterReply.DENY;
        }
        else if (event.getMessage().contains("SQL Warning Code")) {
            return FilterReply.DENY;
        }
        else if (event.getMessage().contains("execute S_1")) {
            return FilterReply.DENY;
        }
        else if (event.getMessage().contains("SET SESSION CHARACTERISTICS")) {
            return FilterReply.DENY;
        }
        else if (event.getMessage().contains("COMMIT")) {
            return FilterReply.DENY;
        }
        else {
            return FilterReply.NEUTRAL;
        }
    }
}
