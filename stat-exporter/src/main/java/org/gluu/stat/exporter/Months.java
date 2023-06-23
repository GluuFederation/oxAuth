package org.gluu.stat.exporter;

import com.google.common.base.Joiner;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Yuriy Z
 */
public class Months {

    public static final DateTimeFormatter YYYYMM = DateTimeFormatter.ofPattern("yyyyMM");

    private Months() {
    }

    public static String getLastMonthsAsString(int count) {
        return Joiner.on(" ").join(Months.getLastMonths(count));
    }

    public static Set<String> getLastMonths(int shiftCount) {
        Set<String> result = new HashSet<>();

        LocalDate now = LocalDate.now();
        for (int i = 0; i < shiftCount; i++) {
            final LocalDate date = now.minusMonths(i);
            result.add(date.format(YYYYMM));
        }

        return result;
    }
}
