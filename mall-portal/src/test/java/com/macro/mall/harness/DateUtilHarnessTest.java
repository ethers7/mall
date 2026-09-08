package com.macro.mall.harness;

import com.macro.mall.portal.util.DateUtil;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import static org.junit.jupiter.api.Assertions.assertEquals;
/** Date helpers used by portal order windows — no Spring context. */
class DateUtilHarnessTest {

    @Test
    void getDateZerosTimeComponent() {
        Calendar cal = new GregorianCalendar(2024, Calendar.JUNE, 15, 13, 45, 22);
        Date dateOnly = DateUtil.getDate(cal.getTime());
        Calendar out = Calendar.getInstance();
        out.setTime(dateOnly);
        assertEquals(2024, out.get(Calendar.YEAR));
        assertEquals(Calendar.JUNE, out.get(Calendar.MONTH));
        assertEquals(15, out.get(Calendar.DAY_OF_MONTH));
        assertEquals(0, out.get(Calendar.HOUR_OF_DAY));
        assertEquals(0, out.get(Calendar.MINUTE));
        assertEquals(0, out.get(Calendar.SECOND));
    }

    @Test
    void getTimeKeepsClockAndEpochDate() {
        Calendar cal = new GregorianCalendar(2024, Calendar.JUNE, 15, 13, 45, 22);
        Date timeOnly = DateUtil.getTime(cal.getTime());
        Calendar out = Calendar.getInstance();
        out.setTime(timeOnly);
        assertEquals(13, out.get(Calendar.HOUR_OF_DAY));
        assertEquals(45, out.get(Calendar.MINUTE));
    }
}
