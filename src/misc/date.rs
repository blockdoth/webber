use std::fmt;
use std::fmt::{Debug, Display};
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub day: i64,
    pub hour: u64,
    pub minute: u64,
    pub second: u64,
}

impl Date {
    pub fn default() -> Self {
        Self {
            day: 0,
            hour: 0,
            minute: 0,
            second: 0,
        }
    }
    pub fn days() -> i64 {
        let date = Self::from_systemtime(SystemTime::now()).expect("really fucked");

        date.day
    }

    pub fn format(&self, format: &DateFormat) -> String {
        use DateFormat::*;

        let (year, month, day) = Self::civil_from_days(self.day);

        let month_name = [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ][month as usize - 1];

        let month_short = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ][month as usize - 1];

        let weekday_idx = self.day.rem_euclid(7) as usize;

        // 1970-01-01 was Thursday
        let weekday = [
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
            "Monday",
            "Tuesday",
            "Wednesday",
        ][weekday_idx];

        let weekday_short = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][weekday_idx];

        let hour = self.hour;
        let minute = self.minute;
        let second = self.second;

        match format {
            Rfc1123 => format!(
                "{weekday_short}, {day:02} {month_short} {year:04} {hour:02}:{minute:02}:{second:02} GMT"
            ),
            Iso8601 => format!("{year:04}-{month:02}-{day:02}T {hour:02}:{minute:02}:{second:02}Z"),
            IsoDate => format!("{year:04}-{month:02}-{day:02}"),
            DateTime => format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"),
            Date => format!("{year:04}/{month:02}/{day:02}"),
            Time => format!("{hour:02}:{minute:02}:{second:02}"),
            Year => year.to_string(),
            Month => format!("{month:02}"),
            MonthName => month_name.to_string(),
            MonthShort => month_short.to_string(),
            Day => format!("{day:02}"),
            Weekday => weekday.to_string(),
            WeekdayShort => weekday_short.to_string(),
            MonthNameYearDay => format!("{month_name} {day:02}, {year:04}"),
            MonthNameShortYearDay => format!("{month_short} {day:02}, {year:04}"),
        }
    }

    pub fn from_systemtime(time: SystemTime) -> Result<Date, SystemTimeError> {
        let unix_seconds = time.duration_since(UNIX_EPOCH)?.as_secs() as i64;

        let day = unix_seconds.div_euclid(86_400);
        let seconds_today = unix_seconds.rem_euclid(86_400) as u64;

        let hour = seconds_today / 3_600;
        let minute = (seconds_today % 3_600) / 60;
        let second = seconds_today % 60;

        Ok(Date {
            day,
            hour,
            minute,
            second,
        })
    }

    pub fn from_exif_date(date_str: String) -> Option<Self> {
        let (date, time) = date_str.split_once(' ')?;

        let mut date_parts = date.split(':');
        let year: i32 = date_parts.next()?.parse().ok()?;
        let month: u32 = date_parts.next()?.parse().ok()?;
        let day: u32 = date_parts.next()?.parse().ok()?;

        let mut time_parts = time.split(':');
        let hour: u64 = time_parts.next()?.parse().ok()?;
        let minute: u64 = time_parts.next()?.parse().ok()?;
        let second: u64 = time_parts.next()?.parse().ok()?;

        Some(Self {
            day: Self::days_from_civil(year, month, day),
            hour,
            minute,
            second,
        })
    }

    // Inspired by this posts and rewriten in rust by clanker
    // https://howardhinnant.github.io/date_algorithms.html
    pub fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
        let z = days_since_epoch + 719_468;
        let era = z.div_euclid(146_097);
        let day_of_era = z - era * 146_097;

        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;

        let mut year = year_of_era + era * 400;

        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);

        let month_prime = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
        let month = month_prime + if month_prime < 10 { 3 } else { -9 };

        year += i64::from(month <= 2);

        (year, month as u32, day as u32)
    }

    pub fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
        let mut year = year as i64;
        let month = month as i64;
        let day = day as i64;

        year -= if month <= 2 { 1 } else { 0 };

        let era = if year >= 0 { year } else { year - 399 } / 400;
        let yoe = year - era * 400;
        let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

        era * 146_097 + doe - 719_468
    }
}

impl Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format(&DateFormat::Rfc1123))
    }
}

#[derive(Debug, Clone)]
pub enum DateFormat {
    Rfc1123,
    Iso8601,
    IsoDate,
    DateTime,
    Date,
    Time,
    Year,
    Month,
    MonthName,
    MonthShort,
    Day,
    Weekday,
    WeekdayShort,
    MonthNameYearDay,
    MonthNameShortYearDay,
}

impl DateFormat {
    pub fn parse(input: &str) -> Option<DateFormat> {
        use DateFormat::*;

        match input {
            "rfc1123" => Some(Rfc1123),

            "iso8601" => Some(Iso8601),
            "iso-date" => Some(IsoDate),

            "datetime" => Some(DateTime),
            "date" => Some(Date),
            "time" => Some(Time),

            "year" => Some(Year),

            "month" => Some(Month),
            "month-name" => Some(MonthName),
            "month-short" => Some(MonthShort),

            "day" => Some(Day),

            "weekday" => Some(Weekday),
            "weekday-short" => Some(WeekdayShort),

            "month-name-day-year" => Some(MonthNameYearDay),
            "month-name-short-day-year" => Some(MonthNameShortYearDay),

            _ => None,
        }
    }
}
