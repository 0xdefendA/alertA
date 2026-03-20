import math
from datetime import datetime, timedelta, timezone
from dateutil.parser import parse
import tzlocal
import logging

logger = logging.getLogger()

# tzlocal >= 4.0 returns a ZoneInfo object
LOCAL_TIMEZONE = tzlocal.get_localzone()


def get_date_parts():
    now = datetime.now(timezone.utc)
    last_hour_now = now - timedelta(hours=1)

    now_hour = str(now.hour).rjust(2, "0")
    now_month = str(now.month).rjust(2, "0")
    now_day = str(now.day).rjust(2, "0")
    now_year = str(now.year)
    last_hour_hour = str(last_hour_now.hour).rjust(2, "0")
    last_hour_month = str(last_hour_now.month).rjust(2, "0")
    last_hour_day = str(last_hour_now.day).rjust(2, "0")
    last_hour_year = str(last_hour_now.year)

    return (
        now_hour,
        now_month,
        now_day,
        now_year,
        last_hour_hour,
        last_hour_month,
        last_hour_day,
        last_hour_year,
    )


def toUTC(suspectedDate):
    """make a UTC date out of almost anything"""
    objDate = None
    if isinstance(suspectedDate, datetime):
        objDate = suspectedDate
    elif isinstance(suspectedDate, float):
        if suspectedDate <= 0:
            objDate = datetime(1970, 1, 1, tzinfo=timezone.utc)
        else:
            # This breaks in the year 2286
            EPOCH_MAGNITUDE = 9
            magnitude = int(math.log10(int(suspectedDate)))
            if magnitude > EPOCH_MAGNITUDE:
                suspectedDate = suspectedDate / 10 ** (magnitude - EPOCH_MAGNITUDE)
            objDate = datetime.fromtimestamp(suspectedDate, LOCAL_TIMEZONE)
    elif str(suspectedDate).isdigit():
        suspected_int = int(str(suspectedDate))
        if suspected_int <= 0:
            objDate = datetime(1970, 1, 1, tzinfo=timezone.utc)
        else:
            # epoch? but seconds/milliseconds/nanoseconds (lookin at you heka)
            epochDivisor = int(str(1) + "0" * (len(str(suspectedDate)) % 10))
            objDate = datetime.fromtimestamp(
                float(suspected_int / epochDivisor), LOCAL_TIMEZONE
            )
    elif isinstance(suspectedDate, str):
        # try to parse float or negative number from string:
        objDate = None
        try:
            suspected_float = float(suspectedDate)
            if suspected_float <= 0:
                objDate = datetime(1970, 1, 1, tzinfo=timezone.utc)
        except ValueError:
            pass
        if objDate is None:
            objDate = parse(suspectedDate, fuzzy=True)

    if objDate is None:
        raise ValueError(f"Unable to convert {suspectedDate} to a date object")

    if objDate.tzinfo is None:
        # If naive, assume it's in local timezone
        objDate = objDate.replace(tzinfo=LOCAL_TIMEZONE)

    # Convert to UTC and normalize (astimezone handles normalization for zoneinfo/pytz)
    objDate = objDate.astimezone(timezone.utc)

    return objDate


def utcnow():
    """Returns a non-naive UTC datetime"""
    return datetime.now(timezone.utc)
