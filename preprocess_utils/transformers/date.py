from datetime import datetime
from re import search, sub


def str_date_to_datetime(str_date: str, str_format: str) -> datetime:
    date = str_date
    if ".%f" in str_format:
        pattern = "(\d{7,12})"
        extraData = search(pattern, str_date)
        if extraData:
            milisecondsFormat = extraData.group()[:6]
            date = sub(pattern, milisecondsFormat, str_date)
    return datetime.strptime(date, str_format)
