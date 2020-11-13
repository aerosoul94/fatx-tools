""" TODO:
    (From leftmost bit to rightmost bit)
      Xbox Original Format:
        07:Year
        04:Month
        05:Day
        05:Hour
        06:Minute
        05:DoubleSeconds
      Xbox 360 Format (OLD):
        05:DoubleSeconds
        06:Minute
        05:Hour
        05:Day
        04:Month
        07:Year
      Xbox 360 Format (NEW):
        07:Year
        04:Month
        05:Day
        05:Hour
        06:Minute
        05:DoubleSeconds
"""


class FatXTimeStamp(object):
    """Representation of a FATX timestamp.

    This handles extraction of each bitfield member of the timestamp."""
    __slots__ = ('time',)

    def __init__(self, time_stamp):
        self.time = time_stamp

    def __str__(self):
        # TODO: think of a reliable way of detecting proto X360 timestamps
        # try:
        #    if self.year > date.today().year:
        #        raise Exception
        #    return str(datetime(year=self.year,
        #                        month=self.month,
        #                        day=self.day,
        #                        hour=self.hour,
        #                        minute=self.min,
        #                        second=self.sec))
        # except:
        #    return str(datetime(year=((self.time & 0xffff) & 0x7f) + 2000,
        #                        month=((self.time & 0xffff) >> 7) & 0xf,
        #                        day=((self.time & 0xffff) >> 0xb),
        #                        hour=((self.time >> 16) & 0x1f),
        #                        minute=((self.time >> 16) >> 5) & 0x3f,
        #                        second=((self.time >> 16) >> 10) & 0xfffe))

        return '{}/{}/{} {}:{:02d}:{:02d}'.format(
            self.month, self.day, self.year,
            self.hour, self.min, self.sec
        )

    @property
    def year(self):
        _year = (self.time & 0xFE000000) >> 25
        return _year

    @property
    def month(self):
        _month = (self.time & 0x1E00000) >> 21
        return _month

    @property
    def day(self):
        _day = (self.time & 0x1F0000) >> 16
        return _day

    @property
    def hour(self):
        _hour = (self.time & 0xF800) >> 11
        return _hour

    @property
    def min(self):
        _min = (self.time & 0x7E0) >> 5
        return _min

    @property
    def sec(self):
        _sec = (self.time & 0x1F) * 2
        return _sec


class X360TimeStamp(FatXTimeStamp):
    """Representation of an Xbox 360 time stamp.

    The Xbox 360 timestamps contains years offset from 1980."""

    @property
    def year(self):
        _year = (((self.time & 0xFE000000) >> 25) + 1980)
        return _year


class XTimeStamp(FatXTimeStamp):
    """Representation of an Original Xbox time stamp.

    The Original Xbox contains years offset from 2000."""

    @property
    def year(self):
        _year = (((self.time & 0xFE000000) >> 25) + 2000)
        return _year
