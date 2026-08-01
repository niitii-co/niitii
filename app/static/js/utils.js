function displayDate(options) { return new Intl.DateTimeFormat(navigator.language, options); }

function showTime(time, options, zone) {
    let newDate;
    zone? newDate = new Date(time+ 'UTC') : newDate = new Date(time);
    return displayDate(options).format(newDate);
}
