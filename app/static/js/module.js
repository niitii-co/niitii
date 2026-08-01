function showTime(time) {
    newDate = new Date(time + 'UTC');
    timestamp = intlDate.format(newDate);
    return timestamp
}

export { showTime };
