/**
 * @param {NginxHTTPRequest} r
 * @returns {string}
 */
function list_headers(r) {
    var headers = {};
    for (var h in r.headersIn) {
        // Define sensitive headers to mask
        if (h.toLowerCase() === 'authorization' || h.toLowerCase() === 'cookie') {
            headers[h] = "[REDACTED]";
        } else {
            headers[h] = r.headersIn[h];
        }
    }
    return JSON.stringify(headers);
}

export default { list_headers };
