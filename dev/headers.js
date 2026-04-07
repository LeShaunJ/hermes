function list_headers(r) {
    return JSON.stringify(r.headersIn);
}

export default { list_headers };
