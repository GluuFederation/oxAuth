var clients = new Clients();

function Clients() {
    this.clients = [];
}

Clients.prototype.add = function (clientId) {
    if (this.clients.indexOf(clientId) != -1) {
        return true;
    }
    this.clients.push(clientId);
    return true;
}

Object.prototype.toQueryString = function (sep, eq) {
    var sep = sep || '&';
    var eq = eq || '=';
    var obj = this;

    return Object.keys(obj).map(function (k) {
        var ks = encodeURIComponent(k) + eq;
        if (Array.isArray(obj[k])) {
            return obj[k].map(function (v) {
                return ks + encodeURIComponent(v);
            }).join(sep);
        } else {
            return ks + encodeURIComponent(obj[k]);
        }
    }).join(sep);
}