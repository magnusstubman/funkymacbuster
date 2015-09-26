var mac = require('mac-lookup');
var pcap = require('pcap');
var moment = require('moment');
var pcap_session = pcap.createSession('', '');

var whitelist = [
    'ff:ff:ff:ff:ff:ff'
];
var seen = [];
var seenSize = 100;

// this call updates the definition from http://standards.ieee.org/develop/regauth/oui/oui.txt
// comment this call out to run the tool totally passive
//mac.rebuild(function (err) {
    ////if (err) throw err;
    //if (err) console.log(err);
    //console.log('rebuild completed');
//});

console.log('Listening on ' + pcap_session.device_name);

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);

    try {
        var shost = macArrToStr(packet.payload.shost.addr);
        //var dhost = macArrToStr(packet.payload.dhost.addr);

        check(shost, packet);
        //check(dhost); // are you a gateway or are you mitming? uncomment this line
    }
    catch (e) {
        console.log(e);
    }
});


var check = function (addr, packet) {
    if (!hasSeen(addr) && !whitelisted(addr)) {
        var prefix = addr.substring(0,8);

        mac.lookup(prefix, function (err, name) {
            if (err) throw err;
            if (name === null) {
                report(addr, packet);
            }
        });
    }
};

var remember = function (addr) {
    if (!hasSeen(addr)) {
        seen.push(addr);
    }

    while (seen.length > seenSize) {
        seen = seen.slice(1, seen.length);
    }
};

var hasSeen = function (addr) {
    return (seen.indexOf(addr) != -1);
};

var whitelisted = function (addr) {
    var prefix = addr.substring(0,8);

    return ((whitelist.indexOf(addr) != -1) || (whitelist.indexOf(prefix) != -1));
};

var report = function (addr, packet) {
    if (!hasSeen(addr)) {
        var sip = getshostipv4(packet);

        if (sip) {
            console.log(getTimestamp() + ' ' + addr + ' is unknown! (' + sip + ')');
        } else {
            console.log(getTimestamp() + ' ' + addr + ' is unknown!');
        }

        remember(addr);
    }
};

var getTimestamp = function () {
    return moment().format();
};

var getshostipv4 = function (packet) {
    try {
        var saddr = packet.payload.payload.saddr;

        return (saddr.o1).toString(10) + '.'
            + (saddr.o2).toString(10) + '.'
            + (saddr.o3).toString(10) + '.'
            + (saddr.o4).toString(10)
    }
    catch (e) {
        // best effort
    }
};

var macArrToStr = function (arr) {
    if (arr.length != 6) {
        throw "Array not correct length: " + arr.length;
    }

    var convert = function (decimal) {
        var ret = (decimal).toString(16);

        if (ret.length == 1) {
            return '0' + ret;
        }

        return ret;
    };

    return convert(arr[0]) + ':'
        + convert(arr[1]) + ':'
        + convert(arr[2]) + ':'
        + convert(arr[3]) + ':'
        + convert(arr[4]) + ':'
        + convert(arr[5])
};
