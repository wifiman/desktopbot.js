var config = require('./desktopbot.js.conf');

if (!config.autoBans)
	config.autoBans = [];
if (!config.channels) {
	config.channels = {};
	if (config.channel)
		config.channels[config.channel] = true;
}

var net = require('net');
var dns = require('dns');
var dgram = require('dgram');

var ircConn = net.connect(config.serverPort, config.server, function () {
	var output = 'NICK ' + config.nick + '\r\n'
	           + 'USER ' + config.nick + ' localhost localhost :' + config.nick + '\r\n';

	if (typeof(config.password) == 'function')
		output = config.password(output);
	else if (config.password)
		output = 'PASS ' + config.password + '\r\n' + output;

	this.write(output);
});

var readBuf = '';
var joined = false;
var authed = false;

function msg (to, message) {
	return ircConn.write('PRIVMSG ' + to + ' :' + message + '\r\n');
}

function parseQ2Addr (addr) {
	addr = addr.toLowerCase().match(/^ *(quake2:\/\/)?([^\/?# ]+)[^# ]*(#(.*))?$/);
	// 2 = server  4 = player
	if (!addr)
		return null;
	var out = addr[2].match(/^(([^\]]*?)(:([^\]:]*))?|\[?(.*)\]:?([^\]]*))$/);
	if (!out || !(out[2] || out[5]))
		return null;
	ret = {
		host: out[2] || out[5],
		port: parseInt((out[4] && out[4].match(/^\d+$/)) || (out[6] && out[6].match(/^\d+$/))) || 27910,
	}
	if (addr[4])
		ret.player = addr[4];
	return ret;
}

function formatQ2Addr (host, port) {
	var output = 'quake2://' + (host.match(/[:\]]/) ? ('[' + host + ']') : host);
	if (port != 27910)
		output += ':' + port;
	return output;
}

var statusPacket = new Buffer(10);
statusPacket.writeUInt32LE(0xFFFFFFFF, 0);
statusPacket.write('status', 4);

function statQ2Server (family, host, port, timeout, callback) {
	var sock = dgram.createSocket('udp' + family);
	sock.send(statusPacket, 0, statusPacket.length, port, host);
	var timer = setTimeout(function () {
		sock.close();
		callback('timeout');
	}, timeout);
	sock.addListener('message', function (response, rInfo) {
		if (rInfo.address != host || rInfo.port != port)
			return;
		if (response.length < 4 || response.readUInt32LE(0) != 0xFFFFFFFF)
			return;
		response = response.toString('ascii', 4).split('\n');
		if (!response[0].match(/^print/) || !response[1])
			return;

		this.close();
		clearTimeout(timer);
		var serverInfo = {};
		response[1].replace(/\\([^\\]*)\\([^\\]*)/g, function (all, name, value) {
			serverInfo[name] = value;
		});
		var players = [];
		for (var i = 2; i < response.length; ++i) {
			var player = response[i].match(/^([0-9-]+) +([0-9-]+) +"(.*)"( .*)?$/);
			if (player) {
				players.push({
					score: parseInt(player[1]) || 0,
					ping: parseInt(player[2]) || 0,
					name: player[3] || '',
				});
			}
		}

		callback(null, serverInfo, players);
	});
	sock.addListener('error', function (exception) {
		this.close();
		clearTimeout(timer);
		callback('socket error (' + err + ')');
	});
	return function () {
		sock.close();
		clearTimeout(timer);
	};
}

function formatQ2Stat (serverInfo, players) {
	var output = serverInfo.hostname ? ('\u201C' + serverInfo.hostname + '\u201D') : '?';
	output += ' ' + (serverInfo.mapname || '?') + ' ' + players.length + '/' + (parseInt(serverInfo.maxclients) || '?');
	for (var i = 0; i < players.length; ++i) {
		output += ' \u201C' + players[i].name + '\u201D:' + players[i].score.toString().replace(/^-/, '\u2212');
	}
	return output.replace(/[\x00-\x1F\x7F]/g, '\uFFFD');
}

commands = {
	q2: function (me, args, from, reply) {
		var addr = parseQ2Addr(args);
		if (!addr)
			return reply('unable to parse address');

		dns.lookup(addr.host, null, function (err, host, family) {
			if (err) {
				reply(formatQ2Addr(addr.host, addr.port) + ' : unknown host (' + err + ')');
				return;
			} else {
				statQ2Server(family, host, addr.port, 3000, function (err, serverInfo, players) {
					reply(formatQ2Addr(host, addr.port) + ' '
					    + (err ? ': ' + err : formatQ2Stat(serverInfo, players)));
				});
			}
		});
	},
}

pmCommands = {
	ban: function (me, args, from, reply) {
		if (!config.adminRegex || !from.match(config.adminRegex))
			return;

		var a = args.replace(/-([^ ]+)|[^- ]([^ ]+) +([^ ]+)/g, function (all, remove, newRegex, newOutput) {
			if (remove) {
				remove = '/' + remove + '/';
				for (i = 0; i < config.autoBans.length; ++i) {
					if (config.autoBans[i].regex.toString() == remove) {
						config.autoBans.splice(i, 1);
						return;
					}
				}
				reply('no match');
				return;
			}

			var regex;
			try {
				regex = new RegExp(newRegex);
			} catch (err) {
				reply('unable to compile (' + err + ')');
				return;
			}

			config.autoBans.push({
				regex: regex,
				output: newOutput,
			});
		});
		if (a == args) {
			for (i = 0; i < config.autoBans.length; ++i) {
				reply('\u201C' + config.autoBans[i].regex.toString().match(/^\/(.*)\/$/)[1] + '\u201D \u2192 \u201C' + config.autoBans[i].output + '\u201D');
			}
			reply('EOL');
		}
	},
	channel: function (me, args, from, reply) {
		if (!config.adminRegex || !from.match(config.adminRegex))
			return;

		args = args.match(/^ *([^ ])([^ ]*)$/);
		if (!args || !args[1]) {
			for (channel in config.channels)
				reply(channel + ' \u2192 ' + config.channels[channel]);
			reply('EOL');
			return;
		}

		var joinList, partList;
		switch (args[1]) {
			case '+':
				if (config.channels[args[2]] == undefined)
					ircConn.write('JOIN ' + args[2] + '\r\n');
				config.channels[args[2]] = true;
				break;
			case '-':
				if (args[2] && args[2] != '') {
					if (config.channels[args[2]] != undefined)
						ircConn.write('PART ' + args[2] + '\r\n');
					delete(config.channels[args[2]]);
				} else {
					var chanList;
					for (var channel in config.channels) {
						if (!chanList)
							chanList = channel;
						else
							chanList += ',' + channel;
					}
					config.channels = {};
					if (chanList)
						ircConn.write('PART ' + chanList + '\r\n');
				}
				break;
			case '=':
				if (config.channels[args[2]] == undefined)
					ircConn.write('JOIN ' + args[2] + '\r\n');
				config.channels[args[2]] = false;
				break;
		}
	},
	ping: function (me, args, from, reply) {
		reply('pong');
	},
}

ircConn.addListener('data', function (data) {
	var lines = (readBuf + data.toString()).split(/\r\n/);
	readBuf = lines.pop();

	for (var i = 0; i < lines.length; ++i) {
		lines[i] = lines[i].match(/^(:([^ ]*) )?([^ ]*)(.*)$/);
		var from = lines[i][2] || '', msgType = lines[i][3], payload = lines[i][4];
		lines[i] = null;

		switch (msgType) {
		case '001':
			if (!authed) {
				if (config.auth)
					config.auth(this);
				authed = true;
			}
			break;
		case '396':
			if (!joined) {
				var chanList;
				for (var channel in config.channels) {
					if (!chanList)
						chanList = channel;
					else
						chanList += ',' + channel;
				}
				if (chanList)
					this.write('JOIN ' + chanList + '\r\n');
				joined = true;
			}
			break;
		case 'JOIN':
			if (true) {  // restrict scope of dest
				var dest = payload.match(/^ ([^ ]*)/);
				if (dest && config.channels[dest[1]]) {
					for (var i = 0; i < config.autoBans.length; ++i) {
						var tmp = from.match(config.autoBans[i].regex);
						if (tmp) {
							var nick = from.match(/^[^!]*/)[0];
							var banMask = config.autoBans[i].output.replace(/\\(.)/g, function (escape, char) {
								if (char >= '0' && char <= '9')
									return tmp[parseInt(char)] || '';
								else if (char == '*')
									return from;
								else
									return char;
							});
							// surround with KICKs, to make it harder for the kickee to see the mask but prevent kick-ban race
							this.write('KICK ' + dest[1] + ' ' + nick + '\r\n'
							         + 'MODE ' + dest[1] + ' +b ' + banMask + '\r\n'
							         + 'KICK ' + dest[1] + ' ' + nick + '\r\n');
							break;
						}
					}
				}
			}
			break;
		case 'PING':
			this.write('PONG' + payload + '\r\n');
			break;
		case 'PRIVMSG':
			do {
				var message = payload.match(/^ ([^ ]*) :(!([0-9A-Za-z]*))?(.*)$/);
				// 1 = to  3 = command  4 = args (or entire message if no command)
				if (message) {
					var cmd = (message[3] || '').toLowerCase();
					var fromNick = from.match(/^[^!]*/)[0];
					if (message[1] == config.nick) {
						cmd = pmCommands[cmd] || pmCommands[null];
						if (cmd)
							cmd(message[3], message[4], from, function (message) {
								return msg(fromNick, message);
							});
					} else if (config.channels[message[1]] != undefined) {
						cmd = commands[cmd] || commands[null];
						var channel = message[1];
						if (cmd)
							cmd(message[3], message[4], from, function (message) {
								return msg(channel, fromNick + ': ' + message);
							});
					}
				}
			} while (0);  // restrict scope of message
			break;
		}
	}
});
