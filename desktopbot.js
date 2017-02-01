// desktopbot.js: a Node.js-based IRC bot
//
// Copyright © 2012  WiFi_Man
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.

var config = require('./desktopbot.js.conf');

if (!config.autoBans)
	config.autoBans = [];
if (!config.channels) {
	config.channels = {};
	if (config.channel)
		config.channels[config.channel] = true;
}
if (!config.joinRegex)
	config.joinRegex = /^(:[^ ]* )?396( |$)/;
if (!config.q2MaxFailures)
	config.q2MaxFailures = 2;
if (!config.q2StatInterval)
	config.q2StatInterval = 5000;

var net = require('net');
var dns = require('dns');
var dgram = require('dgram');

var ircConn = net.connect(config.serverPort, config.server, function () {
	this.setEncoding('utf8');

	this.realWrite = this.write;
	var writeBuffer = '';
	this.write = function (message) {
		var lines = (writeBuffer + message).split(/\r\n/);
		writeBuffer = lines.pop();

		if (config.log)
			for (var i = 0; i < lines.length; ++i)
				config.log(true, lines[i])

		if (lines.length > 0)
			this.realWrite(lines.join('\r\n') + '\r\n');
	}

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

function isAdmin (nick, mask) {
	return config.adminRegex && (nick + mask).match(config.adminRegex);
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
	var output = host.match(/[:\]]/) ? ('[' + host + ']') : host;
	if (port != 27910)
		output += ':' + port;
	return output;
}

var statusPacket = new Buffer(10);
statusPacket.writeUInt32LE(0xFFFFFFFF, 0);
statusPacket.write('status', 4);

function formatQ2Stat (serverInfo, players) {
	var output = serverInfo.hostname ? ('\u201C' + serverInfo.hostname + '\u201D') : '?';
	output += ' ' + (serverInfo.mapname || '?') + ' ' + players.length + '/' + (parseInt(serverInfo.maxclients) || '?');
	for (var i = 0; i < players.length; ++i) {
		output += ' \u201C' + players[i].name + '\u201D:' + players[i].score.toString().replace(/^-/, '\u2212');
	}
	return output.replace(/[\x00-\x1F\x7F]/g, '\uFFFD');
}

function samePlayerNames (playersA, playersB) {
	if (playersA.length != playersB.length)
		return false;
	for (i = 0; i < playersA.length; ++i)
		if (playersA[i].name != playersB[i].name)
			return false;
	return true;
}

function objectIsEmpty (object) {
	for (var prop in object)
		return false;
	return true;
}

var watchedServers = {};
var serverWatchers = {};

function getWatchedServer (family, host, port, onlyIfExists) {
	var addrString = formatQ2Addr(host, port);
	if (!watchedServers[addrString] && !onlyIfExists)
		watchedServers[addrString] = new WatchedServer(family, host, port, addrString);
	return watchedServers[addrString];
}

function WatchedServer (family, host, port, addrString) {
	this.addrString = addrString;
	this.failCount = 0;
	this.family = family;
	this.host = host;
	this.numTempWatchers = 0;
	this.port = port;
	this.serverInfo = {};
	this.watchers = {};
	return this;
}
WatchedServer.prototype.notifyWatchers = function (tempOnly, message) {
	message = 'quake2://' + this.addrString + ' ' + message;

	for (var channel in this.watchers) {
		var to = [];
		for (var nick in this.watchers[channel]) {
			if (tempOnly && this.watchers[channel][nick])
				continue;

			if (channel == null)
				msg(nick, message);
			else
				to.push(nick);

			// Remove temporary watchers after first notification.
			if (!this.watchers[channel][nick])
				this.removeWatcher(channel, nick);
		}
		if (to.length)
			msg(channel, to.sort().join(', ') + ': ' + message);
	}
};
WatchedServer.prototype.addWatcher = function (channel, nick, persistent) {
	if (this.players) {
		var message = 'quake2://' + this.addrString + ' ' + formatQ2Stat(this.serverInfo, this.players);
		if (channel == null)
			msg(nick, message);
		else
			msg(channel, nick + ': ' + message);
		if (!persistent)
			return;
	}

	if (!this.watchers[channel])
		this.watchers[channel] = {};
	this.watchers[channel][nick] = persistent;
	if (!persistent)
		this.numTempWatchers++;

	switch (undefined) {
	case serverWatchers[channel]:
		serverWatchers[channel] = {};
	case serverWatchers[channel][nick]:
		serverWatchers[channel][nick] = {};
	default:
		serverWatchers[channel][nick][this.addrString] = true;
	}

	if (!this.timer) {
		var me = this;  // icky
		this.timer = setInterval(function () {
			me.update();
		}, config.q2StatInterval);
		this.update();
	}
};
WatchedServer.prototype.removeWatcher = function (channel, nick) {
	if (!this.watchers[channel][nick])
		this.numTempWatchers--;
	delete(this.watchers[channel][nick]);
	if (objectIsEmpty(this.watchers[channel]))
		delete(this.watchers[channel]);

	delete(serverWatchers[channel][nick][this.addrString]);
	if (objectIsEmpty(serverWatchers[channel][nick])) {
		delete(serverWatchers[channel][nick]);
		if (objectIsEmpty(serverWatchers[channel]))
			delete(serverWatchers[channel]);
	}
};
WatchedServer.prototype.destroy = function () {
	for (var channel in this.watchers)
		for (var nick in this.watchers[channel])
			this.removeWatcher(channel, nick);

	if (this.socket)
		this.socket.close();
	clearInterval(this.timer);
	delete(watchedServers[this.addrString]);
};
WatchedServer.prototype.update = function () {
	if (objectIsEmpty(this.watchers)) {
		this.destroy();
		return;
	}

	if (this.socket) {
		if (++this.failCount == config.q2MaxFailures) {
			this.notifyWatchers(false, ': timeout');
			this.destroy();
			return;
		}
		this.socket.close();
		delete(this.socket);
	}

	var me = this;  // icky
	this.socket = dgram.createSocket('udp' + this.family);
	this.socket.addListener('message', function (response, rInfo) {
		if (rInfo.address != me.host || rInfo.port != me.port)
			return;
		if (response.length < 4 || response.readUInt32LE(0) != 0xFFFFFFFF)
			return;
		response = response.toString('ascii', 4).split('\n');
		if (!response[0].match(/^print/) || !response[1])
			return;

		this.close();
		delete(me.socket);
		me.serverInfo = {};
		response[1].replace(/\\([^\\]*)\\([^\\]*)/g, function (all, name, value) {
			me.serverInfo[name] = value;
		});
		var newPlayers = [];
		for (var i = 2; i < response.length; ++i) {
			var player = response[i].match(/^([0-9-]+) +([0-9-]+) +"(.*)"( .*)?$/);
			if (player) {
				newPlayers.push({
					score: parseInt(player[1]) || 0,
					ping: parseInt(player[2]) || 0,
					name: player[3] || '',
					index: i - 2,
				});
			}
		}

		newPlayers.sort(function (a, b) {
			switch (true) {
			case a.name  < b.name:  return -1;
			case a.name  > b.name:  return 1;
			case a.index < b.index: return -1;
			case a.index > b.index: return 1;
			default: return 0;
			}
		});

		if (!me.players || !samePlayerNames(newPlayers, me.players))
			me.notifyWatchers(false, formatQ2Stat(me.serverInfo, newPlayers));
		else if (me.numTempWatchers != 0)
			me.notifyWatchers(true, formatQ2Stat(me.serverInfo, newPlayers));

		me.players = newPlayers;
	});
	this.socket.send(statusPacket, 0, statusPacket.length, this.port, this.host);
};

function clearNickInChannelWatches (channel, nick) {
	if (!serverWatchers[channel] || !serverWatchers[channel][nick])
		return;

	for (var addr in serverWatchers[channel][nick])
		watchedServers[addr].removeWatcher(channel, nick);
}

function clearChannelWatches (channel) {
	if (!serverWatchers[channel])
		return;

	for (var nick in serverWatchers[channel])
		for (var addr in serverWatchers[channel][nick])
			watchedServers[addr].removeWatcher(channel, nick);
}

function clearNickWatches (nick) {
	for (var channel in serverWatchers)
		clearNickInChannelWatches(channel, nick);
}

function renameWatcher (oldNick, newNick) {
	for (var channel in serverWatchers) {
		if (serverWatchers[channel][oldNick]) {
			for (var addr in serverWatchers[channel][oldNick]) {
				watchedServers[addr].watchers[channel][newNick] = watchedServers[addr].watchers[channel][oldNick];
				delete(watchedServers[addr].watchers[channel][oldNick]);
			}
			serverWatchers[channel][newNick] = serverWatchers[channel][oldNick];
			delete(serverWatchers[channel][oldNick]);
		}
	}
}

commands = {
	q2: function (me, args, fromNick, fromMask, inChannel, reply) {
		args = args.match(/^ *([+-])?([^ +-].*)?$/);

		if (!args || (args[1] != '-' && !args[2]))
			return reply('usage:  query: !q2 SERVER  watch: !q2 +SERVER  unwatch: !q2 -SERVER  unwatch-all: !q2 -');

		if (args[1] == '-' && !args[2])
			return clearNickInChannelWatches(inChannel, fromNick);

		var addr = parseQ2Addr(args[2]);
		if (!addr)
			return reply('unable to parse address');

		dns.lookup(addr.host, null, function (err, host, family) {
			if (err) {
				reply('quake2://' + formatQ2Addr(addr.host, addr.port) + ' : unknown host (' + err + ')');
				return;
			}
			if (args[1] == '+')
				getWatchedServer(family, host, addr.port).addWatcher(inChannel, fromNick, true);
			else if (args[1] == '-') {
				var server = getWatchedServer(family, host, addr.port, true);
				if (server)
					server.removeWatcher(inChannel, fromNick);
			} else
				getWatchedServer(family, host, addr.port).addWatcher(inChannel, fromNick, false);
		});
	},
}

pmCommands = {
	ban: function (me, args, fromNick, fromMask, inChannel, reply) {
		if (!isAdmin(fromNick, fromMask))
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
	channel: function (me, args, fromNick, fromMask, inChannel, reply) {
		if (!isAdmin(fromNick, fromMask))
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
			if (config.channels[args[2]] == undefined && joined)
				ircConn.write('JOIN ' + args[2] + '\r\n');
			config.channels[args[2]] = true;
			break;
		case '-':
			if (args[2] && args[2] != '') {
				if (config.channels[args[2]] != undefined && joined)
					ircConn.write('PART ' + args[2] + '\r\n');
				clearChannelWatches(args[2]);
				delete(config.channels[args[2]]);
			} else {
				var chanList = [];
				for (var channel in config.channels) {
					chanList.push(channel);
					clearChannelWatches(channel);
				}
				if (chanList.length && joined)
					ircConn.write('PART ' + chanList.sort().join(',') + '\r\n');
				config.channels = {};
			}
			break;
		case '=':
			if (config.channels[args[2]] == undefined && joined)
				ircConn.write('JOIN ' + args[2] + '\r\n');
			config.channels[args[2]] = false;
			break;
		}
	},
	ping: function (me, args, fromNick, fromMask, inChannel, reply) {
		reply('pong');
	},
	quit: function (me, args, fromNick, fromMask, inChannel, reply) {
		if (!isAdmin(fromNick, fromMask))
			return;

		for (var channel in config.channels)
			clearChannelWatches(channel);

		if (args)
			ircConn.end('QUIT :' + args.match(/^ ?(.*)$/)[1] + '\r\n');
		else
			ircConn.end('QUIT\r\n');
	},
}

ircConn.addListener('data', function (data) {
	var lines = (readBuf + data).split(/\r\n/);
	readBuf = lines.pop();

	for (var i = 0; i < lines.length; ++i) {
		if (config.log)
			config.log(false, lines[i]);

		if (!joined && lines[i].match(config.joinRegex)) {
			var chanList = [];
			for (var channel in config.channels)
				chanList.push(channel);
			if (chanList.length)
				this.write('JOIN ' + chanList.sort().join(',') + '\r\n');
			joined = true;
		}

		lines[i] = lines[i].match(/^(:([^ !]*)([^ ]*) )?([^ ]*)(.*)$/);
		var fromNick = lines[i][2] || '', fromMask = lines[i][3] || '', msgType = lines[i][4], payload = lines[i][5];
		lines[i] = null;

		switch (msgType) {
		case '001':
			if (!authed) {
				if (config.auth)
					config.auth(this);
				authed = true;
			}
			break;
		case 'INVITE':
			payload.replace(/^ ([^ ]*) ([^ ]*)/, function (all, nick, channel) {
				if (nick != config.nick)
					return;
				if (!isAdmin(fromNick, fromMask))
					return;
				if (channel in config.channels)
					return;

				if (joined)
					ircConn.write('JOIN ' + channel + '\r\n');
				config.channels[channel] = false;
			});
			break;
		case 'JOIN':
			payload.match(/^ ?([^ ]*)( .*)?$/)[1].replace(/[^,]+/g, function (dest) {
				if ( config.channels[dest] && (config.autoBanAdmins || !isAdmin(fromNick, fromMask)) ) {
					for (var i = 0; i < config.autoBans.length; ++i) {
						var from = fromNick + fromMask;
						var tmp = from.match(config.autoBans[i].regex);
						if (tmp) {
							var banMask = config.autoBans[i].output.replace(/\\(.)/g, function (escape, char) {
								if (char >= '0' && char <= '9')
									return tmp[parseInt(char)] || '';
								else if (char == '*')
									return from;
								else
									return char;
							});
							// surround with KICKs, to make it harder for the kickee to see the mask but prevent kick-ban race
							ircConn.write('KICK ' + dest + ' ' + fromNick + '\r\n'
							            + 'MODE ' + dest + ' +b ' + banMask + '\r\n'
							            + 'KICK ' + dest + ' ' + fromNick + '\r\n');
							break;
						}
					}
				}
			});
			break;
		case 'KICK':
			payload.replace(/^ ([^ ]*) ([^ ]*)/, function (all, channel, nick) {
				if (nick == config.nick) {
					clearChannelWatches(channel);
					delete(config.channels[channel]);
				} else
					clearNickInChannelWatches(channel, nick);
			});
		case 'NICK':
			payload.replace(/^ :([^ ]*)/, function (all, newNick) {
				renameWatcher(fromNick, newNick);
			});
			break;
		case 'PART':
			payload.match(/^ ?([^ ]*)/)[1].replace(/[^,]+/g, function (channel) {
				clearNickInChannelWatches(channel, fromNick);
			});
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
					if (message[1] == config.nick) {
						cmd = pmCommands[cmd] || pmCommands[null];
						if (cmd)
							cmd(message[3], message[4], fromNick, fromMask, null, function (message) {
								return msg(fromNick, message);
							});
					} else if (config.channels[message[1]] != undefined) {
						cmd = commands[cmd] || commands[null];
						var channel = message[1];
						if (cmd)
							cmd(message[3], message[4], fromNick, fromMask, channel, function (message) {
								return msg(channel, fromNick + ': ' + message);
							});
					}
				}
			} while (0);  // restrict scope of message
			break;
		case 'QUIT':
			clearNickWatches(fromNick);
		}
	}
});
ircConn.addListener('end', function () {
	for (var channel in config.channels)
		clearChannelWatches(channel);

	console.log('Disconnected from IRC server.');
});
ircConn.addListener('error', function (err) {
	for (var channel in config.channels)
		clearChannelWatches(channel);

	console.log('IRC socket error: ' + err);
});
