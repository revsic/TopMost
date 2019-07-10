var addon = require('bindings')('topmost')

var topper = new addon.TopMostWrapper(true, 17624);

process.stdin.setRawMode(true);
process.stdin.resume();
process.stdin.on('data', process.exit.bind(process, 0));
