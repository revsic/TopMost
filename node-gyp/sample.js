var addon = require('bindings')('topmost')

var topper = new addon.TopMostWrapper(true);

process.stdin.setRawMode(true);
process.stdin.resume();
process.stdin.on('data', process.exit.bind(process, 0));
