# TopMost

Single header topmost library, make window always topmost.

- Copyright (C) 2019 Youngjoong Kim (revsic)

# Usage

- [Sample: winapp](#sample-winapp)
- [Sample: node-gyp](#sample-node-gyp)
Include library.
```cpp
#include "TopMost.hpp"
```

For making current process as topmost.
```cpp
auto topper = TopMost::MakeTop::CurrentProc(true, false, true);
```
Find process with window title and make topmost.
```cpp
auto topper = TopMost::MakeTop::ByName(name, true, false, true);
```
Make topmost with process id.
```cpp
auto topper = std::make_unique<TopMost::MakeTop>(dwPid, true, false, true);
```
Last three parameters are same in all constructor methods.
```cpp
MakeTop(DWORD pid, bool runThread = true, bool hook = false, bool log = false)
```

## Sample: winapp

Compile winapp.
```
cl winapp.cpp User32.lib /EHsc /std:c++17
```
Run ! It will be stopped when you press any key.

For topmost current window.
```
input format
topmost current app : "current"
pid base topmost : "pid 1223"
window title base : "title ConsoleApplication1 - Microsoft Visual Studio"
input: current
[*] TopMost : Start thread
[*] TopMost : Start Loop
Press any key to continue . . .
[*] TopMost : other topmost app found (name: 배터리 수준)
```
For process id.
```
input format
topmost current app : "current"
pid base topmost : "pid 1223"
window title base : "title ConsoleApplication1 - Microsoft Visual Studio"
input: pid 1600
[*] TopMost : Start thread
[*] TopMost : Start Loop
Press any key to continue . . .
```

## Sample: Node-gyp

Precompiled binary can be donwloaded in [release](https://github.com/revsic/TopMost/releases).

Move files to node-gyp directory.
```
move .\path\to\topmost-x64-Release.node .\node-gyp\build\topmost.node
```
Run sample.js
```
node node-gyp/sample.js
```
Or without precompiled biinary, go to directory and install topmost manually.
```
cd node-gyp; npm install; node sample.js
```

### Node-gyp API
Import module.
```js
var addon = require('bindings')('topmost')
// var addon = require('./build/topmost')
```
Make current app topmost without logging.
```js
var topper = new addon.TopMostWrapper();
// var topper = new addon.TopMostWrapper(false);
```
Make current app topmost with logging.
```js
var topper = new addon.TopMostWrapper(true);
```
Make process topmost with process id.
```js
var log = true; // or false
var pid = 8252;
var topper = new addon.TopMostWrapper(log, pid);
```
