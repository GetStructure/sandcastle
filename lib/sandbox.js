const net = require('net');
const vm = require('vm');
const fs = require('fs');
const clone = require('clone');
const EJSON = require('mongodb-extended-json');
const MMAP = require('mmap-object');

const Sandbox = function(opts) {
  Object.assign(this, {
    socket: '/tmp/sandcastle.sock',
    memoryLimit: 55,
    mmapPath: '/tmp/sandbox-share',
    mmapObject: null,
    readOnlySharedObject: null
  }, opts);
};

Sandbox.prototype.start = function() {
  if (!this.mmapObject) {
    this.createMmap();
  }

  this.server = net.createServer((c) => {

    c.on('data', (data) => {
      data = data.toString();
      const ufid = data.substring(0, data.indexOf('-'));
      const timeStamp = data.substring(data.indexOf('-')+1);
      if (ufid === 'delete') {
        // clean up last objects from the last vm
        const vmTime = timeStamp.substring(0, timeStamp.indexOf('-'));
        const vmType = timeStamp.substring(timeStamp.indexOf('-')+1);
        delete this.mmapObject[`type${vmTime}`];
        delete this.mmapObject[vmType+vmTime];
        return;
      }
      if ( this.readOnlySharedObject ) {
        if (this.readOnlySharedObject.isClosed()) {
          this.readOnlySharedObject = new MMAP.Open(`/tmp/sandcastle-share-${ufid}`);
        }
      } else {
        this.readOnlySharedObject = new MMAP.Open(`/tmp/sandcastle-share-${ufid}`);
      }
      const type = this.readOnlySharedObject[`type${timeStamp}`];

      if (type  === 'script') {
        this.executeScript(c, this.readOnlySharedObject[`sandScript${timeStamp}`] );
      } else if (type  === 'task') {
        this.answerTask(c, this.readOnlySharedObject[`sandTask${timeStamp}`].toString() );
      }
      // you shall not close this mmap file, bad things happen in frequent reads
    });

    c.once('close', (hadError) => {
      if (hadError) { c.destroy(); }
      c.removeAllListeners();
      c._ctx = null;
      setImmediate(() => { gc(); });
    });
  });

  this.server.listen(this.socket, () => {
    console.log(`server started`); // emit data so that sandcastle knows sandbox is created
  });

  this.server.on('error', () => {
    this.server.removeAllListeners();
    this.server = null;
    setTimeout(() => { this.start(); }, 500);
  });
};

Sandbox.prototype.createMmap = function() {
  // setup with a portion of memory (we only want a ~7th of the max)
  const mmapMemory = this.memoryLimit * 150; //KB
  this.mmapObject = new MMAP.Create(this.mmapPath, mmapMemory, 5);
  process.on('SIGINT', () => {
    // delete on kill
    try{ fs.unlinkSync(this.mmapPath); } catch (e) {}
    process.exit()
  });
};

Sandbox.prototype._sendError = function(connection, e, replaceStack) {
  const pack = Buffer.from(EJSON.stringify({
    error: {
      message: e.message,
      stack: !replaceStack ? e.stack : e.stack.replace()
    }
  }));
  const timeStamp = this.nanoTime();
  this.mmapObject[`type${timeStamp}`] = 'script';
  this.mmapObject[`sandScript${timeStamp}`] = pack;
  connection.write(`${timeStamp}`);
};

Sandbox.prototype.answerTask = function(connection, data) {
  try {
    const taskData = EJSON.parse(data.toString());
    const taskName = taskData.task;
    const onAnswerName = `on${taskName.charAt(0).toUpperCase()}${taskName.slice(1)}Task`;
    if (connection._ctx.exports[onAnswerName]) {
      connection._ctx.exports[onAnswerName](taskData.data);
    } else if (connection._ctx.exports.onTask) {
      connection._ctx.exports.onTask(taskName, taskData.data);
    }
  } catch (e) {
    console.log(e);
    this._sendError(connection, e);
  }
};

Sandbox.prototype.executeScript = function(connection, data) {
  let contextObject = {
    runTask: (taskName, options) => {
      try {
        const pack = Buffer.from(EJSON.stringify({
          task: taskName,
          options: options || {}
        }));
        const vmTimeStamp = this.nanoTime();
        this.mmapObject[`type${vmTimeStamp}`] = 'task';
        this.mmapObject[`sandTask${vmTimeStamp}`] = pack;
        connection.write(`${vmTimeStamp}`);
      } catch (e) {
        this._sendError(connection, e, false);
      }
    },
    exit: (output) => {
      try {
        const pack = Buffer.from(EJSON.stringify(output));
        const vmTimeStamp = this.nanoTime();
        this.mmapObject[`type${vmTimeStamp}`] = 'script';
        this.mmapObject[`sandScript${vmTimeStamp}`] = pack;
        connection.write(`${vmTimeStamp}`);
      } catch (e) {
        this._sendError(connection, e, true);
      }
    }
  };

  try {
    const script = EJSON.parse(data);

    // The trusted global variables.
    if (script.globals) {
      const globals = EJSON.parse(script.globals);

      if (globals) {
        Object.keys(globals).forEach((key) => {
          contextObject[key] = globals[key];
        });
      }
    }

    // The trusted API.
    if (script.sourceAPI) {
      const api = eval(script.sourceAPI); // eslint-disable-line

      Object.keys(api).forEach((key) => {
        contextObject[key] = api[key];
      });
    }
    // recursively clone contextObject without prototype,
    // to prevent exploits using __defineGetter__, __defineSetter__.
    // https://github.com/bcoe/sandcastle/pull/21
    contextObject = clone(contextObject, true, Infinity, null);

    connection._ctx = vm.createContext(contextObject);
    vm.runInContext(this.wrapForExecution(script.source, script.methodName), connection._ctx);
  } catch (e) {
    this._sendError(connection, e, false);
  }

};

Sandbox.prototype.wrapForExecution = function(source, methodName) {
  return `var exports = Object.create(null);${source}\nexports.${methodName}();`;
};

Sandbox.prototype.nanoTime = function() {
  const nanoSecs = process.hrtime();
  return ((nanoSecs[0]*1e9) + nanoSecs[1]).toString(36);
}; 

exports.Sandbox = Sandbox;
