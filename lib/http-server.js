'use strict';

var fs = require('fs'),
    union = require('union'),//流中间件
    ecstatic = require('ecstatic'),//静态文件服务器中间件
    httpProxy = require('http-proxy'),//支持websockets的HTTP可编程代理库。它适合于实现反向代理和负载平衡器等组件。
    auth = require('basic-auth'),// 通用的基本授权头字段解析器
    corser = require('corser'),// CORS中间件
    path = require('path'),
    secureCompare = require('secure-compare');// 安全比较算法

// a hacky and direct workaround to fix https://github.com/http-party/http-server/issues/525
function getCaller() {
  try {
    var stack = new Error().stack;
    var stackLines = stack.split('\n');
    var callerStack = stackLines[3];
    return callerStack.match(/at (.+) \(/)[1];
  }
  catch (error) {
    return '';
  }
}

var _pathNormalize = path.normalize;//规范化给定的 path，解析 '..' 和 '.' 片段
path.normalize = function (p) {
  var caller = getCaller();
  var result = _pathNormalize(p);
  // https://github.com/jfhbrook/node-ecstatic/blob/master/lib/ecstatic.js#L20
  if (caller === 'decodePathname') {
    result = result.replace(/\\/g, '/');
  }
  return result;
};

//
// Remark: backwards compatibility for previous
// case convention of HTTP
//
exports.HttpServer = exports.HTTPServer = HttpServer;

/**
 * Returns a new instance of HttpServer with the
 * specified `options`.
 */
exports.createServer = function (options) {
  return new HttpServer(options);
};

/**
 * Constructor function for the HttpServer object
 * which is responsible for serving static files along
 * with other HTTP-related features.
 */
function HttpServer(options) {
  options = options || {};

  if (options.root) {
    this.root = options.root;
  }
  else {
    try {
      fs.lstatSync('./public');// 异步地创建目录
      this.root = './public';
    }
    catch (err) {
      this.root = './';
    }
  }

  this.headers = options.headers || {};

  this.cache = (
    options.cache === undefined ? 3600 :
    // -1 is a special case to turn off caching.
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control#Preventing_caching
    options.cache === -1 ? 'no-cache, no-store, must-revalidate' :
    options.cache // in seconds.
  );
  this.showDir = options.showDir !== 'false';
  this.autoIndex = options.autoIndex !== 'false';
  this.showDotfiles = options.showDotfiles;
  this.gzip = options.gzip === true;
  this.brotli = options.brotli === true;
  console.log(options.ext);
  if (options.ext) {//如果有默认文件扩展名
    this.ext = options.ext === true
      ? 'html'
      : options.ext;
  }
  this.contentType = options.contentType ||
    this.ext === 'html' ? 'text/html' : 'application/octet-stream';//浏览器检bai测文件类型，du有两种响应：第一种是MIME（多zhi功能Internet 邮件扩dao充服务，最早zhuan用于邮件系统，后shudao拓展到浏览器中）；另一种，当浏览器无法确定文件类型时，就是application/octet-stream类型。

  var before = options.before ? options.before.slice() : [];

  if (options.logFn) {//如果有日志输出函数
    before.push(function (req, res) {
      options.logFn(req, res);
      res.emit('next');
    });
  }

  if (options.username || options.password) {//如果有用户名和密码
    before.push(function (req, res) {
      var credentials = auth(req);
      console.log(`credentials:${credentials}`);
      // We perform these outside the if to avoid short-circuiting and giving
      // an attacker knowledge of whether the username is correct via a timing
      // attack.
      if (credentials) {
        // if credentials is defined, name and pass are guaranteed to be string
        // type
        var usernameEqual = secureCompare(options.username.toString(), credentials.name);
        var passwordEqual = secureCompare(options.password.toString(), credentials.pass);
        if (usernameEqual && passwordEqual) {
          return res.emit('next');
        }
      }

      res.statusCode = 401;
      res.setHeader('WWW-Authenticate', 'Basic realm=""');
      res.end('Access denied');
    });
  }

  if (options.cors) {//如果允许跨域
    this.headers['Access-Control-Allow-Origin'] = '*';
    this.headers['Access-Control-Allow-Headers'] = 'Origin, X-Requested-With, Content-Type, Accept, Range';
    if (options.corsHeaders) {
      options.corsHeaders.split(/\s*,\s*/)
          .forEach(function (h) { this.headers['Access-Control-Allow-Headers'] += ', ' + h; }, this);
    }
    before.push(corser.create(options.corsHeaders ? {
      requestHeaders: this.headers['Access-Control-Allow-Headers'].split(/\s*,\s*/)
    } : null));
  }

  if (options.robots) {//如果允许响应 robots.txt
    before.push(function (req, res) {
      if (req.url === '/robots.txt') {
        res.setHeader('Content-Type', 'text/plain');
        var robots = options.robots === true
          ? 'User-agent: *\nDisallow: /'
          : options.robots.replace(/\\n/, '\n');

        return res.end(robots);
      }

      res.emit('next');
    });
  }

  /**
   * 自定义中间件
   */
  const root = this.root;
  before.push(async function(req,res){ 
    const {domains=[],appName2Dir,customization={},defaultDir={}} = global.config;
    const host = req.headers.host;
    const url = req.url;
    console.log(host,url);
    const domainOfUrl = host.split(':')[0];// domain
    const matchDomain = domains.find(({domain})=>domainOfUrl === domain);// matchDomain
    const appMatch = url.match(/^\/(.*?)\//);
    let appName = '';//应用名称
    let resourceUrl = '';//资源路径
    if(appMatch && appName2Dir[appMatch[1]]!==undefined){
      appName = appName2Dir[appMatch[1]];
      resourceUrl = url.slice(url.indexOf(appMatch[1]));
    }else{
      appName = 'root';
      resourceUrl = url;
    }

    //默认路径
    let defaultPath = '';
    if(defaultDir.appdir[appName]){
      defaultPath = defaultDir.appdir[appName];
    }else{
      defaultPath = defaultDir.main + appName2Dir[appName];//如果没有设置appdir.root，那么默认设置为：<main>
    }
    defaultPath += resourceUrl;

    //tod 定制路径
    let customPath = '';

    if(!customization[matchDomain.name]){ // 如果 customization."domainName" 不存在
      customization[matchDomain.name] = {};
      // customPath = `${defaultDir.custom}/${matchDomain.name}/${appName2Dir[appName]}`;
    }
    if(!customization[matchDomain.name].dir){//如果没有设置[customization.xxx].dir，那么默认xxx的dir设置为：<defaultDir.custom>/xxx
      customization[matchDomain.name].dir = `${defaultDir.custom}/${matchDomain.name}`;
    }
    if(!customization[matchDomain.name].appdir){//如果没有设置appdir不存在
      customization[matchDomain.name].appdir = {};
    }
    if(!customization[matchDomain.name].appdir[appName]){//如果没有设置appdir.xxx，那么默认设置为：<dir>/xxx
      customization[matchDomain.name].appdir[appName] = `${customization[matchDomain.name].dir}/${appName2Dir[appName]}`;
    }
    customPath += customization[matchDomain.name].appdir[appName] + resourceUrl;

    // const defaultPath =  defaultDir.main + appFolder + req.url;// 默认路径
    if(matchDomain){//如果当前域名（仲裁委）有定制
      await new Promise((resolve) => {
          fs.access(path.join(root, customPath), fs.constants.F_OK, (err) => {
              req.url = err?defaultPath:customPath;
              resolve();
          });
      });
    }else{//否则没有定制
      req.url = defaultPath;
    }
    console.log(req.url);
    res.emit('next');
  });


  before.push(ecstatic({
    root: this.root,
    cache: this.cache,
    showDir: this.showDir,
    showDotfiles: this.showDotfiles,
    autoIndex: this.autoIndex,
    defaultExt: this.ext,
    gzip: this.gzip,
    brotli: this.brotli,
    contentType: this.contentType,
    handleError: typeof options.proxy !== 'string'
  }));

  if (typeof options.proxy === 'string') {//如果 设置了代理
    var proxy = httpProxy.createProxyServer({});
    before.push(function (req, res) {
      proxy.web(req, res, {
        target: options.proxy,
        changeOrigin: true
      }, function (err, req, res, target) {
        if (options.logFn) {
          options.logFn(req, res, {
            message: err.message,
            status: res.statusCode });
        }
        res.emit('next');
      });
    });
  }

  var serverOptions = {
    before: before,
    headers: this.headers,
    onError: function (err, req, res) {
      if (options.logFn) {
        options.logFn(req, res, err);
      }

      res.end();
    }
  };

  if (options.https) { //设置 https
    serverOptions.https = options.https;
  }

  this.server = union.createServer(serverOptions);
  if (options.timeout !== undefined) {
    this.server.setTimeout(options.timeout);
  }
}

HttpServer.prototype.listen = function () {
  this.server.listen.apply(this.server, arguments);
};

HttpServer.prototype.close = function () {
  return this.server.close();
};
