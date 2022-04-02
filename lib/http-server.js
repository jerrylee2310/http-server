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
  if (options.ext) {//如果有默认文件扩展名
    this.ext = options.ext === true
      ? 'html'
      : options.ext;
  }
  this.contentType = options.contentType ||
    this.ext === 'html' ? 'text/html' : 'application/octet-stream';//baidu浏览器检测文件类型，有两种响应：第一种是MIME（多zhi功能Internet 邮件扩dao充服务，最早zhuan用于邮件系统，后shudao拓展到浏览器中）；另一种，当浏览器无法确定文件类型时，就是application/octet-stream类型。

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
    const {customFolder, rootPath, rootIndex, subApps=[], domains=[]} = global.config;
    const host = req.headers.host;
    const url = req.url;
    console.log(host,url);

    let resourceUrl = req.url;

    const matchSubApp = subApps.find(({appPath})=>url.toLowerCase().startsWith(appPath.toLowerCase()));
    if(matchSubApp && matchSubApp.appIndex && url.toLowerCase()=== matchSubApp.appPath.toLowerCase()){
      resourceUrl = path.join(resourceUrl, matchSubApp.appIndex);
    }

    if(!matchSubApp && rootPath){
      resourceUrl = path.join(rootPath,url);//资源路径
      if(url==='/' && rootIndex) resourceUrl = path.join(resourceUrl, rootIndex);
    }

    const domainOfUrl = host.split(':')[0];// domain
    const matchDomain = domains.find(({domain})=>domainOfUrl === domain);// matchDomain
    if(matchDomain){//如果当前域名（仲裁委）有定制
      // 根据租户名称确定的定制文件夹
      let pathArr = resourceUrl.split('?');
      let customPath = customFolder + '/' + matchDomain.name + pathArr[0];
      let customUrl = customFolder + "/" + matchDomain.name + resourceUrl;

      await new Promise((resolve) => { // 查找文件
          fs.access(path.join(root, customPath), fs.constants.F_OK, (err) => {
              req.url = err?resourceUrl:customUrl;
              resolve();
          });
      });
    }else{
      req.url = resourceUrl;
    }
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
