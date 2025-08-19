import B from "net";
import k from "tls";
import U from "assert";
import { r as T } from "./main-XeQ2BmOL.js";
import I from "http";
import L from "https";
import z from "url";
function F(_, P) {
  for (var d = 0; d < P.length; d++) {
    const h = P[d];
    if (typeof h != "string" && !Array.isArray(h)) {
      for (const c in h)
        if (c !== "default" && !(c in _)) {
          const g = Object.getOwnPropertyDescriptor(h, c);
          g && Object.defineProperty(_, c, g.get ? g : {
            enumerable: !0,
            get: () => h[c]
          });
        }
    }
  }
  return Object.freeze(Object.defineProperty(_, Symbol.toStringTag, { value: "Module" }));
}
var b = {}, O = {}, y = {}, D;
function J() {
  if (D) return y;
  D = 1;
  var _ = y && y.__createBinding || (Object.create ? function(n, u, r, e) {
    e === void 0 && (e = r);
    var t = Object.getOwnPropertyDescriptor(u, r);
    (!t || ("get" in t ? !u.__esModule : t.writable || t.configurable)) && (t = { enumerable: !0, get: function() {
      return u[r];
    } }), Object.defineProperty(n, e, t);
  } : function(n, u, r, e) {
    e === void 0 && (e = r), n[e] = u[r];
  }), P = y && y.__setModuleDefault || (Object.create ? function(n, u) {
    Object.defineProperty(n, "default", { enumerable: !0, value: u });
  } : function(n, u) {
    n.default = u;
  }), d = y && y.__importStar || function(n) {
    if (n && n.__esModule) return n;
    var u = {};
    if (n != null) for (var r in n) r !== "default" && Object.prototype.hasOwnProperty.call(n, r) && _(u, n, r);
    return P(u, n), u;
  };
  Object.defineProperty(y, "__esModule", { value: !0 }), y.req = y.json = y.toBuffer = void 0;
  const h = d(I), c = d(L);
  async function g(n) {
    let u = 0;
    const r = [];
    for await (const e of n)
      u += e.length, r.push(e);
    return Buffer.concat(r, u);
  }
  y.toBuffer = g;
  async function v(n) {
    const r = (await g(n)).toString("utf8");
    try {
      return JSON.parse(r);
    } catch (e) {
      const t = e;
      throw t.message += ` (input: ${r})`, t;
    }
  }
  y.json = v;
  function S(n, u = {}) {
    const e = ((typeof n == "string" ? n : n.href).startsWith("https:") ? c : h).request(n, u), t = new Promise((f, a) => {
      e.once("response", f).once("error", a).end();
    });
    return e.then = t.then.bind(t), e;
  }
  return y.req = S, y;
}
var R;
function K() {
  return R || (R = 1, function(_) {
    var P = O && O.__createBinding || (Object.create ? function(r, e, t, f) {
      f === void 0 && (f = t);
      var a = Object.getOwnPropertyDescriptor(e, t);
      (!a || ("get" in a ? !e.__esModule : a.writable || a.configurable)) && (a = { enumerable: !0, get: function() {
        return e[t];
      } }), Object.defineProperty(r, f, a);
    } : function(r, e, t, f) {
      f === void 0 && (f = t), r[f] = e[t];
    }), d = O && O.__setModuleDefault || (Object.create ? function(r, e) {
      Object.defineProperty(r, "default", { enumerable: !0, value: e });
    } : function(r, e) {
      r.default = e;
    }), h = O && O.__importStar || function(r) {
      if (r && r.__esModule) return r;
      var e = {};
      if (r != null) for (var t in r) t !== "default" && Object.prototype.hasOwnProperty.call(r, t) && P(e, r, t);
      return d(e, r), e;
    }, c = O && O.__exportStar || function(r, e) {
      for (var t in r) t !== "default" && !Object.prototype.hasOwnProperty.call(e, t) && P(e, r, t);
    };
    Object.defineProperty(_, "__esModule", { value: !0 }), _.Agent = void 0;
    const g = h(B), v = h(I), S = L;
    c(J(), _);
    const n = Symbol("AgentBaseInternalState");
    class u extends v.Agent {
      constructor(e) {
        super(e), this[n] = {};
      }
      /**
       * Determine whether this is an `http` or `https` request.
       */
      isSecureEndpoint(e) {
        if (e) {
          if (typeof e.secureEndpoint == "boolean")
            return e.secureEndpoint;
          if (typeof e.protocol == "string")
            return e.protocol === "https:";
        }
        const { stack: t } = new Error();
        return typeof t != "string" ? !1 : t.split(`
`).some((f) => f.indexOf("(https.js:") !== -1 || f.indexOf("node:https:") !== -1);
      }
      // In order to support async signatures in `connect()` and Node's native
      // connection pooling in `http.Agent`, the array of sockets for each origin
      // has to be updated synchronously. This is so the length of the array is
      // accurate when `addRequest()` is next called. We achieve this by creating a
      // fake socket and adding it to `sockets[origin]` and incrementing
      // `totalSocketCount`.
      incrementSockets(e) {
        if (this.maxSockets === 1 / 0 && this.maxTotalSockets === 1 / 0)
          return null;
        this.sockets[e] || (this.sockets[e] = []);
        const t = new g.Socket({ writable: !1 });
        return this.sockets[e].push(t), this.totalSocketCount++, t;
      }
      decrementSockets(e, t) {
        if (!this.sockets[e] || t === null)
          return;
        const f = this.sockets[e], a = f.indexOf(t);
        a !== -1 && (f.splice(a, 1), this.totalSocketCount--, f.length === 0 && delete this.sockets[e]);
      }
      // In order to properly update the socket pool, we need to call `getName()` on
      // the core `https.Agent` if it is a secureEndpoint.
      getName(e) {
        return this.isSecureEndpoint(e) ? S.Agent.prototype.getName.call(this, e) : super.getName(e);
      }
      createSocket(e, t, f) {
        const a = {
          ...t,
          secureEndpoint: this.isSecureEndpoint(t)
        }, x = this.getName(a), o = this.incrementSockets(x);
        Promise.resolve().then(() => this.connect(e, a)).then((i) => {
          if (this.decrementSockets(x, o), i instanceof v.Agent)
            try {
              return i.addRequest(e, a);
            } catch (s) {
              return f(s);
            }
          this[n].currentSocket = i, super.createSocket(e, t, f);
        }, (i) => {
          this.decrementSockets(x, o), f(i);
        });
      }
      createConnection() {
        const e = this[n].currentSocket;
        if (this[n].currentSocket = void 0, !e)
          throw new Error("No socket was returned in the `connect()` function");
        return e;
      }
      get defaultPort() {
        return this[n].defaultPort ?? (this.protocol === "https:" ? 443 : 80);
      }
      set defaultPort(e) {
        this[n] && (this[n].defaultPort = e);
      }
      get protocol() {
        return this[n].protocol ?? (this.isSecureEndpoint() ? "https:" : "http:");
      }
      set protocol(e) {
        this[n] && (this[n].protocol = e);
      }
    }
    _.Agent = u;
  }(O)), O;
}
var A = {}, q;
function W() {
  if (q) return A;
  q = 1;
  var _ = A && A.__importDefault || function(c) {
    return c && c.__esModule ? c : { default: c };
  };
  Object.defineProperty(A, "__esModule", { value: !0 }), A.parseProxyResponse = void 0;
  const d = (0, _(T()).default)("https-proxy-agent:parse-proxy-response");
  function h(c) {
    return new Promise((g, v) => {
      let S = 0;
      const n = [];
      function u() {
        const a = c.read();
        a ? f(a) : c.once("readable", u);
      }
      function r() {
        c.removeListener("end", e), c.removeListener("error", t), c.removeListener("readable", u);
      }
      function e() {
        r(), d("onend"), v(new Error("Proxy connection ended before receiving CONNECT response"));
      }
      function t(a) {
        r(), d("onerror %o", a), v(a);
      }
      function f(a) {
        n.push(a), S += a.length;
        const x = Buffer.concat(n, S), o = x.indexOf(`\r
\r
`);
        if (o === -1) {
          d("have not received end of HTTP headers yet..."), u();
          return;
        }
        const i = x.slice(0, o).toString("ascii").split(`\r
`), s = i.shift();
        if (!s)
          return c.destroy(), v(new Error("No header received from proxy CONNECT response"));
        const p = s.split(" "), l = +p[1], m = p.slice(2).join(" "), w = {};
        for (const j of i) {
          if (!j)
            continue;
          const N = j.indexOf(":");
          if (N === -1)
            return c.destroy(), v(new Error(`Invalid header from proxy CONNECT response: "${j}"`));
          const C = j.slice(0, N).toLowerCase(), M = j.slice(N + 1).trimStart(), E = w[C];
          typeof E == "string" ? w[C] = [E, M] : Array.isArray(E) ? E.push(M) : w[C] = M;
        }
        d("got proxy server response: %o %o", s, w), r(), g({
          connect: {
            statusCode: l,
            statusText: m,
            headers: w
          },
          buffered: x
        });
      }
      c.on("error", t), c.on("end", e), u();
    });
  }
  return A.parseProxyResponse = h, A;
}
var H;
function G() {
  if (H) return b;
  H = 1;
  var _ = b && b.__createBinding || (Object.create ? function(o, i, s, p) {
    p === void 0 && (p = s);
    var l = Object.getOwnPropertyDescriptor(i, s);
    (!l || ("get" in l ? !i.__esModule : l.writable || l.configurable)) && (l = { enumerable: !0, get: function() {
      return i[s];
    } }), Object.defineProperty(o, p, l);
  } : function(o, i, s, p) {
    p === void 0 && (p = s), o[p] = i[s];
  }), P = b && b.__setModuleDefault || (Object.create ? function(o, i) {
    Object.defineProperty(o, "default", { enumerable: !0, value: i });
  } : function(o, i) {
    o.default = i;
  }), d = b && b.__importStar || function(o) {
    if (o && o.__esModule) return o;
    var i = {};
    if (o != null) for (var s in o) s !== "default" && Object.prototype.hasOwnProperty.call(o, s) && _(i, o, s);
    return P(i, o), i;
  }, h = b && b.__importDefault || function(o) {
    return o && o.__esModule ? o : { default: o };
  };
  Object.defineProperty(b, "__esModule", { value: !0 }), b.HttpsProxyAgent = void 0;
  const c = d(B), g = d(k), v = h(U), S = h(T()), n = K(), u = z, r = W(), e = (0, S.default)("https-proxy-agent"), t = (o) => o.servername === void 0 && o.host && !c.isIP(o.host) ? {
    ...o,
    servername: o.host
  } : o;
  class f extends n.Agent {
    constructor(i, s) {
      super(s), this.options = { path: void 0 }, this.proxy = typeof i == "string" ? new u.URL(i) : i, this.proxyHeaders = (s == null ? void 0 : s.headers) ?? {}, e("Creating new HttpsProxyAgent instance: %o", this.proxy.href);
      const p = (this.proxy.hostname || this.proxy.host).replace(/^\[|\]$/g, ""), l = this.proxy.port ? parseInt(this.proxy.port, 10) : this.proxy.protocol === "https:" ? 443 : 80;
      this.connectOpts = {
        // Attempt to negotiate http/1.1 for proxy servers that support http/2
        ALPNProtocols: ["http/1.1"],
        ...s ? x(s, "headers") : null,
        host: p,
        port: l
      };
    }
    /**
     * Called when the node-core HTTP client library is creating a
     * new HTTP request.
     */
    async connect(i, s) {
      const { proxy: p } = this;
      if (!s.host)
        throw new TypeError('No "host" provided');
      let l;
      p.protocol === "https:" ? (e("Creating `tls.Socket`: %o", this.connectOpts), l = g.connect(t(this.connectOpts))) : (e("Creating `net.Socket`: %o", this.connectOpts), l = c.connect(this.connectOpts));
      const m = typeof this.proxyHeaders == "function" ? this.proxyHeaders() : { ...this.proxyHeaders }, w = c.isIPv6(s.host) ? `[${s.host}]` : s.host;
      let j = `CONNECT ${w}:${s.port} HTTP/1.1\r
`;
      if (p.username || p.password) {
        const $ = `${decodeURIComponent(p.username)}:${decodeURIComponent(p.password)}`;
        m["Proxy-Authorization"] = `Basic ${Buffer.from($).toString("base64")}`;
      }
      m.Host = `${w}:${s.port}`, m["Proxy-Connection"] || (m["Proxy-Connection"] = this.keepAlive ? "Keep-Alive" : "close");
      for (const $ of Object.keys(m))
        j += `${$}: ${m[$]}\r
`;
      const N = (0, r.parseProxyResponse)(l);
      l.write(`${j}\r
`);
      const { connect: C, buffered: M } = await N;
      if (i.emit("proxyConnect", C), this.emit("proxyConnect", C, i), C.statusCode === 200)
        return i.once("socket", a), s.secureEndpoint ? (e("Upgrading socket connection to TLS"), g.connect({
          ...x(t(s), "host", "path", "port"),
          socket: l
        })) : l;
      l.destroy();
      const E = new c.Socket({ writable: !1 });
      return E.readable = !0, i.once("socket", ($) => {
        e("Replaying proxy buffer for failed request"), (0, v.default)($.listenerCount("data") > 0), $.push(M), $.push(null);
      }), E;
    }
  }
  f.protocols = ["http", "https"], b.HttpsProxyAgent = f;
  function a(o) {
    o.resume();
  }
  function x(o, ...i) {
    const s = {};
    let p;
    for (p in o)
      i.includes(p) || (s[p] = o[p]);
    return s;
  }
  return b;
}
var Q = G();
const ne = /* @__PURE__ */ F({
  __proto__: null
}, [Q]);
export {
  ne as i
};
