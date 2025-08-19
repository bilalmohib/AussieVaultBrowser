var go = (i) => {
  throw TypeError(i);
};
var So = (i, n, a) => n.has(i) || go("Cannot " + a);
var z = (i, n, a) => (So(i, n, "read from private field"), a ? a.call(i) : n.get(i)), Ae = (i, n, a) => n.has(i) ? go("Cannot add the same private member more than once") : n instanceof WeakSet ? n.add(i) : n.set(i, a), oe = (i, n, a, u) => (So(i, n, "write to private field"), u ? u.call(i, a) : n.set(i, a), a);
import mt from "node:http";
import vi from "node:https";
import Ke from "node:zlib";
import ie, { PassThrough as Jt, pipeline as Je } from "node:stream";
import { Buffer as D } from "node:buffer";
import { types as Xt, deprecate as or, promisify as Ai } from "node:util";
import { c as wo } from "./main-DAuCMoQr.js";
import { format as Bi } from "node:url";
import { isIP as Wi } from "node:net";
import { promises as qi } from "node:fs";
import "node:path";
function ki(i) {
  if (!/^data:/i.test(i))
    throw new TypeError('`uri` does not appear to be a Data URI (must begin with "data:")');
  i = i.replace(/\r?\n/g, "");
  const n = i.indexOf(",");
  if (n === -1 || n <= 4)
    throw new TypeError("malformed data: URI");
  const a = i.substring(5, n).split(";");
  let u = "", l = !1;
  const h = a[0] || "text/plain";
  let c = h;
  for (let E = 1; E < a.length; E++)
    a[E] === "base64" ? l = !0 : a[E] && (c += `;${a[E]}`, a[E].indexOf("charset=") === 0 && (u = a[E].substring(8)));
  !a[0] && !u.length && (c += ";charset=US-ASCII", u = "US-ASCII");
  const P = l ? "base64" : "ascii", v = unescape(i.substring(n + 1)), S = Buffer.from(v, P);
  return S.type = h, S.typeFull = c, S.charset = u, S;
}
var Ro = {}, ct = { exports: {} };
/**
 * @license
 * web-streams-polyfill v3.3.3
 * Copyright 2024 Mattias Buelens, Diwank Singh Tomer and other contributors.
 * This code is released under the MIT license.
 * SPDX-License-Identifier: MIT
 */
var Oi = ct.exports, Co;
function Ii() {
  return Co || (Co = 1, function(i, n) {
    (function(a, u) {
      u(n);
    })(Oi, function(a) {
      function u() {
      }
      function l(e) {
        return typeof e == "object" && e !== null || typeof e == "function";
      }
      const h = u;
      function c(e, t) {
        try {
          Object.defineProperty(e, "name", {
            value: t,
            configurable: !0
          });
        } catch {
        }
      }
      const P = Promise, v = Promise.prototype.then, S = Promise.reject.bind(P);
      function E(e) {
        return new P(e);
      }
      function w(e) {
        return E((t) => t(e));
      }
      function m(e) {
        return S(e);
      }
      function W(e, t, r) {
        return v.call(e, t, r);
      }
      function y(e, t, r) {
        W(W(e, t, r), void 0, h);
      }
      function x(e, t) {
        y(e, t);
      }
      function k(e, t) {
        y(e, void 0, t);
      }
      function O(e, t, r) {
        return W(e, t, r);
      }
      function H(e) {
        W(e, void 0, h);
      }
      let se = (e) => {
        if (typeof queueMicrotask == "function")
          se = queueMicrotask;
        else {
          const t = w(void 0);
          se = (r) => W(t, r);
        }
        return se(e);
      };
      function q(e, t, r) {
        if (typeof e != "function")
          throw new TypeError("Argument is not a function");
        return Function.prototype.apply.call(e, t, r);
      }
      function I(e, t, r) {
        try {
          return w(q(e, t, r));
        } catch (o) {
          return m(o);
        }
      }
      const j = 16384;
      class $ {
        constructor() {
          this._cursor = 0, this._size = 0, this._front = {
            _elements: [],
            _next: void 0
          }, this._back = this._front, this._cursor = 0, this._size = 0;
        }
        get length() {
          return this._size;
        }
        // For exception safety, this method is structured in order:
        // 1. Read state
        // 2. Calculate required state mutations
        // 3. Perform state mutations
        push(t) {
          const r = this._back;
          let o = r;
          r._elements.length === j - 1 && (o = {
            _elements: [],
            _next: void 0
          }), r._elements.push(t), o !== r && (this._back = o, r._next = o), ++this._size;
        }
        // Like push(), shift() follows the read -> calculate -> mutate pattern for
        // exception safety.
        shift() {
          const t = this._front;
          let r = t;
          const o = this._cursor;
          let s = o + 1;
          const f = t._elements, d = f[o];
          return s === j && (r = t._next, s = 0), --this._size, this._cursor = s, t !== r && (this._front = r), f[o] = void 0, d;
        }
        // The tricky thing about forEach() is that it can be called
        // re-entrantly. The queue may be mutated inside the callback. It is easy to
        // see that push() within the callback has no negative effects since the end
        // of the queue is checked for on every iteration. If shift() is called
        // repeatedly within the callback then the next iteration may return an
        // element that has been removed. In this case the callback will be called
        // with undefined values until we either "catch up" with elements that still
        // exist or reach the back of the queue.
        forEach(t) {
          let r = this._cursor, o = this._front, s = o._elements;
          for (; (r !== s.length || o._next !== void 0) && !(r === s.length && (o = o._next, s = o._elements, r = 0, s.length === 0)); )
            t(s[r]), ++r;
        }
        // Return the element that would be returned if shift() was called now,
        // without modifying the queue.
        peek() {
          const t = this._front, r = this._cursor;
          return t._elements[r];
        }
      }
      const St = Symbol("[[AbortSteps]]"), en = Symbol("[[ErrorSteps]]"), ir = Symbol("[[CancelSteps]]"), sr = Symbol("[[PullSteps]]"), lr = Symbol("[[ReleaseSteps]]");
      function tn(e, t) {
        e._ownerReadableStream = t, t._reader = e, t._state === "readable" ? fr(e) : t._state === "closed" ? Lo(e) : rn(e, t._storedError);
      }
      function ur(e, t) {
        const r = e._ownerReadableStream;
        return X(r, t);
      }
      function le(e) {
        const t = e._ownerReadableStream;
        t._state === "readable" ? dr(e, new TypeError("Reader was released and can no longer be used to monitor the stream's closedness")) : Do(e, new TypeError("Reader was released and can no longer be used to monitor the stream's closedness")), t._readableStreamController[lr](), t._reader = void 0, e._ownerReadableStream = void 0;
      }
      function wt(e) {
        return new TypeError("Cannot " + e + " a stream using a released reader");
      }
      function fr(e) {
        e._closedPromise = E((t, r) => {
          e._closedPromise_resolve = t, e._closedPromise_reject = r;
        });
      }
      function rn(e, t) {
        fr(e), dr(e, t);
      }
      function Lo(e) {
        fr(e), nn(e);
      }
      function dr(e, t) {
        e._closedPromise_reject !== void 0 && (H(e._closedPromise), e._closedPromise_reject(t), e._closedPromise_resolve = void 0, e._closedPromise_reject = void 0);
      }
      function Do(e, t) {
        rn(e, t);
      }
      function nn(e) {
        e._closedPromise_resolve !== void 0 && (e._closedPromise_resolve(void 0), e._closedPromise_resolve = void 0, e._closedPromise_reject = void 0);
      }
      const on = Number.isFinite || function(e) {
        return typeof e == "number" && isFinite(e);
      }, jo = Math.trunc || function(e) {
        return e < 0 ? Math.ceil(e) : Math.floor(e);
      };
      function $o(e) {
        return typeof e == "object" || typeof e == "function";
      }
      function re(e, t) {
        if (e !== void 0 && !$o(e))
          throw new TypeError(`${t} is not an object.`);
      }
      function Y(e, t) {
        if (typeof e != "function")
          throw new TypeError(`${t} is not a function.`);
      }
      function Mo(e) {
        return typeof e == "object" && e !== null || typeof e == "function";
      }
      function an(e, t) {
        if (!Mo(e))
          throw new TypeError(`${t} is not an object.`);
      }
      function ue(e, t, r) {
        if (e === void 0)
          throw new TypeError(`Parameter ${t} is required in '${r}'.`);
      }
      function cr(e, t, r) {
        if (e === void 0)
          throw new TypeError(`${t} is required in '${r}'.`);
      }
      function hr(e) {
        return Number(e);
      }
      function sn(e) {
        return e === 0 ? 0 : e;
      }
      function Uo(e) {
        return sn(jo(e));
      }
      function mr(e, t) {
        const o = Number.MAX_SAFE_INTEGER;
        let s = Number(e);
        if (s = sn(s), !on(s))
          throw new TypeError(`${t} is not a finite number`);
        if (s = Uo(s), s < 0 || s > o)
          throw new TypeError(`${t} is outside the accepted range of 0 to ${o}, inclusive`);
        return !on(s) || s === 0 ? 0 : s;
      }
      function br(e, t) {
        if (!Te(e))
          throw new TypeError(`${t} is not a ReadableStream.`);
      }
      function je(e) {
        return new _e(e);
      }
      function ln(e, t) {
        e._reader._readRequests.push(t);
      }
      function pr(e, t, r) {
        const s = e._reader._readRequests.shift();
        r ? s._closeSteps() : s._chunkSteps(t);
      }
      function Rt(e) {
        return e._reader._readRequests.length;
      }
      function un(e) {
        const t = e._reader;
        return !(t === void 0 || !ge(t));
      }
      class _e {
        constructor(t) {
          if (ue(t, 1, "ReadableStreamDefaultReader"), br(t, "First parameter"), Pe(t))
            throw new TypeError("This stream has already been locked for exclusive reading by another reader");
          tn(this, t), this._readRequests = new $();
        }
        /**
         * Returns a promise that will be fulfilled when the stream becomes closed,
         * or rejected if the stream ever errors or the reader's lock is released before the stream finishes closing.
         */
        get closed() {
          return ge(this) ? this._closedPromise : m(Ct("closed"));
        }
        /**
         * If the reader is active, behaves the same as {@link ReadableStream.cancel | stream.cancel(reason)}.
         */
        cancel(t = void 0) {
          return ge(this) ? this._ownerReadableStream === void 0 ? m(wt("cancel")) : ur(this, t) : m(Ct("cancel"));
        }
        /**
         * Returns a promise that allows access to the next chunk from the stream's internal queue, if available.
         *
         * If reading a chunk causes the queue to become empty, more data will be pulled from the underlying source.
         */
        read() {
          if (!ge(this))
            return m(Ct("read"));
          if (this._ownerReadableStream === void 0)
            return m(wt("read from"));
          let t, r;
          const o = E((f, d) => {
            t = f, r = d;
          });
          return tt(this, {
            _chunkSteps: (f) => t({ value: f, done: !1 }),
            _closeSteps: () => t({ value: void 0, done: !0 }),
            _errorSteps: (f) => r(f)
          }), o;
        }
        /**
         * Releases the reader's lock on the corresponding stream. After the lock is released, the reader is no longer active.
         * If the associated stream is errored when the lock is released, the reader will appear errored in the same way
         * from now on; otherwise, the reader will appear closed.
         *
         * A reader's lock cannot be released while it still has a pending read request, i.e., if a promise returned by
         * the reader's {@link ReadableStreamDefaultReader.read | read()} method has not yet been settled. Attempting to
         * do so will throw a `TypeError` and leave the reader locked to the stream.
         */
        releaseLock() {
          if (!ge(this))
            throw Ct("releaseLock");
          this._ownerReadableStream !== void 0 && No(this);
        }
      }
      Object.defineProperties(_e.prototype, {
        cancel: { enumerable: !0 },
        read: { enumerable: !0 },
        releaseLock: { enumerable: !0 },
        closed: { enumerable: !0 }
      }), c(_e.prototype.cancel, "cancel"), c(_e.prototype.read, "read"), c(_e.prototype.releaseLock, "releaseLock"), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(_e.prototype, Symbol.toStringTag, {
        value: "ReadableStreamDefaultReader",
        configurable: !0
      });
      function ge(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_readRequests") ? !1 : e instanceof _e;
      }
      function tt(e, t) {
        const r = e._ownerReadableStream;
        r._disturbed = !0, r._state === "closed" ? t._closeSteps() : r._state === "errored" ? t._errorSteps(r._storedError) : r._readableStreamController[sr](t);
      }
      function No(e) {
        le(e);
        const t = new TypeError("Reader was released");
        fn(e, t);
      }
      function fn(e, t) {
        const r = e._readRequests;
        e._readRequests = new $(), r.forEach((o) => {
          o._errorSteps(t);
        });
      }
      function Ct(e) {
        return new TypeError(`ReadableStreamDefaultReader.prototype.${e} can only be used on a ReadableStreamDefaultReader`);
      }
      const xo = Object.getPrototypeOf(Object.getPrototypeOf(async function* () {
      }).prototype);
      class dn {
        constructor(t, r) {
          this._ongoingPromise = void 0, this._isFinished = !1, this._reader = t, this._preventCancel = r;
        }
        next() {
          const t = () => this._nextSteps();
          return this._ongoingPromise = this._ongoingPromise ? O(this._ongoingPromise, t, t) : t(), this._ongoingPromise;
        }
        return(t) {
          const r = () => this._returnSteps(t);
          return this._ongoingPromise ? O(this._ongoingPromise, r, r) : r();
        }
        _nextSteps() {
          if (this._isFinished)
            return Promise.resolve({ value: void 0, done: !0 });
          const t = this._reader;
          let r, o;
          const s = E((d, b) => {
            r = d, o = b;
          });
          return tt(t, {
            _chunkSteps: (d) => {
              this._ongoingPromise = void 0, se(() => r({ value: d, done: !1 }));
            },
            _closeSteps: () => {
              this._ongoingPromise = void 0, this._isFinished = !0, le(t), r({ value: void 0, done: !0 });
            },
            _errorSteps: (d) => {
              this._ongoingPromise = void 0, this._isFinished = !0, le(t), o(d);
            }
          }), s;
        }
        _returnSteps(t) {
          if (this._isFinished)
            return Promise.resolve({ value: t, done: !0 });
          this._isFinished = !0;
          const r = this._reader;
          if (!this._preventCancel) {
            const o = ur(r, t);
            return le(r), O(o, () => ({ value: t, done: !0 }));
          }
          return le(r), w({ value: t, done: !0 });
        }
      }
      const cn = {
        next() {
          return hn(this) ? this._asyncIteratorImpl.next() : m(mn("next"));
        },
        return(e) {
          return hn(this) ? this._asyncIteratorImpl.return(e) : m(mn("return"));
        }
      };
      Object.setPrototypeOf(cn, xo);
      function Ho(e, t) {
        const r = je(e), o = new dn(r, t), s = Object.create(cn);
        return s._asyncIteratorImpl = o, s;
      }
      function hn(e) {
        if (!l(e) || !Object.prototype.hasOwnProperty.call(e, "_asyncIteratorImpl"))
          return !1;
        try {
          return e._asyncIteratorImpl instanceof dn;
        } catch {
          return !1;
        }
      }
      function mn(e) {
        return new TypeError(`ReadableStreamAsyncIterator.${e} can only be used on a ReadableSteamAsyncIterator`);
      }
      const bn = Number.isNaN || function(e) {
        return e !== e;
      };
      var yr, _r, gr;
      function rt(e) {
        return e.slice();
      }
      function pn(e, t, r, o, s) {
        new Uint8Array(e).set(new Uint8Array(r, o, s), t);
      }
      let fe = (e) => (typeof e.transfer == "function" ? fe = (t) => t.transfer() : typeof structuredClone == "function" ? fe = (t) => structuredClone(t, { transfer: [t] }) : fe = (t) => t, fe(e)), Se = (e) => (typeof e.detached == "boolean" ? Se = (t) => t.detached : Se = (t) => t.byteLength === 0, Se(e));
      function yn(e, t, r) {
        if (e.slice)
          return e.slice(t, r);
        const o = r - t, s = new ArrayBuffer(o);
        return pn(s, 0, e, t, o), s;
      }
      function Tt(e, t) {
        const r = e[t];
        if (r != null) {
          if (typeof r != "function")
            throw new TypeError(`${String(t)} is not a function`);
          return r;
        }
      }
      function Qo(e) {
        const t = {
          [Symbol.iterator]: () => e.iterator
        }, r = async function* () {
          return yield* t;
        }(), o = r.next;
        return { iterator: r, nextMethod: o, done: !1 };
      }
      const Sr = (gr = (yr = Symbol.asyncIterator) !== null && yr !== void 0 ? yr : (_r = Symbol.for) === null || _r === void 0 ? void 0 : _r.call(Symbol, "Symbol.asyncIterator")) !== null && gr !== void 0 ? gr : "@@asyncIterator";
      function _n(e, t = "sync", r) {
        if (r === void 0)
          if (t === "async") {
            if (r = Tt(e, Sr), r === void 0) {
              const f = Tt(e, Symbol.iterator), d = _n(e, "sync", f);
              return Qo(d);
            }
          } else
            r = Tt(e, Symbol.iterator);
        if (r === void 0)
          throw new TypeError("The object is not iterable");
        const o = q(r, e, []);
        if (!l(o))
          throw new TypeError("The iterator method must return an object");
        const s = o.next;
        return { iterator: o, nextMethod: s, done: !1 };
      }
      function Vo(e) {
        const t = q(e.nextMethod, e.iterator, []);
        if (!l(t))
          throw new TypeError("The iterator.next() method must return an object");
        return t;
      }
      function Yo(e) {
        return !!e.done;
      }
      function Go(e) {
        return e.value;
      }
      function Zo(e) {
        return !(typeof e != "number" || bn(e) || e < 0);
      }
      function gn(e) {
        const t = yn(e.buffer, e.byteOffset, e.byteOffset + e.byteLength);
        return new Uint8Array(t);
      }
      function wr(e) {
        const t = e._queue.shift();
        return e._queueTotalSize -= t.size, e._queueTotalSize < 0 && (e._queueTotalSize = 0), t.value;
      }
      function Rr(e, t, r) {
        if (!Zo(r) || r === 1 / 0)
          throw new RangeError("Size must be a finite, non-NaN, non-negative number.");
        e._queue.push({ value: t, size: r }), e._queueTotalSize += r;
      }
      function Ko(e) {
        return e._queue.peek().value;
      }
      function we(e) {
        e._queue = new $(), e._queueTotalSize = 0;
      }
      function Sn(e) {
        return e === DataView;
      }
      function Jo(e) {
        return Sn(e.constructor);
      }
      function Xo(e) {
        return Sn(e) ? 1 : e.BYTES_PER_ELEMENT;
      }
      class Be {
        constructor() {
          throw new TypeError("Illegal constructor");
        }
        /**
         * Returns the view for writing in to, or `null` if the BYOB request has already been responded to.
         */
        get view() {
          if (!Cr(this))
            throw Ar("view");
          return this._view;
        }
        respond(t) {
          if (!Cr(this))
            throw Ar("respond");
          if (ue(t, 1, "respond"), t = mr(t, "First parameter"), this._associatedReadableByteStreamController === void 0)
            throw new TypeError("This BYOB request has been invalidated");
          if (Se(this._view.buffer))
            throw new TypeError("The BYOB request's buffer has been detached and so cannot be used as a response");
          At(this._associatedReadableByteStreamController, t);
        }
        respondWithNewView(t) {
          if (!Cr(this))
            throw Ar("respondWithNewView");
          if (ue(t, 1, "respondWithNewView"), !ArrayBuffer.isView(t))
            throw new TypeError("You can only respond with array buffer views");
          if (this._associatedReadableByteStreamController === void 0)
            throw new TypeError("This BYOB request has been invalidated");
          if (Se(t.buffer))
            throw new TypeError("The given view's buffer has been detached and so cannot be used as a response");
          Bt(this._associatedReadableByteStreamController, t);
        }
      }
      Object.defineProperties(Be.prototype, {
        respond: { enumerable: !0 },
        respondWithNewView: { enumerable: !0 },
        view: { enumerable: !0 }
      }), c(Be.prototype.respond, "respond"), c(Be.prototype.respondWithNewView, "respondWithNewView"), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(Be.prototype, Symbol.toStringTag, {
        value: "ReadableStreamBYOBRequest",
        configurable: !0
      });
      class de {
        constructor() {
          throw new TypeError("Illegal constructor");
        }
        /**
         * Returns the current BYOB pull request, or `null` if there isn't one.
         */
        get byobRequest() {
          if (!We(this))
            throw ot("byobRequest");
          return vr(this);
        }
        /**
         * Returns the desired size to fill the controlled stream's internal queue. It can be negative, if the queue is
         * over-full. An underlying byte source ought to use this information to determine when and how to apply backpressure.
         */
        get desiredSize() {
          if (!We(this))
            throw ot("desiredSize");
          return Wn(this);
        }
        /**
         * Closes the controlled readable stream. Consumers will still be able to read any previously-enqueued chunks from
         * the stream, but once those are read, the stream will become closed.
         */
        close() {
          if (!We(this))
            throw ot("close");
          if (this._closeRequested)
            throw new TypeError("The stream has already been closed; do not close it again!");
          const t = this._controlledReadableByteStream._state;
          if (t !== "readable")
            throw new TypeError(`The stream (in ${t} state) is not in the readable state and cannot be closed`);
          nt(this);
        }
        enqueue(t) {
          if (!We(this))
            throw ot("enqueue");
          if (ue(t, 1, "enqueue"), !ArrayBuffer.isView(t))
            throw new TypeError("chunk must be an array buffer view");
          if (t.byteLength === 0)
            throw new TypeError("chunk must have non-zero byteLength");
          if (t.buffer.byteLength === 0)
            throw new TypeError("chunk's buffer must have non-zero byteLength");
          if (this._closeRequested)
            throw new TypeError("stream is closed or draining");
          const r = this._controlledReadableByteStream._state;
          if (r !== "readable")
            throw new TypeError(`The stream (in ${r} state) is not in the readable state and cannot be enqueued to`);
          vt(this, t);
        }
        /**
         * Errors the controlled readable stream, making all future interactions with it fail with the given error `e`.
         */
        error(t = void 0) {
          if (!We(this))
            throw ot("error");
          G(this, t);
        }
        /** @internal */
        [ir](t) {
          wn(this), we(this);
          const r = this._cancelAlgorithm(t);
          return Et(this), r;
        }
        /** @internal */
        [sr](t) {
          const r = this._controlledReadableByteStream;
          if (this._queueTotalSize > 0) {
            Bn(this, t);
            return;
          }
          const o = this._autoAllocateChunkSize;
          if (o !== void 0) {
            let s;
            try {
              s = new ArrayBuffer(o);
            } catch (d) {
              t._errorSteps(d);
              return;
            }
            const f = {
              buffer: s,
              bufferByteLength: o,
              byteOffset: 0,
              byteLength: o,
              bytesFilled: 0,
              minimumFill: 1,
              elementSize: 1,
              viewConstructor: Uint8Array,
              readerType: "default"
            };
            this._pendingPullIntos.push(f);
          }
          ln(r, t), qe(this);
        }
        /** @internal */
        [lr]() {
          if (this._pendingPullIntos.length > 0) {
            const t = this._pendingPullIntos.peek();
            t.readerType = "none", this._pendingPullIntos = new $(), this._pendingPullIntos.push(t);
          }
        }
      }
      Object.defineProperties(de.prototype, {
        close: { enumerable: !0 },
        enqueue: { enumerable: !0 },
        error: { enumerable: !0 },
        byobRequest: { enumerable: !0 },
        desiredSize: { enumerable: !0 }
      }), c(de.prototype.close, "close"), c(de.prototype.enqueue, "enqueue"), c(de.prototype.error, "error"), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(de.prototype, Symbol.toStringTag, {
        value: "ReadableByteStreamController",
        configurable: !0
      });
      function We(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_controlledReadableByteStream") ? !1 : e instanceof de;
      }
      function Cr(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_associatedReadableByteStreamController") ? !1 : e instanceof Be;
      }
      function qe(e) {
        if (!oa(e))
          return;
        if (e._pulling) {
          e._pullAgain = !0;
          return;
        }
        e._pulling = !0;
        const r = e._pullAlgorithm();
        y(r, () => (e._pulling = !1, e._pullAgain && (e._pullAgain = !1, qe(e)), null), (o) => (G(e, o), null));
      }
      function wn(e) {
        Pr(e), e._pendingPullIntos = new $();
      }
      function Tr(e, t) {
        let r = !1;
        e._state === "closed" && (r = !0);
        const o = Rn(t);
        t.readerType === "default" ? pr(e, o, r) : fa(e, o, r);
      }
      function Rn(e) {
        const t = e.bytesFilled, r = e.elementSize;
        return new e.viewConstructor(e.buffer, e.byteOffset, t / r);
      }
      function Pt(e, t, r, o) {
        e._queue.push({ buffer: t, byteOffset: r, byteLength: o }), e._queueTotalSize += o;
      }
      function Cn(e, t, r, o) {
        let s;
        try {
          s = yn(t, r, r + o);
        } catch (f) {
          throw G(e, f), f;
        }
        Pt(e, s, 0, o);
      }
      function Tn(e, t) {
        t.bytesFilled > 0 && Cn(e, t.buffer, t.byteOffset, t.bytesFilled), $e(e);
      }
      function Pn(e, t) {
        const r = Math.min(e._queueTotalSize, t.byteLength - t.bytesFilled), o = t.bytesFilled + r;
        let s = r, f = !1;
        const d = o % t.elementSize, b = o - d;
        b >= t.minimumFill && (s = b - t.bytesFilled, f = !0);
        const g = e._queue;
        for (; s > 0; ) {
          const p = g.peek(), R = Math.min(s, p.byteLength), C = t.byteOffset + t.bytesFilled;
          pn(t.buffer, C, p.buffer, p.byteOffset, R), p.byteLength === R ? g.shift() : (p.byteOffset += R, p.byteLength -= R), e._queueTotalSize -= R, En(e, R, t), s -= R;
        }
        return f;
      }
      function En(e, t, r) {
        r.bytesFilled += t;
      }
      function vn(e) {
        e._queueTotalSize === 0 && e._closeRequested ? (Et(e), ft(e._controlledReadableByteStream)) : qe(e);
      }
      function Pr(e) {
        e._byobRequest !== null && (e._byobRequest._associatedReadableByteStreamController = void 0, e._byobRequest._view = null, e._byobRequest = null);
      }
      function Er(e) {
        for (; e._pendingPullIntos.length > 0; ) {
          if (e._queueTotalSize === 0)
            return;
          const t = e._pendingPullIntos.peek();
          Pn(e, t) && ($e(e), Tr(e._controlledReadableByteStream, t));
        }
      }
      function ea(e) {
        const t = e._controlledReadableByteStream._reader;
        for (; t._readRequests.length > 0; ) {
          if (e._queueTotalSize === 0)
            return;
          const r = t._readRequests.shift();
          Bn(e, r);
        }
      }
      function ta(e, t, r, o) {
        const s = e._controlledReadableByteStream, f = t.constructor, d = Xo(f), { byteOffset: b, byteLength: g } = t, p = r * d;
        let R;
        try {
          R = fe(t.buffer);
        } catch (A) {
          o._errorSteps(A);
          return;
        }
        const C = {
          buffer: R,
          bufferByteLength: R.byteLength,
          byteOffset: b,
          byteLength: g,
          bytesFilled: 0,
          minimumFill: p,
          elementSize: d,
          viewConstructor: f,
          readerType: "byob"
        };
        if (e._pendingPullIntos.length > 0) {
          e._pendingPullIntos.push(C), On(s, o);
          return;
        }
        if (s._state === "closed") {
          const A = new f(C.buffer, C.byteOffset, 0);
          o._closeSteps(A);
          return;
        }
        if (e._queueTotalSize > 0) {
          if (Pn(e, C)) {
            const A = Rn(C);
            vn(e), o._chunkSteps(A);
            return;
          }
          if (e._closeRequested) {
            const A = new TypeError("Insufficient bytes to fill elements in the given buffer");
            G(e, A), o._errorSteps(A);
            return;
          }
        }
        e._pendingPullIntos.push(C), On(s, o), qe(e);
      }
      function ra(e, t) {
        t.readerType === "none" && $e(e);
        const r = e._controlledReadableByteStream;
        if (Br(r))
          for (; In(r) > 0; ) {
            const o = $e(e);
            Tr(r, o);
          }
      }
      function na(e, t, r) {
        if (En(e, t, r), r.readerType === "none") {
          Tn(e, r), Er(e);
          return;
        }
        if (r.bytesFilled < r.minimumFill)
          return;
        $e(e);
        const o = r.bytesFilled % r.elementSize;
        if (o > 0) {
          const s = r.byteOffset + r.bytesFilled;
          Cn(e, r.buffer, s - o, o);
        }
        r.bytesFilled -= o, Tr(e._controlledReadableByteStream, r), Er(e);
      }
      function An(e, t) {
        const r = e._pendingPullIntos.peek();
        Pr(e), e._controlledReadableByteStream._state === "closed" ? ra(e, r) : na(e, t, r), qe(e);
      }
      function $e(e) {
        return e._pendingPullIntos.shift();
      }
      function oa(e) {
        const t = e._controlledReadableByteStream;
        return t._state !== "readable" || e._closeRequested || !e._started ? !1 : !!(un(t) && Rt(t) > 0 || Br(t) && In(t) > 0 || Wn(e) > 0);
      }
      function Et(e) {
        e._pullAlgorithm = void 0, e._cancelAlgorithm = void 0;
      }
      function nt(e) {
        const t = e._controlledReadableByteStream;
        if (!(e._closeRequested || t._state !== "readable")) {
          if (e._queueTotalSize > 0) {
            e._closeRequested = !0;
            return;
          }
          if (e._pendingPullIntos.length > 0) {
            const r = e._pendingPullIntos.peek();
            if (r.bytesFilled % r.elementSize !== 0) {
              const o = new TypeError("Insufficient bytes to fill elements in the given buffer");
              throw G(e, o), o;
            }
          }
          Et(e), ft(t);
        }
      }
      function vt(e, t) {
        const r = e._controlledReadableByteStream;
        if (e._closeRequested || r._state !== "readable")
          return;
        const { buffer: o, byteOffset: s, byteLength: f } = t;
        if (Se(o))
          throw new TypeError("chunk's buffer is detached and so cannot be enqueued");
        const d = fe(o);
        if (e._pendingPullIntos.length > 0) {
          const b = e._pendingPullIntos.peek();
          if (Se(b.buffer))
            throw new TypeError("The BYOB request's buffer has been detached and so cannot be filled with an enqueued chunk");
          Pr(e), b.buffer = fe(b.buffer), b.readerType === "none" && Tn(e, b);
        }
        if (un(r))
          if (ea(e), Rt(r) === 0)
            Pt(e, d, s, f);
          else {
            e._pendingPullIntos.length > 0 && $e(e);
            const b = new Uint8Array(d, s, f);
            pr(r, b, !1);
          }
        else Br(r) ? (Pt(e, d, s, f), Er(e)) : Pt(e, d, s, f);
        qe(e);
      }
      function G(e, t) {
        const r = e._controlledReadableByteStream;
        r._state === "readable" && (wn(e), we(e), Et(e), oo(r, t));
      }
      function Bn(e, t) {
        const r = e._queue.shift();
        e._queueTotalSize -= r.byteLength, vn(e);
        const o = new Uint8Array(r.buffer, r.byteOffset, r.byteLength);
        t._chunkSteps(o);
      }
      function vr(e) {
        if (e._byobRequest === null && e._pendingPullIntos.length > 0) {
          const t = e._pendingPullIntos.peek(), r = new Uint8Array(t.buffer, t.byteOffset + t.bytesFilled, t.byteLength - t.bytesFilled), o = Object.create(Be.prototype);
          ia(o, e, r), e._byobRequest = o;
        }
        return e._byobRequest;
      }
      function Wn(e) {
        const t = e._controlledReadableByteStream._state;
        return t === "errored" ? null : t === "closed" ? 0 : e._strategyHWM - e._queueTotalSize;
      }
      function At(e, t) {
        const r = e._pendingPullIntos.peek();
        if (e._controlledReadableByteStream._state === "closed") {
          if (t !== 0)
            throw new TypeError("bytesWritten must be 0 when calling respond() on a closed stream");
        } else {
          if (t === 0)
            throw new TypeError("bytesWritten must be greater than 0 when calling respond() on a readable stream");
          if (r.bytesFilled + t > r.byteLength)
            throw new RangeError("bytesWritten out of range");
        }
        r.buffer = fe(r.buffer), An(e, t);
      }
      function Bt(e, t) {
        const r = e._pendingPullIntos.peek();
        if (e._controlledReadableByteStream._state === "closed") {
          if (t.byteLength !== 0)
            throw new TypeError("The view's length must be 0 when calling respondWithNewView() on a closed stream");
        } else if (t.byteLength === 0)
          throw new TypeError("The view's length must be greater than 0 when calling respondWithNewView() on a readable stream");
        if (r.byteOffset + r.bytesFilled !== t.byteOffset)
          throw new RangeError("The region specified by view does not match byobRequest");
        if (r.bufferByteLength !== t.buffer.byteLength)
          throw new RangeError("The buffer of view has different capacity than byobRequest");
        if (r.bytesFilled + t.byteLength > r.byteLength)
          throw new RangeError("The region specified by view is larger than byobRequest");
        const s = t.byteLength;
        r.buffer = fe(t.buffer), An(e, s);
      }
      function qn(e, t, r, o, s, f, d) {
        t._controlledReadableByteStream = e, t._pullAgain = !1, t._pulling = !1, t._byobRequest = null, t._queue = t._queueTotalSize = void 0, we(t), t._closeRequested = !1, t._started = !1, t._strategyHWM = f, t._pullAlgorithm = o, t._cancelAlgorithm = s, t._autoAllocateChunkSize = d, t._pendingPullIntos = new $(), e._readableStreamController = t;
        const b = r();
        y(w(b), () => (t._started = !0, qe(t), null), (g) => (G(t, g), null));
      }
      function aa(e, t, r) {
        const o = Object.create(de.prototype);
        let s, f, d;
        t.start !== void 0 ? s = () => t.start(o) : s = () => {
        }, t.pull !== void 0 ? f = () => t.pull(o) : f = () => w(void 0), t.cancel !== void 0 ? d = (g) => t.cancel(g) : d = () => w(void 0);
        const b = t.autoAllocateChunkSize;
        if (b === 0)
          throw new TypeError("autoAllocateChunkSize must be greater than 0");
        qn(e, o, s, f, d, r, b);
      }
      function ia(e, t, r) {
        e._associatedReadableByteStreamController = t, e._view = r;
      }
      function Ar(e) {
        return new TypeError(`ReadableStreamBYOBRequest.prototype.${e} can only be used on a ReadableStreamBYOBRequest`);
      }
      function ot(e) {
        return new TypeError(`ReadableByteStreamController.prototype.${e} can only be used on a ReadableByteStreamController`);
      }
      function sa(e, t) {
        re(e, t);
        const r = e == null ? void 0 : e.mode;
        return {
          mode: r === void 0 ? void 0 : la(r, `${t} has member 'mode' that`)
        };
      }
      function la(e, t) {
        if (e = `${e}`, e !== "byob")
          throw new TypeError(`${t} '${e}' is not a valid enumeration value for ReadableStreamReaderMode`);
        return e;
      }
      function ua(e, t) {
        var r;
        re(e, t);
        const o = (r = e == null ? void 0 : e.min) !== null && r !== void 0 ? r : 1;
        return {
          min: mr(o, `${t} has member 'min' that`)
        };
      }
      function kn(e) {
        return new Re(e);
      }
      function On(e, t) {
        e._reader._readIntoRequests.push(t);
      }
      function fa(e, t, r) {
        const s = e._reader._readIntoRequests.shift();
        r ? s._closeSteps(t) : s._chunkSteps(t);
      }
      function In(e) {
        return e._reader._readIntoRequests.length;
      }
      function Br(e) {
        const t = e._reader;
        return !(t === void 0 || !ke(t));
      }
      class Re {
        constructor(t) {
          if (ue(t, 1, "ReadableStreamBYOBReader"), br(t, "First parameter"), Pe(t))
            throw new TypeError("This stream has already been locked for exclusive reading by another reader");
          if (!We(t._readableStreamController))
            throw new TypeError("Cannot construct a ReadableStreamBYOBReader for a stream not constructed with a byte source");
          tn(this, t), this._readIntoRequests = new $();
        }
        /**
         * Returns a promise that will be fulfilled when the stream becomes closed, or rejected if the stream ever errors or
         * the reader's lock is released before the stream finishes closing.
         */
        get closed() {
          return ke(this) ? this._closedPromise : m(Wt("closed"));
        }
        /**
         * If the reader is active, behaves the same as {@link ReadableStream.cancel | stream.cancel(reason)}.
         */
        cancel(t = void 0) {
          return ke(this) ? this._ownerReadableStream === void 0 ? m(wt("cancel")) : ur(this, t) : m(Wt("cancel"));
        }
        read(t, r = {}) {
          if (!ke(this))
            return m(Wt("read"));
          if (!ArrayBuffer.isView(t))
            return m(new TypeError("view must be an array buffer view"));
          if (t.byteLength === 0)
            return m(new TypeError("view must have non-zero byteLength"));
          if (t.buffer.byteLength === 0)
            return m(new TypeError("view's buffer must have non-zero byteLength"));
          if (Se(t.buffer))
            return m(new TypeError("view's buffer has been detached"));
          let o;
          try {
            o = ua(r, "options");
          } catch (p) {
            return m(p);
          }
          const s = o.min;
          if (s === 0)
            return m(new TypeError("options.min must be greater than 0"));
          if (Jo(t)) {
            if (s > t.byteLength)
              return m(new RangeError("options.min must be less than or equal to view's byteLength"));
          } else if (s > t.length)
            return m(new RangeError("options.min must be less than or equal to view's length"));
          if (this._ownerReadableStream === void 0)
            return m(wt("read from"));
          let f, d;
          const b = E((p, R) => {
            f = p, d = R;
          });
          return zn(this, t, s, {
            _chunkSteps: (p) => f({ value: p, done: !1 }),
            _closeSteps: (p) => f({ value: p, done: !0 }),
            _errorSteps: (p) => d(p)
          }), b;
        }
        /**
         * Releases the reader's lock on the corresponding stream. After the lock is released, the reader is no longer active.
         * If the associated stream is errored when the lock is released, the reader will appear errored in the same way
         * from now on; otherwise, the reader will appear closed.
         *
         * A reader's lock cannot be released while it still has a pending read request, i.e., if a promise returned by
         * the reader's {@link ReadableStreamBYOBReader.read | read()} method has not yet been settled. Attempting to
         * do so will throw a `TypeError` and leave the reader locked to the stream.
         */
        releaseLock() {
          if (!ke(this))
            throw Wt("releaseLock");
          this._ownerReadableStream !== void 0 && da(this);
        }
      }
      Object.defineProperties(Re.prototype, {
        cancel: { enumerable: !0 },
        read: { enumerable: !0 },
        releaseLock: { enumerable: !0 },
        closed: { enumerable: !0 }
      }), c(Re.prototype.cancel, "cancel"), c(Re.prototype.read, "read"), c(Re.prototype.releaseLock, "releaseLock"), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(Re.prototype, Symbol.toStringTag, {
        value: "ReadableStreamBYOBReader",
        configurable: !0
      });
      function ke(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_readIntoRequests") ? !1 : e instanceof Re;
      }
      function zn(e, t, r, o) {
        const s = e._ownerReadableStream;
        s._disturbed = !0, s._state === "errored" ? o._errorSteps(s._storedError) : ta(s._readableStreamController, t, r, o);
      }
      function da(e) {
        le(e);
        const t = new TypeError("Reader was released");
        Fn(e, t);
      }
      function Fn(e, t) {
        const r = e._readIntoRequests;
        e._readIntoRequests = new $(), r.forEach((o) => {
          o._errorSteps(t);
        });
      }
      function Wt(e) {
        return new TypeError(`ReadableStreamBYOBReader.prototype.${e} can only be used on a ReadableStreamBYOBReader`);
      }
      function at(e, t) {
        const { highWaterMark: r } = e;
        if (r === void 0)
          return t;
        if (bn(r) || r < 0)
          throw new RangeError("Invalid highWaterMark");
        return r;
      }
      function qt(e) {
        const { size: t } = e;
        return t || (() => 1);
      }
      function kt(e, t) {
        re(e, t);
        const r = e == null ? void 0 : e.highWaterMark, o = e == null ? void 0 : e.size;
        return {
          highWaterMark: r === void 0 ? void 0 : hr(r),
          size: o === void 0 ? void 0 : ca(o, `${t} has member 'size' that`)
        };
      }
      function ca(e, t) {
        return Y(e, t), (r) => hr(e(r));
      }
      function ha(e, t) {
        re(e, t);
        const r = e == null ? void 0 : e.abort, o = e == null ? void 0 : e.close, s = e == null ? void 0 : e.start, f = e == null ? void 0 : e.type, d = e == null ? void 0 : e.write;
        return {
          abort: r === void 0 ? void 0 : ma(r, e, `${t} has member 'abort' that`),
          close: o === void 0 ? void 0 : ba(o, e, `${t} has member 'close' that`),
          start: s === void 0 ? void 0 : pa(s, e, `${t} has member 'start' that`),
          write: d === void 0 ? void 0 : ya(d, e, `${t} has member 'write' that`),
          type: f
        };
      }
      function ma(e, t, r) {
        return Y(e, r), (o) => I(e, t, [o]);
      }
      function ba(e, t, r) {
        return Y(e, r), () => I(e, t, []);
      }
      function pa(e, t, r) {
        return Y(e, r), (o) => q(e, t, [o]);
      }
      function ya(e, t, r) {
        return Y(e, r), (o, s) => I(e, t, [o, s]);
      }
      function Ln(e, t) {
        if (!Me(e))
          throw new TypeError(`${t} is not a WritableStream.`);
      }
      function _a(e) {
        if (typeof e != "object" || e === null)
          return !1;
        try {
          return typeof e.aborted == "boolean";
        } catch {
          return !1;
        }
      }
      const ga = typeof AbortController == "function";
      function Sa() {
        if (ga)
          return new AbortController();
      }
      class Ce {
        constructor(t = {}, r = {}) {
          t === void 0 ? t = null : an(t, "First parameter");
          const o = kt(r, "Second parameter"), s = ha(t, "First parameter");
          if (jn(this), s.type !== void 0)
            throw new RangeError("Invalid type is specified");
          const d = qt(o), b = at(o, 1);
          Ia(this, s, b, d);
        }
        /**
         * Returns whether or not the writable stream is locked to a writer.
         */
        get locked() {
          if (!Me(this))
            throw Lt("locked");
          return Ue(this);
        }
        /**
         * Aborts the stream, signaling that the producer can no longer successfully write to the stream and it is to be
         * immediately moved to an errored state, with any queued-up writes discarded. This will also execute any abort
         * mechanism of the underlying sink.
         *
         * The returned promise will fulfill if the stream shuts down successfully, or reject if the underlying sink signaled
         * that there was an error doing so. Additionally, it will reject with a `TypeError` (without attempting to cancel
         * the stream) if the stream is currently locked.
         */
        abort(t = void 0) {
          return Me(this) ? Ue(this) ? m(new TypeError("Cannot abort a stream that already has a writer")) : Ot(this, t) : m(Lt("abort"));
        }
        /**
         * Closes the stream. The underlying sink will finish processing any previously-written chunks, before invoking its
         * close behavior. During this time any further attempts to write will fail (without erroring the stream).
         *
         * The method returns a promise that will fulfill if all remaining chunks are successfully written and the stream
         * successfully closes, or rejects if an error is encountered during this process. Additionally, it will reject with
         * a `TypeError` (without attempting to cancel the stream) if the stream is currently locked.
         */
        close() {
          return Me(this) ? Ue(this) ? m(new TypeError("Cannot close a stream that already has a writer")) : ne(this) ? m(new TypeError("Cannot close an already-closing stream")) : $n(this) : m(Lt("close"));
        }
        /**
         * Creates a {@link WritableStreamDefaultWriter | writer} and locks the stream to the new writer. While the stream
         * is locked, no other writer can be acquired until this one is released.
         *
         * This functionality is especially useful for creating abstractions that desire the ability to write to a stream
         * without interruption or interleaving. By getting a writer for the stream, you can ensure nobody else can write at
         * the same time, which would cause the resulting written data to be unpredictable and probably useless.
         */
        getWriter() {
          if (!Me(this))
            throw Lt("getWriter");
          return Dn(this);
        }
      }
      Object.defineProperties(Ce.prototype, {
        abort: { enumerable: !0 },
        close: { enumerable: !0 },
        getWriter: { enumerable: !0 },
        locked: { enumerable: !0 }
      }), c(Ce.prototype.abort, "abort"), c(Ce.prototype.close, "close"), c(Ce.prototype.getWriter, "getWriter"), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(Ce.prototype, Symbol.toStringTag, {
        value: "WritableStream",
        configurable: !0
      });
      function Dn(e) {
        return new ce(e);
      }
      function wa(e, t, r, o, s = 1, f = () => 1) {
        const d = Object.create(Ce.prototype);
        jn(d);
        const b = Object.create(Ne.prototype);
        return Qn(d, b, e, t, r, o, s, f), d;
      }
      function jn(e) {
        e._state = "writable", e._storedError = void 0, e._writer = void 0, e._writableStreamController = void 0, e._writeRequests = new $(), e._inFlightWriteRequest = void 0, e._closeRequest = void 0, e._inFlightCloseRequest = void 0, e._pendingAbortRequest = void 0, e._backpressure = !1;
      }
      function Me(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_writableStreamController") ? !1 : e instanceof Ce;
      }
      function Ue(e) {
        return e._writer !== void 0;
      }
      function Ot(e, t) {
        var r;
        if (e._state === "closed" || e._state === "errored")
          return w(void 0);
        e._writableStreamController._abortReason = t, (r = e._writableStreamController._abortController) === null || r === void 0 || r.abort(t);
        const o = e._state;
        if (o === "closed" || o === "errored")
          return w(void 0);
        if (e._pendingAbortRequest !== void 0)
          return e._pendingAbortRequest._promise;
        let s = !1;
        o === "erroring" && (s = !0, t = void 0);
        const f = E((d, b) => {
          e._pendingAbortRequest = {
            _promise: void 0,
            _resolve: d,
            _reject: b,
            _reason: t,
            _wasAlreadyErroring: s
          };
        });
        return e._pendingAbortRequest._promise = f, s || qr(e, t), f;
      }
      function $n(e) {
        const t = e._state;
        if (t === "closed" || t === "errored")
          return m(new TypeError(`The stream (in ${t} state) is not in the writable state and cannot be closed`));
        const r = E((s, f) => {
          const d = {
            _resolve: s,
            _reject: f
          };
          e._closeRequest = d;
        }), o = e._writer;
        return o !== void 0 && e._backpressure && t === "writable" && jr(o), za(e._writableStreamController), r;
      }
      function Ra(e) {
        return E((r, o) => {
          const s = {
            _resolve: r,
            _reject: o
          };
          e._writeRequests.push(s);
        });
      }
      function Wr(e, t) {
        if (e._state === "writable") {
          qr(e, t);
          return;
        }
        kr(e);
      }
      function qr(e, t) {
        const r = e._writableStreamController;
        e._state = "erroring", e._storedError = t;
        const o = e._writer;
        o !== void 0 && Un(o, t), !va(e) && r._started && kr(e);
      }
      function kr(e) {
        e._state = "errored", e._writableStreamController[en]();
        const t = e._storedError;
        if (e._writeRequests.forEach((s) => {
          s._reject(t);
        }), e._writeRequests = new $(), e._pendingAbortRequest === void 0) {
          It(e);
          return;
        }
        const r = e._pendingAbortRequest;
        if (e._pendingAbortRequest = void 0, r._wasAlreadyErroring) {
          r._reject(t), It(e);
          return;
        }
        const o = e._writableStreamController[St](r._reason);
        y(o, () => (r._resolve(), It(e), null), (s) => (r._reject(s), It(e), null));
      }
      function Ca(e) {
        e._inFlightWriteRequest._resolve(void 0), e._inFlightWriteRequest = void 0;
      }
      function Ta(e, t) {
        e._inFlightWriteRequest._reject(t), e._inFlightWriteRequest = void 0, Wr(e, t);
      }
      function Pa(e) {
        e._inFlightCloseRequest._resolve(void 0), e._inFlightCloseRequest = void 0, e._state === "erroring" && (e._storedError = void 0, e._pendingAbortRequest !== void 0 && (e._pendingAbortRequest._resolve(), e._pendingAbortRequest = void 0)), e._state = "closed";
        const r = e._writer;
        r !== void 0 && Zn(r);
      }
      function Ea(e, t) {
        e._inFlightCloseRequest._reject(t), e._inFlightCloseRequest = void 0, e._pendingAbortRequest !== void 0 && (e._pendingAbortRequest._reject(t), e._pendingAbortRequest = void 0), Wr(e, t);
      }
      function ne(e) {
        return !(e._closeRequest === void 0 && e._inFlightCloseRequest === void 0);
      }
      function va(e) {
        return !(e._inFlightWriteRequest === void 0 && e._inFlightCloseRequest === void 0);
      }
      function Aa(e) {
        e._inFlightCloseRequest = e._closeRequest, e._closeRequest = void 0;
      }
      function Ba(e) {
        e._inFlightWriteRequest = e._writeRequests.shift();
      }
      function It(e) {
        e._closeRequest !== void 0 && (e._closeRequest._reject(e._storedError), e._closeRequest = void 0);
        const t = e._writer;
        t !== void 0 && Lr(t, e._storedError);
      }
      function Or(e, t) {
        const r = e._writer;
        r !== void 0 && t !== e._backpressure && (t ? Ua(r) : jr(r)), e._backpressure = t;
      }
      class ce {
        constructor(t) {
          if (ue(t, 1, "WritableStreamDefaultWriter"), Ln(t, "First parameter"), Ue(t))
            throw new TypeError("This stream has already been locked for exclusive writing by another writer");
          this._ownerWritableStream = t, t._writer = this;
          const r = t._state;
          if (r === "writable")
            !ne(t) && t._backpressure ? jt(this) : Kn(this), Dt(this);
          else if (r === "erroring")
            Dr(this, t._storedError), Dt(this);
          else if (r === "closed")
            Kn(this), $a(this);
          else {
            const o = t._storedError;
            Dr(this, o), Gn(this, o);
          }
        }
        /**
         * Returns a promise that will be fulfilled when the stream becomes closed, or rejected if the stream ever errors or
         * the writer’s lock is released before the stream finishes closing.
         */
        get closed() {
          return Oe(this) ? this._closedPromise : m(Ie("closed"));
        }
        /**
         * Returns the desired size to fill the stream’s internal queue. It can be negative, if the queue is over-full.
         * A producer can use this information to determine the right amount of data to write.
         *
         * It will be `null` if the stream cannot be successfully written to (due to either being errored, or having an abort
         * queued up). It will return zero if the stream is closed. And the getter will throw an exception if invoked when
         * the writer’s lock is released.
         */
        get desiredSize() {
          if (!Oe(this))
            throw Ie("desiredSize");
          if (this._ownerWritableStream === void 0)
            throw st("desiredSize");
          return Oa(this);
        }
        /**
         * Returns a promise that will be fulfilled when the desired size to fill the stream’s internal queue transitions
         * from non-positive to positive, signaling that it is no longer applying backpressure. Once the desired size dips
         * back to zero or below, the getter will return a new promise that stays pending until the next transition.
         *
         * If the stream becomes errored or aborted, or the writer’s lock is released, the returned promise will become
         * rejected.
         */
        get ready() {
          return Oe(this) ? this._readyPromise : m(Ie("ready"));
        }
        /**
         * If the reader is active, behaves the same as {@link WritableStream.abort | stream.abort(reason)}.
         */
        abort(t = void 0) {
          return Oe(this) ? this._ownerWritableStream === void 0 ? m(st("abort")) : Wa(this, t) : m(Ie("abort"));
        }
        /**
         * If the reader is active, behaves the same as {@link WritableStream.close | stream.close()}.
         */
        close() {
          if (!Oe(this))
            return m(Ie("close"));
          const t = this._ownerWritableStream;
          return t === void 0 ? m(st("close")) : ne(t) ? m(new TypeError("Cannot close an already-closing stream")) : Mn(this);
        }
        /**
         * Releases the writer’s lock on the corresponding stream. After the lock is released, the writer is no longer active.
         * If the associated stream is errored when the lock is released, the writer will appear errored in the same way from
         * now on; otherwise, the writer will appear closed.
         *
         * Note that the lock can still be released even if some ongoing writes have not yet finished (i.e. even if the
         * promises returned from previous calls to {@link WritableStreamDefaultWriter.write | write()} have not yet settled).
         * It’s not necessary to hold the lock on the writer for the duration of the write; the lock instead simply prevents
         * other producers from writing in an interleaved manner.
         */
        releaseLock() {
          if (!Oe(this))
            throw Ie("releaseLock");
          this._ownerWritableStream !== void 0 && Nn(this);
        }
        write(t = void 0) {
          return Oe(this) ? this._ownerWritableStream === void 0 ? m(st("write to")) : xn(this, t) : m(Ie("write"));
        }
      }
      Object.defineProperties(ce.prototype, {
        abort: { enumerable: !0 },
        close: { enumerable: !0 },
        releaseLock: { enumerable: !0 },
        write: { enumerable: !0 },
        closed: { enumerable: !0 },
        desiredSize: { enumerable: !0 },
        ready: { enumerable: !0 }
      }), c(ce.prototype.abort, "abort"), c(ce.prototype.close, "close"), c(ce.prototype.releaseLock, "releaseLock"), c(ce.prototype.write, "write"), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(ce.prototype, Symbol.toStringTag, {
        value: "WritableStreamDefaultWriter",
        configurable: !0
      });
      function Oe(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_ownerWritableStream") ? !1 : e instanceof ce;
      }
      function Wa(e, t) {
        const r = e._ownerWritableStream;
        return Ot(r, t);
      }
      function Mn(e) {
        const t = e._ownerWritableStream;
        return $n(t);
      }
      function qa(e) {
        const t = e._ownerWritableStream, r = t._state;
        return ne(t) || r === "closed" ? w(void 0) : r === "errored" ? m(t._storedError) : Mn(e);
      }
      function ka(e, t) {
        e._closedPromiseState === "pending" ? Lr(e, t) : Ma(e, t);
      }
      function Un(e, t) {
        e._readyPromiseState === "pending" ? Jn(e, t) : Na(e, t);
      }
      function Oa(e) {
        const t = e._ownerWritableStream, r = t._state;
        return r === "errored" || r === "erroring" ? null : r === "closed" ? 0 : Vn(t._writableStreamController);
      }
      function Nn(e) {
        const t = e._ownerWritableStream, r = new TypeError("Writer was released and can no longer be used to monitor the stream's closedness");
        Un(e, r), ka(e, r), t._writer = void 0, e._ownerWritableStream = void 0;
      }
      function xn(e, t) {
        const r = e._ownerWritableStream, o = r._writableStreamController, s = Fa(o, t);
        if (r !== e._ownerWritableStream)
          return m(st("write to"));
        const f = r._state;
        if (f === "errored")
          return m(r._storedError);
        if (ne(r) || f === "closed")
          return m(new TypeError("The stream is closing or closed and cannot be written to"));
        if (f === "erroring")
          return m(r._storedError);
        const d = Ra(r);
        return La(o, t, s), d;
      }
      const Hn = {};
      class Ne {
        constructor() {
          throw new TypeError("Illegal constructor");
        }
        /**
         * The reason which was passed to `WritableStream.abort(reason)` when the stream was aborted.
         *
         * @deprecated
         *  This property has been removed from the specification, see https://github.com/whatwg/streams/pull/1177.
         *  Use {@link WritableStreamDefaultController.signal}'s `reason` instead.
         */
        get abortReason() {
          if (!Ir(this))
            throw Fr("abortReason");
          return this._abortReason;
        }
        /**
         * An `AbortSignal` that can be used to abort the pending write or close operation when the stream is aborted.
         */
        get signal() {
          if (!Ir(this))
            throw Fr("signal");
          if (this._abortController === void 0)
            throw new TypeError("WritableStreamDefaultController.prototype.signal is not supported");
          return this._abortController.signal;
        }
        /**
         * Closes the controlled writable stream, making all future interactions with it fail with the given error `e`.
         *
         * This method is rarely used, since usually it suffices to return a rejected promise from one of the underlying
         * sink's methods. However, it can be useful for suddenly shutting down a stream in response to an event outside the
         * normal lifecycle of interactions with the underlying sink.
         */
        error(t = void 0) {
          if (!Ir(this))
            throw Fr("error");
          this._controlledWritableStream._state === "writable" && Yn(this, t);
        }
        /** @internal */
        [St](t) {
          const r = this._abortAlgorithm(t);
          return zt(this), r;
        }
        /** @internal */
        [en]() {
          we(this);
        }
      }
      Object.defineProperties(Ne.prototype, {
        abortReason: { enumerable: !0 },
        signal: { enumerable: !0 },
        error: { enumerable: !0 }
      }), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(Ne.prototype, Symbol.toStringTag, {
        value: "WritableStreamDefaultController",
        configurable: !0
      });
      function Ir(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_controlledWritableStream") ? !1 : e instanceof Ne;
      }
      function Qn(e, t, r, o, s, f, d, b) {
        t._controlledWritableStream = e, e._writableStreamController = t, t._queue = void 0, t._queueTotalSize = void 0, we(t), t._abortReason = void 0, t._abortController = Sa(), t._started = !1, t._strategySizeAlgorithm = b, t._strategyHWM = d, t._writeAlgorithm = o, t._closeAlgorithm = s, t._abortAlgorithm = f;
        const g = zr(t);
        Or(e, g);
        const p = r(), R = w(p);
        y(R, () => (t._started = !0, Ft(t), null), (C) => (t._started = !0, Wr(e, C), null));
      }
      function Ia(e, t, r, o) {
        const s = Object.create(Ne.prototype);
        let f, d, b, g;
        t.start !== void 0 ? f = () => t.start(s) : f = () => {
        }, t.write !== void 0 ? d = (p) => t.write(p, s) : d = () => w(void 0), t.close !== void 0 ? b = () => t.close() : b = () => w(void 0), t.abort !== void 0 ? g = (p) => t.abort(p) : g = () => w(void 0), Qn(e, s, f, d, b, g, r, o);
      }
      function zt(e) {
        e._writeAlgorithm = void 0, e._closeAlgorithm = void 0, e._abortAlgorithm = void 0, e._strategySizeAlgorithm = void 0;
      }
      function za(e) {
        Rr(e, Hn, 0), Ft(e);
      }
      function Fa(e, t) {
        try {
          return e._strategySizeAlgorithm(t);
        } catch (r) {
          return it(e, r), 1;
        }
      }
      function Vn(e) {
        return e._strategyHWM - e._queueTotalSize;
      }
      function La(e, t, r) {
        try {
          Rr(e, t, r);
        } catch (s) {
          it(e, s);
          return;
        }
        const o = e._controlledWritableStream;
        if (!ne(o) && o._state === "writable") {
          const s = zr(e);
          Or(o, s);
        }
        Ft(e);
      }
      function Ft(e) {
        const t = e._controlledWritableStream;
        if (!e._started || t._inFlightWriteRequest !== void 0)
          return;
        if (t._state === "erroring") {
          kr(t);
          return;
        }
        if (e._queue.length === 0)
          return;
        const o = Ko(e);
        o === Hn ? Da(e) : ja(e, o);
      }
      function it(e, t) {
        e._controlledWritableStream._state === "writable" && Yn(e, t);
      }
      function Da(e) {
        const t = e._controlledWritableStream;
        Aa(t), wr(e);
        const r = e._closeAlgorithm();
        zt(e), y(r, () => (Pa(t), null), (o) => (Ea(t, o), null));
      }
      function ja(e, t) {
        const r = e._controlledWritableStream;
        Ba(r);
        const o = e._writeAlgorithm(t);
        y(o, () => {
          Ca(r);
          const s = r._state;
          if (wr(e), !ne(r) && s === "writable") {
            const f = zr(e);
            Or(r, f);
          }
          return Ft(e), null;
        }, (s) => (r._state === "writable" && zt(e), Ta(r, s), null));
      }
      function zr(e) {
        return Vn(e) <= 0;
      }
      function Yn(e, t) {
        const r = e._controlledWritableStream;
        zt(e), qr(r, t);
      }
      function Lt(e) {
        return new TypeError(`WritableStream.prototype.${e} can only be used on a WritableStream`);
      }
      function Fr(e) {
        return new TypeError(`WritableStreamDefaultController.prototype.${e} can only be used on a WritableStreamDefaultController`);
      }
      function Ie(e) {
        return new TypeError(`WritableStreamDefaultWriter.prototype.${e} can only be used on a WritableStreamDefaultWriter`);
      }
      function st(e) {
        return new TypeError("Cannot " + e + " a stream using a released writer");
      }
      function Dt(e) {
        e._closedPromise = E((t, r) => {
          e._closedPromise_resolve = t, e._closedPromise_reject = r, e._closedPromiseState = "pending";
        });
      }
      function Gn(e, t) {
        Dt(e), Lr(e, t);
      }
      function $a(e) {
        Dt(e), Zn(e);
      }
      function Lr(e, t) {
        e._closedPromise_reject !== void 0 && (H(e._closedPromise), e._closedPromise_reject(t), e._closedPromise_resolve = void 0, e._closedPromise_reject = void 0, e._closedPromiseState = "rejected");
      }
      function Ma(e, t) {
        Gn(e, t);
      }
      function Zn(e) {
        e._closedPromise_resolve !== void 0 && (e._closedPromise_resolve(void 0), e._closedPromise_resolve = void 0, e._closedPromise_reject = void 0, e._closedPromiseState = "resolved");
      }
      function jt(e) {
        e._readyPromise = E((t, r) => {
          e._readyPromise_resolve = t, e._readyPromise_reject = r;
        }), e._readyPromiseState = "pending";
      }
      function Dr(e, t) {
        jt(e), Jn(e, t);
      }
      function Kn(e) {
        jt(e), jr(e);
      }
      function Jn(e, t) {
        e._readyPromise_reject !== void 0 && (H(e._readyPromise), e._readyPromise_reject(t), e._readyPromise_resolve = void 0, e._readyPromise_reject = void 0, e._readyPromiseState = "rejected");
      }
      function Ua(e) {
        jt(e);
      }
      function Na(e, t) {
        Dr(e, t);
      }
      function jr(e) {
        e._readyPromise_resolve !== void 0 && (e._readyPromise_resolve(void 0), e._readyPromise_resolve = void 0, e._readyPromise_reject = void 0, e._readyPromiseState = "fulfilled");
      }
      function xa() {
        if (typeof globalThis < "u")
          return globalThis;
        if (typeof self < "u")
          return self;
        if (typeof wo < "u")
          return wo;
      }
      const $r = xa();
      function Ha(e) {
        if (!(typeof e == "function" || typeof e == "object") || e.name !== "DOMException")
          return !1;
        try {
          return new e(), !0;
        } catch {
          return !1;
        }
      }
      function Qa() {
        const e = $r == null ? void 0 : $r.DOMException;
        return Ha(e) ? e : void 0;
      }
      function Va() {
        const e = function(r, o) {
          this.message = r || "", this.name = o || "Error", Error.captureStackTrace && Error.captureStackTrace(this, this.constructor);
        };
        return c(e, "DOMException"), e.prototype = Object.create(Error.prototype), Object.defineProperty(e.prototype, "constructor", { value: e, writable: !0, configurable: !0 }), e;
      }
      const Ya = Qa() || Va();
      function Xn(e, t, r, o, s, f) {
        const d = je(e), b = Dn(t);
        e._disturbed = !0;
        let g = !1, p = w(void 0);
        return E((R, C) => {
          let A;
          if (f !== void 0) {
            if (A = () => {
              const _ = f.reason !== void 0 ? f.reason : new Ya("Aborted", "AbortError"), T = [];
              o || T.push(() => t._state === "writable" ? Ot(t, _) : w(void 0)), s || T.push(() => e._state === "readable" ? X(e, _) : w(void 0)), U(() => Promise.all(T.map((B) => B())), !0, _);
            }, f.aborted) {
              A();
              return;
            }
            f.addEventListener("abort", A);
          }
          function ee() {
            return E((_, T) => {
              function B(Q) {
                Q ? _() : W(Ve(), B, T);
              }
              B(!1);
            });
          }
          function Ve() {
            return g ? w(!0) : W(b._readyPromise, () => E((_, T) => {
              tt(d, {
                _chunkSteps: (B) => {
                  p = W(xn(b, B), void 0, u), _(!1);
                },
                _closeSteps: () => _(!0),
                _errorSteps: T
              });
            }));
          }
          if (me(e, d._closedPromise, (_) => (o ? Z(!0, _) : U(() => Ot(t, _), !0, _), null)), me(t, b._closedPromise, (_) => (s ? Z(!0, _) : U(() => X(e, _), !0, _), null)), M(e, d._closedPromise, () => (r ? Z() : U(() => qa(b)), null)), ne(t) || t._state === "closed") {
            const _ = new TypeError("the destination writable stream closed before all data could be piped to it");
            s ? Z(!0, _) : U(() => X(e, _), !0, _);
          }
          H(ee());
          function ve() {
            const _ = p;
            return W(p, () => _ !== p ? ve() : void 0);
          }
          function me(_, T, B) {
            _._state === "errored" ? B(_._storedError) : k(T, B);
          }
          function M(_, T, B) {
            _._state === "closed" ? B() : x(T, B);
          }
          function U(_, T, B) {
            if (g)
              return;
            g = !0, t._state === "writable" && !ne(t) ? x(ve(), Q) : Q();
            function Q() {
              return y(_(), () => be(T, B), (Ye) => be(!0, Ye)), null;
            }
          }
          function Z(_, T) {
            g || (g = !0, t._state === "writable" && !ne(t) ? x(ve(), () => be(_, T)) : be(_, T));
          }
          function be(_, T) {
            return Nn(b), le(d), f !== void 0 && f.removeEventListener("abort", A), _ ? C(T) : R(void 0), null;
          }
        });
      }
      class he {
        constructor() {
          throw new TypeError("Illegal constructor");
        }
        /**
         * Returns the desired size to fill the controlled stream's internal queue. It can be negative, if the queue is
         * over-full. An underlying source ought to use this information to determine when and how to apply backpressure.
         */
        get desiredSize() {
          if (!$t(this))
            throw Ut("desiredSize");
          return Mr(this);
        }
        /**
         * Closes the controlled readable stream. Consumers will still be able to read any previously-enqueued chunks from
         * the stream, but once those are read, the stream will become closed.
         */
        close() {
          if (!$t(this))
            throw Ut("close");
          if (!He(this))
            throw new TypeError("The stream is not in a state that permits close");
          ze(this);
        }
        enqueue(t = void 0) {
          if (!$t(this))
            throw Ut("enqueue");
          if (!He(this))
            throw new TypeError("The stream is not in a state that permits enqueue");
          return xe(this, t);
        }
        /**
         * Errors the controlled readable stream, making all future interactions with it fail with the given error `e`.
         */
        error(t = void 0) {
          if (!$t(this))
            throw Ut("error");
          J(this, t);
        }
        /** @internal */
        [ir](t) {
          we(this);
          const r = this._cancelAlgorithm(t);
          return Mt(this), r;
        }
        /** @internal */
        [sr](t) {
          const r = this._controlledReadableStream;
          if (this._queue.length > 0) {
            const o = wr(this);
            this._closeRequested && this._queue.length === 0 ? (Mt(this), ft(r)) : lt(this), t._chunkSteps(o);
          } else
            ln(r, t), lt(this);
        }
        /** @internal */
        [lr]() {
        }
      }
      Object.defineProperties(he.prototype, {
        close: { enumerable: !0 },
        enqueue: { enumerable: !0 },
        error: { enumerable: !0 },
        desiredSize: { enumerable: !0 }
      }), c(he.prototype.close, "close"), c(he.prototype.enqueue, "enqueue"), c(he.prototype.error, "error"), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(he.prototype, Symbol.toStringTag, {
        value: "ReadableStreamDefaultController",
        configurable: !0
      });
      function $t(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_controlledReadableStream") ? !1 : e instanceof he;
      }
      function lt(e) {
        if (!eo(e))
          return;
        if (e._pulling) {
          e._pullAgain = !0;
          return;
        }
        e._pulling = !0;
        const r = e._pullAlgorithm();
        y(r, () => (e._pulling = !1, e._pullAgain && (e._pullAgain = !1, lt(e)), null), (o) => (J(e, o), null));
      }
      function eo(e) {
        const t = e._controlledReadableStream;
        return !He(e) || !e._started ? !1 : !!(Pe(t) && Rt(t) > 0 || Mr(e) > 0);
      }
      function Mt(e) {
        e._pullAlgorithm = void 0, e._cancelAlgorithm = void 0, e._strategySizeAlgorithm = void 0;
      }
      function ze(e) {
        if (!He(e))
          return;
        const t = e._controlledReadableStream;
        e._closeRequested = !0, e._queue.length === 0 && (Mt(e), ft(t));
      }
      function xe(e, t) {
        if (!He(e))
          return;
        const r = e._controlledReadableStream;
        if (Pe(r) && Rt(r) > 0)
          pr(r, t, !1);
        else {
          let o;
          try {
            o = e._strategySizeAlgorithm(t);
          } catch (s) {
            throw J(e, s), s;
          }
          try {
            Rr(e, t, o);
          } catch (s) {
            throw J(e, s), s;
          }
        }
        lt(e);
      }
      function J(e, t) {
        const r = e._controlledReadableStream;
        r._state === "readable" && (we(e), Mt(e), oo(r, t));
      }
      function Mr(e) {
        const t = e._controlledReadableStream._state;
        return t === "errored" ? null : t === "closed" ? 0 : e._strategyHWM - e._queueTotalSize;
      }
      function Ga(e) {
        return !eo(e);
      }
      function He(e) {
        const t = e._controlledReadableStream._state;
        return !e._closeRequested && t === "readable";
      }
      function to(e, t, r, o, s, f, d) {
        t._controlledReadableStream = e, t._queue = void 0, t._queueTotalSize = void 0, we(t), t._started = !1, t._closeRequested = !1, t._pullAgain = !1, t._pulling = !1, t._strategySizeAlgorithm = d, t._strategyHWM = f, t._pullAlgorithm = o, t._cancelAlgorithm = s, e._readableStreamController = t;
        const b = r();
        y(w(b), () => (t._started = !0, lt(t), null), (g) => (J(t, g), null));
      }
      function Za(e, t, r, o) {
        const s = Object.create(he.prototype);
        let f, d, b;
        t.start !== void 0 ? f = () => t.start(s) : f = () => {
        }, t.pull !== void 0 ? d = () => t.pull(s) : d = () => w(void 0), t.cancel !== void 0 ? b = (g) => t.cancel(g) : b = () => w(void 0), to(e, s, f, d, b, r, o);
      }
      function Ut(e) {
        return new TypeError(`ReadableStreamDefaultController.prototype.${e} can only be used on a ReadableStreamDefaultController`);
      }
      function Ka(e, t) {
        return We(e._readableStreamController) ? Xa(e) : Ja(e);
      }
      function Ja(e, t) {
        const r = je(e);
        let o = !1, s = !1, f = !1, d = !1, b, g, p, R, C;
        const A = E((M) => {
          C = M;
        });
        function ee() {
          return o ? (s = !0, w(void 0)) : (o = !0, tt(r, {
            _chunkSteps: (U) => {
              se(() => {
                s = !1;
                const Z = U, be = U;
                f || xe(p._readableStreamController, Z), d || xe(R._readableStreamController, be), o = !1, s && ee();
              });
            },
            _closeSteps: () => {
              o = !1, f || ze(p._readableStreamController), d || ze(R._readableStreamController), (!f || !d) && C(void 0);
            },
            _errorSteps: () => {
              o = !1;
            }
          }), w(void 0));
        }
        function Ve(M) {
          if (f = !0, b = M, d) {
            const U = rt([b, g]), Z = X(e, U);
            C(Z);
          }
          return A;
        }
        function ve(M) {
          if (d = !0, g = M, f) {
            const U = rt([b, g]), Z = X(e, U);
            C(Z);
          }
          return A;
        }
        function me() {
        }
        return p = ut(me, ee, Ve), R = ut(me, ee, ve), k(r._closedPromise, (M) => (J(p._readableStreamController, M), J(R._readableStreamController, M), (!f || !d) && C(void 0), null)), [p, R];
      }
      function Xa(e) {
        let t = je(e), r = !1, o = !1, s = !1, f = !1, d = !1, b, g, p, R, C;
        const A = E((_) => {
          C = _;
        });
        function ee(_) {
          k(_._closedPromise, (T) => (_ !== t || (G(p._readableStreamController, T), G(R._readableStreamController, T), (!f || !d) && C(void 0)), null));
        }
        function Ve() {
          ke(t) && (le(t), t = je(e), ee(t)), tt(t, {
            _chunkSteps: (T) => {
              se(() => {
                o = !1, s = !1;
                const B = T;
                let Q = T;
                if (!f && !d)
                  try {
                    Q = gn(T);
                  } catch (Ye) {
                    G(p._readableStreamController, Ye), G(R._readableStreamController, Ye), C(X(e, Ye));
                    return;
                  }
                f || vt(p._readableStreamController, B), d || vt(R._readableStreamController, Q), r = !1, o ? me() : s && M();
              });
            },
            _closeSteps: () => {
              r = !1, f || nt(p._readableStreamController), d || nt(R._readableStreamController), p._readableStreamController._pendingPullIntos.length > 0 && At(p._readableStreamController, 0), R._readableStreamController._pendingPullIntos.length > 0 && At(R._readableStreamController, 0), (!f || !d) && C(void 0);
            },
            _errorSteps: () => {
              r = !1;
            }
          });
        }
        function ve(_, T) {
          ge(t) && (le(t), t = kn(e), ee(t));
          const B = T ? R : p, Q = T ? p : R;
          zn(t, _, 1, {
            _chunkSteps: (Ge) => {
              se(() => {
                o = !1, s = !1;
                const Ze = T ? d : f;
                if (T ? f : d)
                  Ze || Bt(B._readableStreamController, Ge);
                else {
                  let _o;
                  try {
                    _o = gn(Ge);
                  } catch (Qr) {
                    G(B._readableStreamController, Qr), G(Q._readableStreamController, Qr), C(X(e, Qr));
                    return;
                  }
                  Ze || Bt(B._readableStreamController, Ge), vt(Q._readableStreamController, _o);
                }
                r = !1, o ? me() : s && M();
              });
            },
            _closeSteps: (Ge) => {
              r = !1;
              const Ze = T ? d : f, Zt = T ? f : d;
              Ze || nt(B._readableStreamController), Zt || nt(Q._readableStreamController), Ge !== void 0 && (Ze || Bt(B._readableStreamController, Ge), !Zt && Q._readableStreamController._pendingPullIntos.length > 0 && At(Q._readableStreamController, 0)), (!Ze || !Zt) && C(void 0);
            },
            _errorSteps: () => {
              r = !1;
            }
          });
        }
        function me() {
          if (r)
            return o = !0, w(void 0);
          r = !0;
          const _ = vr(p._readableStreamController);
          return _ === null ? Ve() : ve(_._view, !1), w(void 0);
        }
        function M() {
          if (r)
            return s = !0, w(void 0);
          r = !0;
          const _ = vr(R._readableStreamController);
          return _ === null ? Ve() : ve(_._view, !0), w(void 0);
        }
        function U(_) {
          if (f = !0, b = _, d) {
            const T = rt([b, g]), B = X(e, T);
            C(B);
          }
          return A;
        }
        function Z(_) {
          if (d = !0, g = _, f) {
            const T = rt([b, g]), B = X(e, T);
            C(B);
          }
          return A;
        }
        function be() {
        }
        return p = no(be, me, U), R = no(be, M, Z), ee(t), [p, R];
      }
      function ei(e) {
        return l(e) && typeof e.getReader < "u";
      }
      function ti(e) {
        return ei(e) ? ni(e.getReader()) : ri(e);
      }
      function ri(e) {
        let t;
        const r = _n(e, "async"), o = u;
        function s() {
          let d;
          try {
            d = Vo(r);
          } catch (g) {
            return m(g);
          }
          const b = w(d);
          return O(b, (g) => {
            if (!l(g))
              throw new TypeError("The promise returned by the iterator.next() method must fulfill with an object");
            if (Yo(g))
              ze(t._readableStreamController);
            else {
              const R = Go(g);
              xe(t._readableStreamController, R);
            }
          });
        }
        function f(d) {
          const b = r.iterator;
          let g;
          try {
            g = Tt(b, "return");
          } catch (C) {
            return m(C);
          }
          if (g === void 0)
            return w(void 0);
          let p;
          try {
            p = q(g, b, [d]);
          } catch (C) {
            return m(C);
          }
          const R = w(p);
          return O(R, (C) => {
            if (!l(C))
              throw new TypeError("The promise returned by the iterator.return() method must fulfill with an object");
          });
        }
        return t = ut(o, s, f, 0), t;
      }
      function ni(e) {
        let t;
        const r = u;
        function o() {
          let f;
          try {
            f = e.read();
          } catch (d) {
            return m(d);
          }
          return O(f, (d) => {
            if (!l(d))
              throw new TypeError("The promise returned by the reader.read() method must fulfill with an object");
            if (d.done)
              ze(t._readableStreamController);
            else {
              const b = d.value;
              xe(t._readableStreamController, b);
            }
          });
        }
        function s(f) {
          try {
            return w(e.cancel(f));
          } catch (d) {
            return m(d);
          }
        }
        return t = ut(r, o, s, 0), t;
      }
      function oi(e, t) {
        re(e, t);
        const r = e, o = r == null ? void 0 : r.autoAllocateChunkSize, s = r == null ? void 0 : r.cancel, f = r == null ? void 0 : r.pull, d = r == null ? void 0 : r.start, b = r == null ? void 0 : r.type;
        return {
          autoAllocateChunkSize: o === void 0 ? void 0 : mr(o, `${t} has member 'autoAllocateChunkSize' that`),
          cancel: s === void 0 ? void 0 : ai(s, r, `${t} has member 'cancel' that`),
          pull: f === void 0 ? void 0 : ii(f, r, `${t} has member 'pull' that`),
          start: d === void 0 ? void 0 : si(d, r, `${t} has member 'start' that`),
          type: b === void 0 ? void 0 : li(b, `${t} has member 'type' that`)
        };
      }
      function ai(e, t, r) {
        return Y(e, r), (o) => I(e, t, [o]);
      }
      function ii(e, t, r) {
        return Y(e, r), (o) => I(e, t, [o]);
      }
      function si(e, t, r) {
        return Y(e, r), (o) => q(e, t, [o]);
      }
      function li(e, t) {
        if (e = `${e}`, e !== "bytes")
          throw new TypeError(`${t} '${e}' is not a valid enumeration value for ReadableStreamType`);
        return e;
      }
      function ui(e, t) {
        return re(e, t), { preventCancel: !!(e == null ? void 0 : e.preventCancel) };
      }
      function ro(e, t) {
        re(e, t);
        const r = e == null ? void 0 : e.preventAbort, o = e == null ? void 0 : e.preventCancel, s = e == null ? void 0 : e.preventClose, f = e == null ? void 0 : e.signal;
        return f !== void 0 && fi(f, `${t} has member 'signal' that`), {
          preventAbort: !!r,
          preventCancel: !!o,
          preventClose: !!s,
          signal: f
        };
      }
      function fi(e, t) {
        if (!_a(e))
          throw new TypeError(`${t} is not an AbortSignal.`);
      }
      function di(e, t) {
        re(e, t);
        const r = e == null ? void 0 : e.readable;
        cr(r, "readable", "ReadableWritablePair"), br(r, `${t} has member 'readable' that`);
        const o = e == null ? void 0 : e.writable;
        return cr(o, "writable", "ReadableWritablePair"), Ln(o, `${t} has member 'writable' that`), { readable: r, writable: o };
      }
      class L {
        constructor(t = {}, r = {}) {
          t === void 0 ? t = null : an(t, "First parameter");
          const o = kt(r, "Second parameter"), s = oi(t, "First parameter");
          if (Ur(this), s.type === "bytes") {
            if (o.size !== void 0)
              throw new RangeError("The strategy for a byte stream cannot have a size function");
            const f = at(o, 0);
            aa(this, s, f);
          } else {
            const f = qt(o), d = at(o, 1);
            Za(this, s, d, f);
          }
        }
        /**
         * Whether or not the readable stream is locked to a {@link ReadableStreamDefaultReader | reader}.
         */
        get locked() {
          if (!Te(this))
            throw Fe("locked");
          return Pe(this);
        }
        /**
         * Cancels the stream, signaling a loss of interest in the stream by a consumer.
         *
         * The supplied `reason` argument will be given to the underlying source's {@link UnderlyingSource.cancel | cancel()}
         * method, which might or might not use it.
         */
        cancel(t = void 0) {
          return Te(this) ? Pe(this) ? m(new TypeError("Cannot cancel a stream that already has a reader")) : X(this, t) : m(Fe("cancel"));
        }
        getReader(t = void 0) {
          if (!Te(this))
            throw Fe("getReader");
          return sa(t, "First parameter").mode === void 0 ? je(this) : kn(this);
        }
        pipeThrough(t, r = {}) {
          if (!Te(this))
            throw Fe("pipeThrough");
          ue(t, 1, "pipeThrough");
          const o = di(t, "First parameter"), s = ro(r, "Second parameter");
          if (Pe(this))
            throw new TypeError("ReadableStream.prototype.pipeThrough cannot be used on a locked ReadableStream");
          if (Ue(o.writable))
            throw new TypeError("ReadableStream.prototype.pipeThrough cannot be used on a locked WritableStream");
          const f = Xn(this, o.writable, s.preventClose, s.preventAbort, s.preventCancel, s.signal);
          return H(f), o.readable;
        }
        pipeTo(t, r = {}) {
          if (!Te(this))
            return m(Fe("pipeTo"));
          if (t === void 0)
            return m("Parameter 1 is required in 'pipeTo'.");
          if (!Me(t))
            return m(new TypeError("ReadableStream.prototype.pipeTo's first argument must be a WritableStream"));
          let o;
          try {
            o = ro(r, "Second parameter");
          } catch (s) {
            return m(s);
          }
          return Pe(this) ? m(new TypeError("ReadableStream.prototype.pipeTo cannot be used on a locked ReadableStream")) : Ue(t) ? m(new TypeError("ReadableStream.prototype.pipeTo cannot be used on a locked WritableStream")) : Xn(this, t, o.preventClose, o.preventAbort, o.preventCancel, o.signal);
        }
        /**
         * Tees this readable stream, returning a two-element array containing the two resulting branches as
         * new {@link ReadableStream} instances.
         *
         * Teeing a stream will lock it, preventing any other consumer from acquiring a reader.
         * To cancel the stream, cancel both of the resulting branches; a composite cancellation reason will then be
         * propagated to the stream's underlying source.
         *
         * Note that the chunks seen in each branch will be the same object. If the chunks are not immutable,
         * this could allow interference between the two branches.
         */
        tee() {
          if (!Te(this))
            throw Fe("tee");
          const t = Ka(this);
          return rt(t);
        }
        values(t = void 0) {
          if (!Te(this))
            throw Fe("values");
          const r = ui(t, "First parameter");
          return Ho(this, r.preventCancel);
        }
        [Sr](t) {
          return this.values(t);
        }
        /**
         * Creates a new ReadableStream wrapping the provided iterable or async iterable.
         *
         * This can be used to adapt various kinds of objects into a readable stream,
         * such as an array, an async generator, or a Node.js readable stream.
         */
        static from(t) {
          return ti(t);
        }
      }
      Object.defineProperties(L, {
        from: { enumerable: !0 }
      }), Object.defineProperties(L.prototype, {
        cancel: { enumerable: !0 },
        getReader: { enumerable: !0 },
        pipeThrough: { enumerable: !0 },
        pipeTo: { enumerable: !0 },
        tee: { enumerable: !0 },
        values: { enumerable: !0 },
        locked: { enumerable: !0 }
      }), c(L.from, "from"), c(L.prototype.cancel, "cancel"), c(L.prototype.getReader, "getReader"), c(L.prototype.pipeThrough, "pipeThrough"), c(L.prototype.pipeTo, "pipeTo"), c(L.prototype.tee, "tee"), c(L.prototype.values, "values"), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(L.prototype, Symbol.toStringTag, {
        value: "ReadableStream",
        configurable: !0
      }), Object.defineProperty(L.prototype, Sr, {
        value: L.prototype.values,
        writable: !0,
        configurable: !0
      });
      function ut(e, t, r, o = 1, s = () => 1) {
        const f = Object.create(L.prototype);
        Ur(f);
        const d = Object.create(he.prototype);
        return to(f, d, e, t, r, o, s), f;
      }
      function no(e, t, r) {
        const o = Object.create(L.prototype);
        Ur(o);
        const s = Object.create(de.prototype);
        return qn(o, s, e, t, r, 0, void 0), o;
      }
      function Ur(e) {
        e._state = "readable", e._reader = void 0, e._storedError = void 0, e._disturbed = !1;
      }
      function Te(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_readableStreamController") ? !1 : e instanceof L;
      }
      function Pe(e) {
        return e._reader !== void 0;
      }
      function X(e, t) {
        if (e._disturbed = !0, e._state === "closed")
          return w(void 0);
        if (e._state === "errored")
          return m(e._storedError);
        ft(e);
        const r = e._reader;
        if (r !== void 0 && ke(r)) {
          const s = r._readIntoRequests;
          r._readIntoRequests = new $(), s.forEach((f) => {
            f._closeSteps(void 0);
          });
        }
        const o = e._readableStreamController[ir](t);
        return O(o, u);
      }
      function ft(e) {
        e._state = "closed";
        const t = e._reader;
        if (t !== void 0 && (nn(t), ge(t))) {
          const r = t._readRequests;
          t._readRequests = new $(), r.forEach((o) => {
            o._closeSteps();
          });
        }
      }
      function oo(e, t) {
        e._state = "errored", e._storedError = t;
        const r = e._reader;
        r !== void 0 && (dr(r, t), ge(r) ? fn(r, t) : Fn(r, t));
      }
      function Fe(e) {
        return new TypeError(`ReadableStream.prototype.${e} can only be used on a ReadableStream`);
      }
      function ao(e, t) {
        re(e, t);
        const r = e == null ? void 0 : e.highWaterMark;
        return cr(r, "highWaterMark", "QueuingStrategyInit"), {
          highWaterMark: hr(r)
        };
      }
      const io = (e) => e.byteLength;
      c(io, "size");
      class Nt {
        constructor(t) {
          ue(t, 1, "ByteLengthQueuingStrategy"), t = ao(t, "First parameter"), this._byteLengthQueuingStrategyHighWaterMark = t.highWaterMark;
        }
        /**
         * Returns the high water mark provided to the constructor.
         */
        get highWaterMark() {
          if (!lo(this))
            throw so("highWaterMark");
          return this._byteLengthQueuingStrategyHighWaterMark;
        }
        /**
         * Measures the size of `chunk` by returning the value of its `byteLength` property.
         */
        get size() {
          if (!lo(this))
            throw so("size");
          return io;
        }
      }
      Object.defineProperties(Nt.prototype, {
        highWaterMark: { enumerable: !0 },
        size: { enumerable: !0 }
      }), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(Nt.prototype, Symbol.toStringTag, {
        value: "ByteLengthQueuingStrategy",
        configurable: !0
      });
      function so(e) {
        return new TypeError(`ByteLengthQueuingStrategy.prototype.${e} can only be used on a ByteLengthQueuingStrategy`);
      }
      function lo(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_byteLengthQueuingStrategyHighWaterMark") ? !1 : e instanceof Nt;
      }
      const uo = () => 1;
      c(uo, "size");
      class xt {
        constructor(t) {
          ue(t, 1, "CountQueuingStrategy"), t = ao(t, "First parameter"), this._countQueuingStrategyHighWaterMark = t.highWaterMark;
        }
        /**
         * Returns the high water mark provided to the constructor.
         */
        get highWaterMark() {
          if (!co(this))
            throw fo("highWaterMark");
          return this._countQueuingStrategyHighWaterMark;
        }
        /**
         * Measures the size of `chunk` by always returning 1.
         * This ensures that the total queue size is a count of the number of chunks in the queue.
         */
        get size() {
          if (!co(this))
            throw fo("size");
          return uo;
        }
      }
      Object.defineProperties(xt.prototype, {
        highWaterMark: { enumerable: !0 },
        size: { enumerable: !0 }
      }), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(xt.prototype, Symbol.toStringTag, {
        value: "CountQueuingStrategy",
        configurable: !0
      });
      function fo(e) {
        return new TypeError(`CountQueuingStrategy.prototype.${e} can only be used on a CountQueuingStrategy`);
      }
      function co(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_countQueuingStrategyHighWaterMark") ? !1 : e instanceof xt;
      }
      function ci(e, t) {
        re(e, t);
        const r = e == null ? void 0 : e.cancel, o = e == null ? void 0 : e.flush, s = e == null ? void 0 : e.readableType, f = e == null ? void 0 : e.start, d = e == null ? void 0 : e.transform, b = e == null ? void 0 : e.writableType;
        return {
          cancel: r === void 0 ? void 0 : pi(r, e, `${t} has member 'cancel' that`),
          flush: o === void 0 ? void 0 : hi(o, e, `${t} has member 'flush' that`),
          readableType: s,
          start: f === void 0 ? void 0 : mi(f, e, `${t} has member 'start' that`),
          transform: d === void 0 ? void 0 : bi(d, e, `${t} has member 'transform' that`),
          writableType: b
        };
      }
      function hi(e, t, r) {
        return Y(e, r), (o) => I(e, t, [o]);
      }
      function mi(e, t, r) {
        return Y(e, r), (o) => q(e, t, [o]);
      }
      function bi(e, t, r) {
        return Y(e, r), (o, s) => I(e, t, [o, s]);
      }
      function pi(e, t, r) {
        return Y(e, r), (o) => I(e, t, [o]);
      }
      class Ht {
        constructor(t = {}, r = {}, o = {}) {
          t === void 0 && (t = null);
          const s = kt(r, "Second parameter"), f = kt(o, "Third parameter"), d = ci(t, "First parameter");
          if (d.readableType !== void 0)
            throw new RangeError("Invalid readableType specified");
          if (d.writableType !== void 0)
            throw new RangeError("Invalid writableType specified");
          const b = at(f, 0), g = qt(f), p = at(s, 1), R = qt(s);
          let C;
          const A = E((ee) => {
            C = ee;
          });
          yi(this, A, p, R, b, g), gi(this, d), d.start !== void 0 ? C(d.start(this._transformStreamController)) : C(void 0);
        }
        /**
         * The readable side of the transform stream.
         */
        get readable() {
          if (!ho(this))
            throw yo("readable");
          return this._readable;
        }
        /**
         * The writable side of the transform stream.
         */
        get writable() {
          if (!ho(this))
            throw yo("writable");
          return this._writable;
        }
      }
      Object.defineProperties(Ht.prototype, {
        readable: { enumerable: !0 },
        writable: { enumerable: !0 }
      }), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(Ht.prototype, Symbol.toStringTag, {
        value: "TransformStream",
        configurable: !0
      });
      function yi(e, t, r, o, s, f) {
        function d() {
          return t;
        }
        function b(A) {
          return Ri(e, A);
        }
        function g(A) {
          return Ci(e, A);
        }
        function p() {
          return Ti(e);
        }
        e._writable = wa(d, b, p, g, r, o);
        function R() {
          return Pi(e);
        }
        function C(A) {
          return Ei(e, A);
        }
        e._readable = ut(d, R, C, s, f), e._backpressure = void 0, e._backpressureChangePromise = void 0, e._backpressureChangePromise_resolve = void 0, Qt(e, !0), e._transformStreamController = void 0;
      }
      function ho(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_transformStreamController") ? !1 : e instanceof Ht;
      }
      function mo(e, t) {
        J(e._readable._readableStreamController, t), Nr(e, t);
      }
      function Nr(e, t) {
        Yt(e._transformStreamController), it(e._writable._writableStreamController, t), xr(e);
      }
      function xr(e) {
        e._backpressure && Qt(e, !1);
      }
      function Qt(e, t) {
        e._backpressureChangePromise !== void 0 && e._backpressureChangePromise_resolve(), e._backpressureChangePromise = E((r) => {
          e._backpressureChangePromise_resolve = r;
        }), e._backpressure = t;
      }
      class Ee {
        constructor() {
          throw new TypeError("Illegal constructor");
        }
        /**
         * Returns the desired size to fill the readable side’s internal queue. It can be negative, if the queue is over-full.
         */
        get desiredSize() {
          if (!Vt(this))
            throw Gt("desiredSize");
          const t = this._controlledTransformStream._readable._readableStreamController;
          return Mr(t);
        }
        enqueue(t = void 0) {
          if (!Vt(this))
            throw Gt("enqueue");
          bo(this, t);
        }
        /**
         * Errors both the readable side and the writable side of the controlled transform stream, making all future
         * interactions with it fail with the given error `e`. Any chunks queued for transformation will be discarded.
         */
        error(t = void 0) {
          if (!Vt(this))
            throw Gt("error");
          Si(this, t);
        }
        /**
         * Closes the readable side and errors the writable side of the controlled transform stream. This is useful when the
         * transformer only needs to consume a portion of the chunks written to the writable side.
         */
        terminate() {
          if (!Vt(this))
            throw Gt("terminate");
          wi(this);
        }
      }
      Object.defineProperties(Ee.prototype, {
        enqueue: { enumerable: !0 },
        error: { enumerable: !0 },
        terminate: { enumerable: !0 },
        desiredSize: { enumerable: !0 }
      }), c(Ee.prototype.enqueue, "enqueue"), c(Ee.prototype.error, "error"), c(Ee.prototype.terminate, "terminate"), typeof Symbol.toStringTag == "symbol" && Object.defineProperty(Ee.prototype, Symbol.toStringTag, {
        value: "TransformStreamDefaultController",
        configurable: !0
      });
      function Vt(e) {
        return !l(e) || !Object.prototype.hasOwnProperty.call(e, "_controlledTransformStream") ? !1 : e instanceof Ee;
      }
      function _i(e, t, r, o, s) {
        t._controlledTransformStream = e, e._transformStreamController = t, t._transformAlgorithm = r, t._flushAlgorithm = o, t._cancelAlgorithm = s, t._finishPromise = void 0, t._finishPromise_resolve = void 0, t._finishPromise_reject = void 0;
      }
      function gi(e, t) {
        const r = Object.create(Ee.prototype);
        let o, s, f;
        t.transform !== void 0 ? o = (d) => t.transform(d, r) : o = (d) => {
          try {
            return bo(r, d), w(void 0);
          } catch (b) {
            return m(b);
          }
        }, t.flush !== void 0 ? s = () => t.flush(r) : s = () => w(void 0), t.cancel !== void 0 ? f = (d) => t.cancel(d) : f = () => w(void 0), _i(e, r, o, s, f);
      }
      function Yt(e) {
        e._transformAlgorithm = void 0, e._flushAlgorithm = void 0, e._cancelAlgorithm = void 0;
      }
      function bo(e, t) {
        const r = e._controlledTransformStream, o = r._readable._readableStreamController;
        if (!He(o))
          throw new TypeError("Readable side is not in a state that permits enqueue");
        try {
          xe(o, t);
        } catch (f) {
          throw Nr(r, f), r._readable._storedError;
        }
        Ga(o) !== r._backpressure && Qt(r, !0);
      }
      function Si(e, t) {
        mo(e._controlledTransformStream, t);
      }
      function po(e, t) {
        const r = e._transformAlgorithm(t);
        return O(r, void 0, (o) => {
          throw mo(e._controlledTransformStream, o), o;
        });
      }
      function wi(e) {
        const t = e._controlledTransformStream, r = t._readable._readableStreamController;
        ze(r);
        const o = new TypeError("TransformStream terminated");
        Nr(t, o);
      }
      function Ri(e, t) {
        const r = e._transformStreamController;
        if (e._backpressure) {
          const o = e._backpressureChangePromise;
          return O(o, () => {
            const s = e._writable;
            if (s._state === "erroring")
              throw s._storedError;
            return po(r, t);
          });
        }
        return po(r, t);
      }
      function Ci(e, t) {
        const r = e._transformStreamController;
        if (r._finishPromise !== void 0)
          return r._finishPromise;
        const o = e._readable;
        r._finishPromise = E((f, d) => {
          r._finishPromise_resolve = f, r._finishPromise_reject = d;
        });
        const s = r._cancelAlgorithm(t);
        return Yt(r), y(s, () => (o._state === "errored" ? Qe(r, o._storedError) : (J(o._readableStreamController, t), Hr(r)), null), (f) => (J(o._readableStreamController, f), Qe(r, f), null)), r._finishPromise;
      }
      function Ti(e) {
        const t = e._transformStreamController;
        if (t._finishPromise !== void 0)
          return t._finishPromise;
        const r = e._readable;
        t._finishPromise = E((s, f) => {
          t._finishPromise_resolve = s, t._finishPromise_reject = f;
        });
        const o = t._flushAlgorithm();
        return Yt(t), y(o, () => (r._state === "errored" ? Qe(t, r._storedError) : (ze(r._readableStreamController), Hr(t)), null), (s) => (J(r._readableStreamController, s), Qe(t, s), null)), t._finishPromise;
      }
      function Pi(e) {
        return Qt(e, !1), e._backpressureChangePromise;
      }
      function Ei(e, t) {
        const r = e._transformStreamController;
        if (r._finishPromise !== void 0)
          return r._finishPromise;
        const o = e._writable;
        r._finishPromise = E((f, d) => {
          r._finishPromise_resolve = f, r._finishPromise_reject = d;
        });
        const s = r._cancelAlgorithm(t);
        return Yt(r), y(s, () => (o._state === "errored" ? Qe(r, o._storedError) : (it(o._writableStreamController, t), xr(e), Hr(r)), null), (f) => (it(o._writableStreamController, f), xr(e), Qe(r, f), null)), r._finishPromise;
      }
      function Gt(e) {
        return new TypeError(`TransformStreamDefaultController.prototype.${e} can only be used on a TransformStreamDefaultController`);
      }
      function Hr(e) {
        e._finishPromise_resolve !== void 0 && (e._finishPromise_resolve(), e._finishPromise_resolve = void 0, e._finishPromise_reject = void 0);
      }
      function Qe(e, t) {
        e._finishPromise_reject !== void 0 && (H(e._finishPromise), e._finishPromise_reject(t), e._finishPromise_resolve = void 0, e._finishPromise_reject = void 0);
      }
      function yo(e) {
        return new TypeError(`TransformStream.prototype.${e} can only be used on a TransformStream`);
      }
      a.ByteLengthQueuingStrategy = Nt, a.CountQueuingStrategy = xt, a.ReadableByteStreamController = de, a.ReadableStream = L, a.ReadableStreamBYOBReader = Re, a.ReadableStreamBYOBRequest = Be, a.ReadableStreamDefaultController = he, a.ReadableStreamDefaultReader = _e, a.TransformStream = Ht, a.TransformStreamDefaultController = Ee, a.WritableStream = Ce, a.WritableStreamDefaultController = Ne, a.WritableStreamDefaultWriter = ce;
    });
  }(ct, ct.exports)), ct.exports;
}
var To;
function zi() {
  if (To) return Ro;
  To = 1;
  const i = 65536;
  if (!globalThis.ReadableStream)
    try {
      const n = require("node:process"), { emitWarning: a } = n;
      try {
        n.emitWarning = () => {
        }, Object.assign(globalThis, require("node:stream/web")), n.emitWarning = a;
      } catch (u) {
        throw n.emitWarning = a, u;
      }
    } catch {
      Object.assign(globalThis, Ii());
    }
  try {
    const { Blob: n } = require("buffer");
    n && !n.prototype.stream && (n.prototype.stream = function(u) {
      let l = 0;
      const h = this;
      return new ReadableStream({
        type: "bytes",
        async pull(c) {
          const v = await h.slice(l, Math.min(h.size, l + i)).arrayBuffer();
          l += v.byteLength, c.enqueue(new Uint8Array(v)), l === h.size && c.close();
        }
      });
    });
  } catch {
  }
  return Ro;
}
zi();
/*! fetch-blob. MIT License. Jimmy Wärting <https://jimmy.warting.se/opensource> */
const Po = 65536;
async function* Vr(i, n = !0) {
  for (const a of i)
    if ("stream" in a)
      yield* (
        /** @type {AsyncIterableIterator<Uint8Array>} */
        a.stream()
      );
    else if (ArrayBuffer.isView(a))
      if (n) {
        let u = a.byteOffset;
        const l = a.byteOffset + a.byteLength;
        for (; u !== l; ) {
          const h = Math.min(l - u, Po), c = a.buffer.slice(u, u + h);
          u += c.byteLength, yield new Uint8Array(c);
        }
      } else
        yield a;
    else {
      let u = 0, l = (
        /** @type {Blob} */
        a
      );
      for (; u !== l.size; ) {
        const c = await l.slice(u, Math.min(l.size, u + Po)).arrayBuffer();
        u += c.byteLength, yield new Uint8Array(c);
      }
    }
}
var pe, yt, et, nr, De;
const ko = (De = class {
  /**
   * The Blob() constructor returns a new Blob object. The content
   * of the blob consists of the concatenation of the values given
   * in the parameter array.
   *
   * @param {*} blobParts
   * @param {{ type?: string, endings?: string }} [options]
   */
  constructor(n = [], a = {}) {
    /** @type {Array.<(Blob|Uint8Array)>} */
    Ae(this, pe, []);
    Ae(this, yt, "");
    Ae(this, et, 0);
    Ae(this, nr, "transparent");
    if (typeof n != "object" || n === null)
      throw new TypeError("Failed to construct 'Blob': The provided value cannot be converted to a sequence.");
    if (typeof n[Symbol.iterator] != "function")
      throw new TypeError("Failed to construct 'Blob': The object must have a callable @@iterator property.");
    if (typeof a != "object" && typeof a != "function")
      throw new TypeError("Failed to construct 'Blob': parameter 2 cannot convert to dictionary.");
    a === null && (a = {});
    const u = new TextEncoder();
    for (const h of n) {
      let c;
      ArrayBuffer.isView(h) ? c = new Uint8Array(h.buffer.slice(h.byteOffset, h.byteOffset + h.byteLength)) : h instanceof ArrayBuffer ? c = new Uint8Array(h.slice(0)) : h instanceof De ? c = h : c = u.encode(`${h}`), oe(this, et, z(this, et) + (ArrayBuffer.isView(c) ? c.byteLength : c.size)), z(this, pe).push(c);
    }
    oe(this, nr, `${a.endings === void 0 ? "transparent" : a.endings}`);
    const l = a.type === void 0 ? "" : String(a.type);
    oe(this, yt, /^[\x20-\x7E]*$/.test(l) ? l : "");
  }
  /**
   * The Blob interface's size property returns the
   * size of the Blob in bytes.
   */
  get size() {
    return z(this, et);
  }
  /**
   * The type property of a Blob object returns the MIME type of the file.
   */
  get type() {
    return z(this, yt);
  }
  /**
   * The text() method in the Blob interface returns a Promise
   * that resolves with a string containing the contents of
   * the blob, interpreted as UTF-8.
   *
   * @return {Promise<string>}
   */
  async text() {
    const n = new TextDecoder();
    let a = "";
    for await (const u of Vr(z(this, pe), !1))
      a += n.decode(u, { stream: !0 });
    return a += n.decode(), a;
  }
  /**
   * The arrayBuffer() method in the Blob interface returns a
   * Promise that resolves with the contents of the blob as
   * binary data contained in an ArrayBuffer.
   *
   * @return {Promise<ArrayBuffer>}
   */
  async arrayBuffer() {
    const n = new Uint8Array(this.size);
    let a = 0;
    for await (const u of Vr(z(this, pe), !1))
      n.set(u, a), a += u.length;
    return n.buffer;
  }
  stream() {
    const n = Vr(z(this, pe), !0);
    return new globalThis.ReadableStream({
      // @ts-ignore
      type: "bytes",
      async pull(a) {
        const u = await n.next();
        u.done ? a.close() : a.enqueue(u.value);
      },
      async cancel() {
        await n.return();
      }
    });
  }
  /**
   * The Blob interface's slice() method creates and returns a
   * new Blob object which contains data from a subset of the
   * blob on which it's called.
   *
   * @param {number} [start]
   * @param {number} [end]
   * @param {string} [type]
   */
  slice(n = 0, a = this.size, u = "") {
    const { size: l } = this;
    let h = n < 0 ? Math.max(l + n, 0) : Math.min(n, l), c = a < 0 ? Math.max(l + a, 0) : Math.min(a, l);
    const P = Math.max(c - h, 0), v = z(this, pe), S = [];
    let E = 0;
    for (const m of v) {
      if (E >= P)
        break;
      const W = ArrayBuffer.isView(m) ? m.byteLength : m.size;
      if (h && W <= h)
        h -= W, c -= W;
      else {
        let y;
        ArrayBuffer.isView(m) ? (y = m.subarray(h, Math.min(W, c)), E += y.byteLength) : (y = m.slice(h, Math.min(W, c)), E += y.size), c -= W, S.push(y), h = 0;
      }
    }
    const w = new De([], { type: String(u).toLowerCase() });
    return oe(w, et, P), oe(w, pe, S), w;
  }
  get [Symbol.toStringTag]() {
    return "Blob";
  }
  static [Symbol.hasInstance](n) {
    return n && typeof n == "object" && typeof n.constructor == "function" && (typeof n.stream == "function" || typeof n.arrayBuffer == "function") && /^(Blob|File)$/.test(n[Symbol.toStringTag]);
  }
}, pe = new WeakMap(), yt = new WeakMap(), et = new WeakMap(), nr = new WeakMap(), De);
Object.defineProperties(ko.prototype, {
  size: { enumerable: !0 },
  type: { enumerable: !0 },
  slice: { enumerable: !0 }
});
const er = ko;
var _t, gt, Wo;
const Fi = (Wo = class extends er {
  /**
   * @param {*[]} fileBits
   * @param {string} fileName
   * @param {{lastModified?: number, type?: string}} options
   */
  // @ts-ignore
  constructor(a, u, l = {}) {
    if (arguments.length < 2)
      throw new TypeError(`Failed to construct 'File': 2 arguments required, but only ${arguments.length} present.`);
    super(a, l);
    Ae(this, _t, 0);
    Ae(this, gt, "");
    l === null && (l = {});
    const h = l.lastModified === void 0 ? Date.now() : Number(l.lastModified);
    Number.isNaN(h) || oe(this, _t, h), oe(this, gt, String(u));
  }
  get name() {
    return z(this, gt);
  }
  get lastModified() {
    return z(this, _t);
  }
  get [Symbol.toStringTag]() {
    return "File";
  }
  static [Symbol.hasInstance](a) {
    return !!a && a instanceof er && /^(File)$/.test(a[Symbol.toStringTag]);
  }
}, _t = new WeakMap(), gt = new WeakMap(), Wo), Li = Fi;
/*! formdata-polyfill. MIT License. Jimmy Wärting <https://jimmy.warting.se/opensource> */
var { toStringTag: ht, iterator: Di, hasInstance: ji } = Symbol, Eo = Math.random, $i = "append,set,get,getAll,delete,keys,values,entries,forEach,constructor".split(","), vo = (i, n, a) => (i += "", /^(Blob|File)$/.test(n && n[ht]) ? [(a = a !== void 0 ? a + "" : n[ht] == "File" ? n.name : "blob", i), n.name !== a || n[ht] == "blob" ? new Li([n], a, n) : n] : [i, n + ""]), Yr = (i, n) => (n ? i : i.replace(/\r?\n|\r/g, `\r
`)).replace(/\n/g, "%0A").replace(/\r/g, "%0D").replace(/"/g, "%22"), Le = (i, n, a) => {
  if (n.length < a)
    throw new TypeError(`Failed to execute '${i}' on 'FormData': ${a} arguments required, but only ${n.length} present.`);
}, K, qo;
const Kr = (qo = class {
  constructor(...n) {
    Ae(this, K, []);
    if (n.length) throw new TypeError("Failed to construct 'FormData': parameter 1 is not of type 'HTMLFormElement'.");
  }
  get [ht]() {
    return "FormData";
  }
  [Di]() {
    return this.entries();
  }
  static [ji](n) {
    return n && typeof n == "object" && n[ht] === "FormData" && !$i.some((a) => typeof n[a] != "function");
  }
  append(...n) {
    Le("append", arguments, 2), z(this, K).push(vo(...n));
  }
  delete(n) {
    Le("delete", arguments, 1), n += "", oe(this, K, z(this, K).filter(([a]) => a !== n));
  }
  get(n) {
    Le("get", arguments, 1), n += "";
    for (var a = z(this, K), u = a.length, l = 0; l < u; l++) if (a[l][0] === n) return a[l][1];
    return null;
  }
  getAll(n, a) {
    return Le("getAll", arguments, 1), a = [], n += "", z(this, K).forEach((u) => u[0] === n && a.push(u[1])), a;
  }
  has(n) {
    return Le("has", arguments, 1), n += "", z(this, K).some((a) => a[0] === n);
  }
  forEach(n, a) {
    Le("forEach", arguments, 1);
    for (var [u, l] of this) n.call(a, l, u, this);
  }
  set(...n) {
    Le("set", arguments, 2);
    var a = [], u = !0;
    n = vo(...n), z(this, K).forEach((l) => {
      l[0] === n[0] ? u && (u = !a.push(n)) : a.push(l);
    }), u && a.push(n), oe(this, K, a);
  }
  *entries() {
    yield* z(this, K);
  }
  *keys() {
    for (var [n] of this) yield n;
  }
  *values() {
    for (var [, n] of this) yield n;
  }
}, K = new WeakMap(), qo);
function Mi(i, n = er) {
  var a = `${Eo()}${Eo()}`.replace(/\./g, "").slice(-28).padStart(32, "-"), u = [], l = `--${a}\r
Content-Disposition: form-data; name="`;
  return i.forEach((h, c) => typeof h == "string" ? u.push(l + Yr(c) + `"\r
\r
${h.replace(new RegExp("\\r(?!\\n)|(?<!\\r)\\n", "g"), `\r
`)}\r
`) : u.push(l + Yr(c) + `"; filename="${Yr(h.name, 1)}"\r
Content-Type: ${h.type || "application/octet-stream"}\r
\r
`, h, `\r
`)), u.push(`--${a}--`), new n(u, { type: "multipart/form-data; boundary=" + a });
}
class ar extends Error {
  constructor(n, a) {
    super(n), Error.captureStackTrace(this, this.constructor), this.type = a;
  }
  get name() {
    return this.constructor.name;
  }
  get [Symbol.toStringTag]() {
    return this.constructor.name;
  }
}
class ae extends ar {
  /**
   * @param  {string} message -      Error message for human
   * @param  {string} [type] -        Error type for machine
   * @param  {SystemError} [systemError] - For Node.js system error
   */
  constructor(n, a, u) {
    super(n, a), u && (this.code = this.errno = u.code, this.erroredSysCall = u.syscall);
  }
}
const tr = Symbol.toStringTag, Oo = (i) => typeof i == "object" && typeof i.append == "function" && typeof i.delete == "function" && typeof i.get == "function" && typeof i.getAll == "function" && typeof i.has == "function" && typeof i.set == "function" && typeof i.sort == "function" && i[tr] === "URLSearchParams", rr = (i) => i && typeof i == "object" && typeof i.arrayBuffer == "function" && typeof i.type == "string" && typeof i.stream == "function" && typeof i.constructor == "function" && /^(Blob|File)$/.test(i[tr]), Ui = (i) => typeof i == "object" && (i[tr] === "AbortSignal" || i[tr] === "EventTarget"), Ni = (i, n) => {
  const a = new URL(n).hostname, u = new URL(i).hostname;
  return a === u || a.endsWith(`.${u}`);
}, xi = (i, n) => {
  const a = new URL(n).protocol, u = new URL(i).protocol;
  return a === u;
}, Hi = Ai(ie.pipeline), N = Symbol("Body internals");
class bt {
  constructor(n, {
    size: a = 0
  } = {}) {
    let u = null;
    n === null ? n = null : Oo(n) ? n = D.from(n.toString()) : rr(n) || D.isBuffer(n) || (Xt.isAnyArrayBuffer(n) ? n = D.from(n) : ArrayBuffer.isView(n) ? n = D.from(n.buffer, n.byteOffset, n.byteLength) : n instanceof ie || (n instanceof Kr ? (n = Mi(n), u = n.type.split("=")[1]) : n = D.from(String(n))));
    let l = n;
    D.isBuffer(n) ? l = ie.Readable.from(n) : rr(n) && (l = ie.Readable.from(n.stream())), this[N] = {
      body: n,
      stream: l,
      boundary: u,
      disturbed: !1,
      error: null
    }, this.size = a, n instanceof ie && n.on("error", (h) => {
      const c = h instanceof ar ? h : new ae(`Invalid response body while trying to fetch ${this.url}: ${h.message}`, "system", h);
      this[N].error = c;
    });
  }
  get body() {
    return this[N].stream;
  }
  get bodyUsed() {
    return this[N].disturbed;
  }
  /**
   * Decode response as ArrayBuffer
   *
   * @return  Promise
   */
  async arrayBuffer() {
    const { buffer: n, byteOffset: a, byteLength: u } = await Gr(this);
    return n.slice(a, a + u);
  }
  async formData() {
    const n = this.headers.get("content-type");
    if (n.startsWith("application/x-www-form-urlencoded")) {
      const u = new Kr(), l = new URLSearchParams(await this.text());
      for (const [h, c] of l)
        u.append(h, c);
      return u;
    }
    const { toFormData: a } = await import("./multipart-parser-DkH5UnAD.js");
    return a(this.body, n);
  }
  /**
   * Return raw response as Blob
   *
   * @return Promise
   */
  async blob() {
    const n = this.headers && this.headers.get("content-type") || this[N].body && this[N].body.type || "", a = await this.arrayBuffer();
    return new er([a], {
      type: n
    });
  }
  /**
   * Decode response as json
   *
   * @return  Promise
   */
  async json() {
    const n = await this.text();
    return JSON.parse(n);
  }
  /**
   * Decode response as text
   *
   * @return  Promise
   */
  async text() {
    const n = await Gr(this);
    return new TextDecoder().decode(n);
  }
  /**
   * Decode response as buffer (non-spec api)
   *
   * @return  Promise
   */
  buffer() {
    return Gr(this);
  }
}
bt.prototype.buffer = or(bt.prototype.buffer, "Please use 'response.arrayBuffer()' instead of 'response.buffer()'", "node-fetch#buffer");
Object.defineProperties(bt.prototype, {
  body: { enumerable: !0 },
  bodyUsed: { enumerable: !0 },
  arrayBuffer: { enumerable: !0 },
  blob: { enumerable: !0 },
  json: { enumerable: !0 },
  text: { enumerable: !0 },
  data: { get: or(
    () => {
    },
    "data doesn't exist, use json(), text(), arrayBuffer(), or body instead",
    "https://github.com/node-fetch/node-fetch/issues/1000 (response)"
  ) }
});
async function Gr(i) {
  if (i[N].disturbed)
    throw new TypeError(`body used already for: ${i.url}`);
  if (i[N].disturbed = !0, i[N].error)
    throw i[N].error;
  const { body: n } = i;
  if (n === null)
    return D.alloc(0);
  if (!(n instanceof ie))
    return D.alloc(0);
  const a = [];
  let u = 0;
  try {
    for await (const l of n) {
      if (i.size > 0 && u + l.length > i.size) {
        const h = new ae(`content size at ${i.url} over limit: ${i.size}`, "max-size");
        throw n.destroy(h), h;
      }
      u += l.length, a.push(l);
    }
  } catch (l) {
    throw l instanceof ar ? l : new ae(`Invalid response body while trying to fetch ${i.url}: ${l.message}`, "system", l);
  }
  if (n.readableEnded === !0 || n._readableState.ended === !0)
    try {
      return a.every((l) => typeof l == "string") ? D.from(a.join("")) : D.concat(a, u);
    } catch (l) {
      throw new ae(`Could not create Buffer from response body for ${i.url}: ${l.message}`, "system", l);
    }
  else
    throw new ae(`Premature close of server response while trying to fetch ${i.url}`);
}
const Xr = (i, n) => {
  let a, u, { body: l } = i[N];
  if (i.bodyUsed)
    throw new Error("cannot clone body after it is used");
  return l instanceof ie && typeof l.getBoundary != "function" && (a = new Jt({ highWaterMark: n }), u = new Jt({ highWaterMark: n }), l.pipe(a), l.pipe(u), i[N].stream = a, l = u), l;
}, Qi = or(
  (i) => i.getBoundary(),
  "form-data doesn't follow the spec and requires special treatment. Use alternative package",
  "https://github.com/node-fetch/node-fetch/issues/1167"
), Io = (i, n) => i === null ? null : typeof i == "string" ? "text/plain;charset=UTF-8" : Oo(i) ? "application/x-www-form-urlencoded;charset=UTF-8" : rr(i) ? i.type || null : D.isBuffer(i) || Xt.isAnyArrayBuffer(i) || ArrayBuffer.isView(i) ? null : i instanceof Kr ? `multipart/form-data; boundary=${n[N].boundary}` : i && typeof i.getBoundary == "function" ? `multipart/form-data;boundary=${Qi(i)}` : i instanceof ie ? null : "text/plain;charset=UTF-8", Vi = (i) => {
  const { body: n } = i[N];
  return n === null ? 0 : rr(n) ? n.size : D.isBuffer(n) ? n.length : n && typeof n.getLengthSync == "function" && n.hasKnownLength && n.hasKnownLength() ? n.getLengthSync() : null;
}, Yi = async (i, { body: n }) => {
  n === null ? i.end() : await Hi(n, i);
}, Kt = typeof mt.validateHeaderName == "function" ? mt.validateHeaderName : (i) => {
  if (!/^[\^`\-\w!#$%&'*+.|~]+$/.test(i)) {
    const n = new TypeError(`Header name must be a valid HTTP token [${i}]`);
    throw Object.defineProperty(n, "code", { value: "ERR_INVALID_HTTP_TOKEN" }), n;
  }
}, Jr = typeof mt.validateHeaderValue == "function" ? mt.validateHeaderValue : (i, n) => {
  if (/[^\t\u0020-\u007E\u0080-\u00FF]/.test(n)) {
    const a = new TypeError(`Invalid character in header content ["${i}"]`);
    throw Object.defineProperty(a, "code", { value: "ERR_INVALID_CHAR" }), a;
  }
};
class ye extends URLSearchParams {
  /**
   * Headers class
   *
   * @constructor
   * @param {HeadersInit} [init] - Response headers
   */
  constructor(n) {
    let a = [];
    if (n instanceof ye) {
      const u = n.raw();
      for (const [l, h] of Object.entries(u))
        a.push(...h.map((c) => [l, c]));
    } else if (n != null) if (typeof n == "object" && !Xt.isBoxedPrimitive(n)) {
      const u = n[Symbol.iterator];
      if (u == null)
        a.push(...Object.entries(n));
      else {
        if (typeof u != "function")
          throw new TypeError("Header pairs must be iterable");
        a = [...n].map((l) => {
          if (typeof l != "object" || Xt.isBoxedPrimitive(l))
            throw new TypeError("Each header pair must be an iterable object");
          return [...l];
        }).map((l) => {
          if (l.length !== 2)
            throw new TypeError("Each header pair must be a name/value tuple");
          return [...l];
        });
      }
    } else
      throw new TypeError("Failed to construct 'Headers': The provided value is not of type '(sequence<sequence<ByteString>> or record<ByteString, ByteString>)");
    return a = a.length > 0 ? a.map(([u, l]) => (Kt(u), Jr(u, String(l)), [String(u).toLowerCase(), String(l)])) : void 0, super(a), new Proxy(this, {
      get(u, l, h) {
        switch (l) {
          case "append":
          case "set":
            return (c, P) => (Kt(c), Jr(c, String(P)), URLSearchParams.prototype[l].call(
              u,
              String(c).toLowerCase(),
              String(P)
            ));
          case "delete":
          case "has":
          case "getAll":
            return (c) => (Kt(c), URLSearchParams.prototype[l].call(
              u,
              String(c).toLowerCase()
            ));
          case "keys":
            return () => (u.sort(), new Set(URLSearchParams.prototype.keys.call(u)).keys());
          default:
            return Reflect.get(u, l, h);
        }
      }
    });
  }
  get [Symbol.toStringTag]() {
    return this.constructor.name;
  }
  toString() {
    return Object.prototype.toString.call(this);
  }
  get(n) {
    const a = this.getAll(n);
    if (a.length === 0)
      return null;
    let u = a.join(", ");
    return /^content-encoding$/i.test(n) && (u = u.toLowerCase()), u;
  }
  forEach(n, a = void 0) {
    for (const u of this.keys())
      Reflect.apply(n, a, [this.get(u), u, this]);
  }
  *values() {
    for (const n of this.keys())
      yield this.get(n);
  }
  /**
   * @type {() => IterableIterator<[string, string]>}
   */
  *entries() {
    for (const n of this.keys())
      yield [n, this.get(n)];
  }
  [Symbol.iterator]() {
    return this.entries();
  }
  /**
   * Node-fetch non-spec method
   * returning all headers and their values as array
   * @returns {Record<string, string[]>}
   */
  raw() {
    return [...this.keys()].reduce((n, a) => (n[a] = this.getAll(a), n), {});
  }
  /**
   * For better console.log(headers) and also to convert Headers into Node.js Request compatible format
   */
  [Symbol.for("nodejs.util.inspect.custom")]() {
    return [...this.keys()].reduce((n, a) => {
      const u = this.getAll(a);
      return a === "host" ? n[a] = u[0] : n[a] = u.length > 1 ? u : u[0], n;
    }, {});
  }
}
Object.defineProperties(
  ye.prototype,
  ["get", "entries", "forEach", "values"].reduce((i, n) => (i[n] = { enumerable: !0 }, i), {})
);
function Gi(i = []) {
  return new ye(
    i.reduce((n, a, u, l) => (u % 2 === 0 && n.push(l.slice(u, u + 2)), n), []).filter(([n, a]) => {
      try {
        return Kt(n), Jr(n, String(a)), !0;
      } catch {
        return !1;
      }
    })
  );
}
const Zi = /* @__PURE__ */ new Set([301, 302, 303, 307, 308]), zo = (i) => Zi.has(i), te = Symbol("Response internals");
class V extends bt {
  constructor(n = null, a = {}) {
    super(n, a);
    const u = a.status != null ? a.status : 200, l = new ye(a.headers);
    if (n !== null && !l.has("Content-Type")) {
      const h = Io(n, this);
      h && l.append("Content-Type", h);
    }
    this[te] = {
      type: "default",
      url: a.url,
      status: u,
      statusText: a.statusText || "",
      headers: l,
      counter: a.counter,
      highWaterMark: a.highWaterMark
    };
  }
  get type() {
    return this[te].type;
  }
  get url() {
    return this[te].url || "";
  }
  get status() {
    return this[te].status;
  }
  /**
   * Convenience property representing if the request ended normally
   */
  get ok() {
    return this[te].status >= 200 && this[te].status < 300;
  }
  get redirected() {
    return this[te].counter > 0;
  }
  get statusText() {
    return this[te].statusText;
  }
  get headers() {
    return this[te].headers;
  }
  get highWaterMark() {
    return this[te].highWaterMark;
  }
  /**
   * Clone this response
   *
   * @return  Response
   */
  clone() {
    return new V(Xr(this, this.highWaterMark), {
      type: this.type,
      url: this.url,
      status: this.status,
      statusText: this.statusText,
      headers: this.headers,
      ok: this.ok,
      redirected: this.redirected,
      size: this.size,
      highWaterMark: this.highWaterMark
    });
  }
  /**
   * @param {string} url    The URL that the new response is to originate from.
   * @param {number} status An optional status code for the response (e.g., 302.)
   * @returns {Response}    A Response object.
   */
  static redirect(n, a = 302) {
    if (!zo(a))
      throw new RangeError('Failed to execute "redirect" on "response": Invalid status code');
    return new V(null, {
      headers: {
        location: new URL(n).toString()
      },
      status: a
    });
  }
  static error() {
    const n = new V(null, { status: 0, statusText: "" });
    return n[te].type = "error", n;
  }
  static json(n = void 0, a = {}) {
    const u = JSON.stringify(n);
    if (u === void 0)
      throw new TypeError("data is not JSON serializable");
    const l = new ye(a && a.headers);
    return l.has("content-type") || l.set("content-type", "application/json"), new V(u, {
      ...a,
      headers: l
    });
  }
  get [Symbol.toStringTag]() {
    return "Response";
  }
}
Object.defineProperties(V.prototype, {
  type: { enumerable: !0 },
  url: { enumerable: !0 },
  status: { enumerable: !0 },
  ok: { enumerable: !0 },
  redirected: { enumerable: !0 },
  statusText: { enumerable: !0 },
  headers: { enumerable: !0 },
  clone: { enumerable: !0 }
});
const Ki = (i) => {
  if (i.search)
    return i.search;
  const n = i.href.length - 1, a = i.hash || (i.href[n] === "#" ? "#" : "");
  return i.href[n - a.length] === "?" ? "?" : "";
};
function Ao(i, n = !1) {
  return i == null || (i = new URL(i), /^(about|blob|data):$/.test(i.protocol)) ? "no-referrer" : (i.username = "", i.password = "", i.hash = "", n && (i.pathname = "", i.search = ""), i);
}
const Fo = /* @__PURE__ */ new Set([
  "",
  "no-referrer",
  "no-referrer-when-downgrade",
  "same-origin",
  "origin",
  "strict-origin",
  "origin-when-cross-origin",
  "strict-origin-when-cross-origin",
  "unsafe-url"
]), Ji = "strict-origin-when-cross-origin";
function Xi(i) {
  if (!Fo.has(i))
    throw new TypeError(`Invalid referrerPolicy: ${i}`);
  return i;
}
function es(i) {
  if (/^(http|ws)s:$/.test(i.protocol))
    return !0;
  const n = i.host.replace(/(^\[)|(]$)/g, ""), a = Wi(n);
  return a === 4 && /^127\./.test(n) || a === 6 && /^(((0+:){7})|(::(0+:){0,6}))0*1$/.test(n) ? !0 : i.host === "localhost" || i.host.endsWith(".localhost") ? !1 : i.protocol === "file:";
}
function Xe(i) {
  return /^about:(blank|srcdoc)$/.test(i) || i.protocol === "data:" || /^(blob|filesystem):$/.test(i.protocol) ? !0 : es(i);
}
function ts(i, { referrerURLCallback: n, referrerOriginCallback: a } = {}) {
  if (i.referrer === "no-referrer" || i.referrerPolicy === "")
    return null;
  const u = i.referrerPolicy;
  if (i.referrer === "about:client")
    return "no-referrer";
  const l = i.referrer;
  let h = Ao(l), c = Ao(l, !0);
  h.toString().length > 4096 && (h = c), n && (h = n(h)), a && (c = a(c));
  const P = new URL(i.url);
  switch (u) {
    case "no-referrer":
      return "no-referrer";
    case "origin":
      return c;
    case "unsafe-url":
      return h;
    case "strict-origin":
      return Xe(h) && !Xe(P) ? "no-referrer" : c.toString();
    case "strict-origin-when-cross-origin":
      return h.origin === P.origin ? h : Xe(h) && !Xe(P) ? "no-referrer" : c;
    case "same-origin":
      return h.origin === P.origin ? h : "no-referrer";
    case "origin-when-cross-origin":
      return h.origin === P.origin ? h : c;
    case "no-referrer-when-downgrade":
      return Xe(h) && !Xe(P) ? "no-referrer" : h;
    default:
      throw new TypeError(`Invalid referrerPolicy: ${u}`);
  }
}
function rs(i) {
  const n = (i.get("referrer-policy") || "").split(/[,\s]+/);
  let a = "";
  for (const u of n)
    u && Fo.has(u) && (a = u);
  return a;
}
const F = Symbol("Request internals"), dt = (i) => typeof i == "object" && typeof i[F] == "object", ns = or(
  () => {
  },
  ".data is not a valid RequestInit property, use .body instead",
  "https://github.com/node-fetch/node-fetch/issues/1000 (request)"
);
class pt extends bt {
  constructor(n, a = {}) {
    let u;
    if (dt(n) ? u = new URL(n.url) : (u = new URL(n), n = {}), u.username !== "" || u.password !== "")
      throw new TypeError(`${u} is an url with embedded credentials.`);
    let l = a.method || n.method || "GET";
    if (/^(delete|get|head|options|post|put)$/i.test(l) && (l = l.toUpperCase()), !dt(a) && "data" in a && ns(), (a.body != null || dt(n) && n.body !== null) && (l === "GET" || l === "HEAD"))
      throw new TypeError("Request with GET/HEAD method cannot have body");
    const h = a.body ? a.body : dt(n) && n.body !== null ? Xr(n) : null;
    super(h, {
      size: a.size || n.size || 0
    });
    const c = new ye(a.headers || n.headers || {});
    if (h !== null && !c.has("Content-Type")) {
      const S = Io(h, this);
      S && c.set("Content-Type", S);
    }
    let P = dt(n) ? n.signal : null;
    if ("signal" in a && (P = a.signal), P != null && !Ui(P))
      throw new TypeError("Expected signal to be an instanceof AbortSignal or EventTarget");
    let v = a.referrer == null ? n.referrer : a.referrer;
    if (v === "")
      v = "no-referrer";
    else if (v) {
      const S = new URL(v);
      v = /^about:(\/\/)?client$/.test(S) ? "client" : S;
    } else
      v = void 0;
    this[F] = {
      method: l,
      redirect: a.redirect || n.redirect || "follow",
      headers: c,
      parsedURL: u,
      signal: P,
      referrer: v
    }, this.follow = a.follow === void 0 ? n.follow === void 0 ? 20 : n.follow : a.follow, this.compress = a.compress === void 0 ? n.compress === void 0 ? !0 : n.compress : a.compress, this.counter = a.counter || n.counter || 0, this.agent = a.agent || n.agent, this.highWaterMark = a.highWaterMark || n.highWaterMark || 16384, this.insecureHTTPParser = a.insecureHTTPParser || n.insecureHTTPParser || !1, this.referrerPolicy = a.referrerPolicy || n.referrerPolicy || "";
  }
  /** @returns {string} */
  get method() {
    return this[F].method;
  }
  /** @returns {string} */
  get url() {
    return Bi(this[F].parsedURL);
  }
  /** @returns {Headers} */
  get headers() {
    return this[F].headers;
  }
  get redirect() {
    return this[F].redirect;
  }
  /** @returns {AbortSignal} */
  get signal() {
    return this[F].signal;
  }
  // https://fetch.spec.whatwg.org/#dom-request-referrer
  get referrer() {
    if (this[F].referrer === "no-referrer")
      return "";
    if (this[F].referrer === "client")
      return "about:client";
    if (this[F].referrer)
      return this[F].referrer.toString();
  }
  get referrerPolicy() {
    return this[F].referrerPolicy;
  }
  set referrerPolicy(n) {
    this[F].referrerPolicy = Xi(n);
  }
  /**
   * Clone this request
   *
   * @return  Request
   */
  clone() {
    return new pt(this);
  }
  get [Symbol.toStringTag]() {
    return "Request";
  }
}
Object.defineProperties(pt.prototype, {
  method: { enumerable: !0 },
  url: { enumerable: !0 },
  headers: { enumerable: !0 },
  redirect: { enumerable: !0 },
  clone: { enumerable: !0 },
  signal: { enumerable: !0 },
  referrer: { enumerable: !0 },
  referrerPolicy: { enumerable: !0 }
});
const os = (i) => {
  const { parsedURL: n } = i[F], a = new ye(i[F].headers);
  a.has("Accept") || a.set("Accept", "*/*");
  let u = null;
  if (i.body === null && /^(post|put)$/i.test(i.method) && (u = "0"), i.body !== null) {
    const P = Vi(i);
    typeof P == "number" && !Number.isNaN(P) && (u = String(P));
  }
  u && a.set("Content-Length", u), i.referrerPolicy === "" && (i.referrerPolicy = Ji), i.referrer && i.referrer !== "no-referrer" ? i[F].referrer = ts(i) : i[F].referrer = "no-referrer", i[F].referrer instanceof URL && a.set("Referer", i.referrer), a.has("User-Agent") || a.set("User-Agent", "node-fetch"), i.compress && !a.has("Accept-Encoding") && a.set("Accept-Encoding", "gzip, deflate, br");
  let { agent: l } = i;
  typeof l == "function" && (l = l(n));
  const h = Ki(n), c = {
    // Overwrite search to retain trailing ? (issue #776)
    path: n.pathname + h,
    // The following options are not expressed in the URL
    method: i.method,
    headers: a[Symbol.for("nodejs.util.inspect.custom")](),
    insecureHTTPParser: i.insecureHTTPParser,
    agent: l
  };
  return {
    /** @type {URL} */
    parsedURL: n,
    options: c
  };
};
class as extends ar {
  constructor(n, a = "aborted") {
    super(n, a);
  }
}
/*! node-domexception. MIT License. Jimmy Wärting <https://jimmy.warting.se/opensource> */
var Zr, Bo;
function is() {
  if (Bo) return Zr;
  if (Bo = 1, !globalThis.DOMException)
    try {
      const { MessageChannel: i } = require("worker_threads"), n = new i().port1, a = new ArrayBuffer();
      n.postMessage(a, [a, a]);
    } catch (i) {
      i.constructor.name === "DOMException" && (globalThis.DOMException = i.constructor);
    }
  return Zr = globalThis.DOMException, Zr;
}
is();
const { stat: Ts } = qi, ss = /* @__PURE__ */ new Set(["data:", "http:", "https:"]);
async function ls(i, n) {
  return new Promise((a, u) => {
    const l = new pt(i, n), { parsedURL: h, options: c } = os(l);
    if (!ss.has(h.protocol))
      throw new TypeError(`node-fetch cannot load ${i}. URL scheme "${h.protocol.replace(/:$/, "")}" is not supported.`);
    if (h.protocol === "data:") {
      const y = ki(l.url), x = new V(y, { headers: { "Content-Type": y.typeFull } });
      a(x);
      return;
    }
    const P = (h.protocol === "https:" ? vi : mt).request, { signal: v } = l;
    let S = null;
    const E = () => {
      const y = new as("The operation was aborted.");
      u(y), l.body && l.body instanceof ie.Readable && l.body.destroy(y), !(!S || !S.body) && S.body.emit("error", y);
    };
    if (v && v.aborted) {
      E();
      return;
    }
    const w = () => {
      E(), W();
    }, m = P(h.toString(), c);
    v && v.addEventListener("abort", w);
    const W = () => {
      m.abort(), v && v.removeEventListener("abort", w);
    };
    m.on("error", (y) => {
      u(new ae(`request to ${l.url} failed, reason: ${y.message}`, "system", y)), W();
    }), us(m, (y) => {
      S && S.body && S.body.destroy(y);
    }), process.version < "v14" && m.on("socket", (y) => {
      let x;
      y.prependListener("end", () => {
        x = y._eventsCount;
      }), y.prependListener("close", (k) => {
        if (S && x < y._eventsCount && !k) {
          const O = new Error("Premature close");
          O.code = "ERR_STREAM_PREMATURE_CLOSE", S.body.emit("error", O);
        }
      });
    }), m.on("response", (y) => {
      m.setTimeout(0);
      const x = Gi(y.rawHeaders);
      if (zo(y.statusCode)) {
        const q = x.get("Location");
        let I = null;
        try {
          I = q === null ? null : new URL(q, l.url);
        } catch {
          if (l.redirect !== "manual") {
            u(new ae(`uri requested responds with an invalid redirect URL: ${q}`, "invalid-redirect")), W();
            return;
          }
        }
        switch (l.redirect) {
          case "error":
            u(new ae(`uri requested responds with a redirect, redirect mode is set to error: ${l.url}`, "no-redirect")), W();
            return;
          case "manual":
            break;
          case "follow": {
            if (I === null)
              break;
            if (l.counter >= l.follow) {
              u(new ae(`maximum redirect reached at: ${l.url}`, "max-redirect")), W();
              return;
            }
            const j = {
              headers: new ye(l.headers),
              follow: l.follow,
              counter: l.counter + 1,
              agent: l.agent,
              compress: l.compress,
              method: l.method,
              body: Xr(l),
              signal: l.signal,
              size: l.size,
              referrer: l.referrer,
              referrerPolicy: l.referrerPolicy
            };
            if (!Ni(l.url, I) || !xi(l.url, I))
              for (const St of ["authorization", "www-authenticate", "cookie", "cookie2"])
                j.headers.delete(St);
            if (y.statusCode !== 303 && l.body && n.body instanceof ie.Readable) {
              u(new ae("Cannot follow redirect with body being a readable stream", "unsupported-redirect")), W();
              return;
            }
            (y.statusCode === 303 || (y.statusCode === 301 || y.statusCode === 302) && l.method === "POST") && (j.method = "GET", j.body = void 0, j.headers.delete("content-length"));
            const $ = rs(x);
            $ && (j.referrerPolicy = $), a(ls(new pt(I, j))), W();
            return;
          }
          default:
            return u(new TypeError(`Redirect option '${l.redirect}' is not a valid value of RequestRedirect`));
        }
      }
      v && y.once("end", () => {
        v.removeEventListener("abort", w);
      });
      let k = Je(y, new Jt(), (q) => {
        q && u(q);
      });
      process.version < "v12.10" && y.on("aborted", w);
      const O = {
        url: l.url,
        status: y.statusCode,
        statusText: y.statusMessage,
        headers: x,
        size: l.size,
        counter: l.counter,
        highWaterMark: l.highWaterMark
      }, H = x.get("Content-Encoding");
      if (!l.compress || l.method === "HEAD" || H === null || y.statusCode === 204 || y.statusCode === 304) {
        S = new V(k, O), a(S);
        return;
      }
      const se = {
        flush: Ke.Z_SYNC_FLUSH,
        finishFlush: Ke.Z_SYNC_FLUSH
      };
      if (H === "gzip" || H === "x-gzip") {
        k = Je(k, Ke.createGunzip(se), (q) => {
          q && u(q);
        }), S = new V(k, O), a(S);
        return;
      }
      if (H === "deflate" || H === "x-deflate") {
        const q = Je(y, new Jt(), (I) => {
          I && u(I);
        });
        q.once("data", (I) => {
          (I[0] & 15) === 8 ? k = Je(k, Ke.createInflate(), (j) => {
            j && u(j);
          }) : k = Je(k, Ke.createInflateRaw(), (j) => {
            j && u(j);
          }), S = new V(k, O), a(S);
        }), q.once("end", () => {
          S || (S = new V(k, O), a(S));
        });
        return;
      }
      if (H === "br") {
        k = Je(k, Ke.createBrotliDecompress(), (q) => {
          q && u(q);
        }), S = new V(k, O), a(S);
        return;
      }
      S = new V(k, O), a(S);
    }), Yi(m, l).catch(u);
  });
}
function us(i, n) {
  const a = D.from(`0\r
\r
`);
  let u = !1, l = !1, h;
  i.on("response", (c) => {
    const { headers: P } = c;
    u = P["transfer-encoding"] === "chunked" && !P["content-length"];
  }), i.on("socket", (c) => {
    const P = () => {
      if (u && !l) {
        const S = new Error("Premature close");
        S.code = "ERR_STREAM_PREMATURE_CLOSE", n(S);
      }
    }, v = (S) => {
      l = D.compare(S.slice(-5), a) === 0, !l && h && (l = D.compare(h.slice(-3), a.slice(0, 3)) === 0 && D.compare(S.slice(-2), a.slice(3)) === 0), h = S;
    };
    c.prependListener("close", P), c.on("data", v), i.on("close", () => {
      c.removeListener("close", P), c.removeListener("data", v);
    });
  });
}
export {
  as as AbortError,
  er as Blob,
  ae as FetchError,
  Li as File,
  Kr as FormData,
  ye as Headers,
  pt as Request,
  V as Response,
  ls as default,
  zo as isRedirect
};
