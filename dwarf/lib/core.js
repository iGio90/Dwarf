(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
module.exports = require("core-js/library/fn/date/now");
},{"core-js/library/fn/date/now":14}],2:[function(require,module,exports){
module.exports = require("core-js/library/fn/json/stringify");
},{"core-js/library/fn/json/stringify":15}],3:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/assign");
},{"core-js/library/fn/object/assign":16}],4:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/define-property");
},{"core-js/library/fn/object/define-property":17}],5:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/get-own-property-names");
},{"core-js/library/fn/object/get-own-property-names":18}],6:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/keys");
},{"core-js/library/fn/object/keys":19}],7:[function(require,module,exports){
module.exports = require("core-js/library/fn/parse-int");
},{"core-js/library/fn/parse-int":20}],8:[function(require,module,exports){
module.exports = require("core-js/library/fn/symbol");
},{"core-js/library/fn/symbol":21}],9:[function(require,module,exports){
module.exports = require("core-js/library/fn/symbol/iterator");
},{"core-js/library/fn/symbol/iterator":22}],10:[function(require,module,exports){
function _classCallCheck(instance, Constructor) {
  if (!(instance instanceof Constructor)) {
    throw new TypeError("Cannot call a class as a function");
  }
}

module.exports = _classCallCheck;
},{}],11:[function(require,module,exports){
var _Object$defineProperty = require("../core-js/object/define-property");

function _defineProperties(target, props) {
  for (var i = 0; i < props.length; i++) {
    var descriptor = props[i];
    descriptor.enumerable = descriptor.enumerable || false;
    descriptor.configurable = true;
    if ("value" in descriptor) descriptor.writable = true;

    _Object$defineProperty(target, descriptor.key, descriptor);
  }
}

function _createClass(Constructor, protoProps, staticProps) {
  if (protoProps) _defineProperties(Constructor.prototype, protoProps);
  if (staticProps) _defineProperties(Constructor, staticProps);
  return Constructor;
}

module.exports = _createClass;
},{"../core-js/object/define-property":4}],12:[function(require,module,exports){
function _interopRequireDefault(obj) {
  return obj && obj.__esModule ? obj : {
    "default": obj
  };
}

module.exports = _interopRequireDefault;
},{}],13:[function(require,module,exports){
var _Symbol$iterator = require("../core-js/symbol/iterator");

var _Symbol = require("../core-js/symbol");

function _typeof2(obj) { if (typeof _Symbol === "function" && typeof _Symbol$iterator === "symbol") { _typeof2 = function _typeof2(obj) { return typeof obj; }; } else { _typeof2 = function _typeof2(obj) { return obj && typeof _Symbol === "function" && obj.constructor === _Symbol && obj !== _Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof2(obj); }

function _typeof(obj) {
  if (typeof _Symbol === "function" && _typeof2(_Symbol$iterator) === "symbol") {
    module.exports = _typeof = function _typeof(obj) {
      return _typeof2(obj);
    };
  } else {
    module.exports = _typeof = function _typeof(obj) {
      return obj && typeof _Symbol === "function" && obj.constructor === _Symbol && obj !== _Symbol.prototype ? "symbol" : _typeof2(obj);
    };
  }

  return _typeof(obj);
}

module.exports = _typeof;
},{"../core-js/symbol":8,"../core-js/symbol/iterator":9}],14:[function(require,module,exports){
require('../../modules/es6.date.now');
module.exports = require('../../modules/_core').Date.now;

},{"../../modules/_core":28,"../../modules/es6.date.now":84}],15:[function(require,module,exports){
var core = require('../../modules/_core');
var $JSON = core.JSON || (core.JSON = { stringify: JSON.stringify });
module.exports = function stringify(it) { // eslint-disable-line no-unused-vars
  return $JSON.stringify.apply($JSON, arguments);
};

},{"../../modules/_core":28}],16:[function(require,module,exports){
require('../../modules/es6.object.assign');
module.exports = require('../../modules/_core').Object.assign;

},{"../../modules/_core":28,"../../modules/es6.object.assign":85}],17:[function(require,module,exports){
require('../../modules/es6.object.define-property');
var $Object = require('../../modules/_core').Object;
module.exports = function defineProperty(it, key, desc) {
  return $Object.defineProperty(it, key, desc);
};

},{"../../modules/_core":28,"../../modules/es6.object.define-property":86}],18:[function(require,module,exports){
require('../../modules/es6.object.get-own-property-names');
var $Object = require('../../modules/_core').Object;
module.exports = function getOwnPropertyNames(it) {
  return $Object.getOwnPropertyNames(it);
};

},{"../../modules/_core":28,"../../modules/es6.object.get-own-property-names":87}],19:[function(require,module,exports){
require('../../modules/es6.object.keys');
module.exports = require('../../modules/_core').Object.keys;

},{"../../modules/_core":28,"../../modules/es6.object.keys":88}],20:[function(require,module,exports){
require('../modules/es6.parse-int');
module.exports = require('../modules/_core').parseInt;

},{"../modules/_core":28,"../modules/es6.parse-int":90}],21:[function(require,module,exports){
require('../../modules/es6.symbol');
require('../../modules/es6.object.to-string');
require('../../modules/es7.symbol.async-iterator');
require('../../modules/es7.symbol.observable');
module.exports = require('../../modules/_core').Symbol;

},{"../../modules/_core":28,"../../modules/es6.object.to-string":89,"../../modules/es6.symbol":92,"../../modules/es7.symbol.async-iterator":93,"../../modules/es7.symbol.observable":94}],22:[function(require,module,exports){
require('../../modules/es6.string.iterator');
require('../../modules/web.dom.iterable');
module.exports = require('../../modules/_wks-ext').f('iterator');

},{"../../modules/_wks-ext":81,"../../modules/es6.string.iterator":91,"../../modules/web.dom.iterable":95}],23:[function(require,module,exports){
module.exports = function (it) {
  if (typeof it != 'function') throw TypeError(it + ' is not a function!');
  return it;
};

},{}],24:[function(require,module,exports){
module.exports = function () { /* empty */ };

},{}],25:[function(require,module,exports){
var isObject = require('./_is-object');
module.exports = function (it) {
  if (!isObject(it)) throw TypeError(it + ' is not an object!');
  return it;
};

},{"./_is-object":44}],26:[function(require,module,exports){
// false -> Array#indexOf
// true  -> Array#includes
var toIObject = require('./_to-iobject');
var toLength = require('./_to-length');
var toAbsoluteIndex = require('./_to-absolute-index');
module.exports = function (IS_INCLUDES) {
  return function ($this, el, fromIndex) {
    var O = toIObject($this);
    var length = toLength(O.length);
    var index = toAbsoluteIndex(fromIndex, length);
    var value;
    // Array#includes uses SameValueZero equality algorithm
    // eslint-disable-next-line no-self-compare
    if (IS_INCLUDES && el != el) while (length > index) {
      value = O[index++];
      // eslint-disable-next-line no-self-compare
      if (value != value) return true;
    // Array#indexOf ignores holes, Array#includes - not
    } else for (;length > index; index++) if (IS_INCLUDES || index in O) {
      if (O[index] === el) return IS_INCLUDES || index || 0;
    } return !IS_INCLUDES && -1;
  };
};

},{"./_to-absolute-index":73,"./_to-iobject":75,"./_to-length":76}],27:[function(require,module,exports){
var toString = {}.toString;

module.exports = function (it) {
  return toString.call(it).slice(8, -1);
};

},{}],28:[function(require,module,exports){
var core = module.exports = { version: '2.6.9' };
if (typeof __e == 'number') __e = core; // eslint-disable-line no-undef

},{}],29:[function(require,module,exports){
// optional / simple context binding
var aFunction = require('./_a-function');
module.exports = function (fn, that, length) {
  aFunction(fn);
  if (that === undefined) return fn;
  switch (length) {
    case 1: return function (a) {
      return fn.call(that, a);
    };
    case 2: return function (a, b) {
      return fn.call(that, a, b);
    };
    case 3: return function (a, b, c) {
      return fn.call(that, a, b, c);
    };
  }
  return function (/* ...args */) {
    return fn.apply(that, arguments);
  };
};

},{"./_a-function":23}],30:[function(require,module,exports){
// 7.2.1 RequireObjectCoercible(argument)
module.exports = function (it) {
  if (it == undefined) throw TypeError("Can't call method on  " + it);
  return it;
};

},{}],31:[function(require,module,exports){
// Thank's IE8 for his funny defineProperty
module.exports = !require('./_fails')(function () {
  return Object.defineProperty({}, 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_fails":36}],32:[function(require,module,exports){
var isObject = require('./_is-object');
var document = require('./_global').document;
// typeof document.createElement is 'object' in old IE
var is = isObject(document) && isObject(document.createElement);
module.exports = function (it) {
  return is ? document.createElement(it) : {};
};

},{"./_global":37,"./_is-object":44}],33:[function(require,module,exports){
// IE 8- don't enum bug keys
module.exports = (
  'constructor,hasOwnProperty,isPrototypeOf,propertyIsEnumerable,toLocaleString,toString,valueOf'
).split(',');

},{}],34:[function(require,module,exports){
// all enumerable object keys, includes symbols
var getKeys = require('./_object-keys');
var gOPS = require('./_object-gops');
var pIE = require('./_object-pie');
module.exports = function (it) {
  var result = getKeys(it);
  var getSymbols = gOPS.f;
  if (getSymbols) {
    var symbols = getSymbols(it);
    var isEnum = pIE.f;
    var i = 0;
    var key;
    while (symbols.length > i) if (isEnum.call(it, key = symbols[i++])) result.push(key);
  } return result;
};

},{"./_object-gops":58,"./_object-keys":61,"./_object-pie":62}],35:[function(require,module,exports){
var global = require('./_global');
var core = require('./_core');
var ctx = require('./_ctx');
var hide = require('./_hide');
var has = require('./_has');
var PROTOTYPE = 'prototype';

var $export = function (type, name, source) {
  var IS_FORCED = type & $export.F;
  var IS_GLOBAL = type & $export.G;
  var IS_STATIC = type & $export.S;
  var IS_PROTO = type & $export.P;
  var IS_BIND = type & $export.B;
  var IS_WRAP = type & $export.W;
  var exports = IS_GLOBAL ? core : core[name] || (core[name] = {});
  var expProto = exports[PROTOTYPE];
  var target = IS_GLOBAL ? global : IS_STATIC ? global[name] : (global[name] || {})[PROTOTYPE];
  var key, own, out;
  if (IS_GLOBAL) source = name;
  for (key in source) {
    // contains in native
    own = !IS_FORCED && target && target[key] !== undefined;
    if (own && has(exports, key)) continue;
    // export native or passed
    out = own ? target[key] : source[key];
    // prevent global pollution for namespaces
    exports[key] = IS_GLOBAL && typeof target[key] != 'function' ? source[key]
    // bind timers to global for call from export context
    : IS_BIND && own ? ctx(out, global)
    // wrap global constructors for prevent change them in library
    : IS_WRAP && target[key] == out ? (function (C) {
      var F = function (a, b, c) {
        if (this instanceof C) {
          switch (arguments.length) {
            case 0: return new C();
            case 1: return new C(a);
            case 2: return new C(a, b);
          } return new C(a, b, c);
        } return C.apply(this, arguments);
      };
      F[PROTOTYPE] = C[PROTOTYPE];
      return F;
    // make static versions for prototype methods
    })(out) : IS_PROTO && typeof out == 'function' ? ctx(Function.call, out) : out;
    // export proto methods to core.%CONSTRUCTOR%.methods.%NAME%
    if (IS_PROTO) {
      (exports.virtual || (exports.virtual = {}))[key] = out;
      // export proto methods to core.%CONSTRUCTOR%.prototype.%NAME%
      if (type & $export.R && expProto && !expProto[key]) hide(expProto, key, out);
    }
  }
};
// type bitmap
$export.F = 1;   // forced
$export.G = 2;   // global
$export.S = 4;   // static
$export.P = 8;   // proto
$export.B = 16;  // bind
$export.W = 32;  // wrap
$export.U = 64;  // safe
$export.R = 128; // real proto method for `library`
module.exports = $export;

},{"./_core":28,"./_ctx":29,"./_global":37,"./_has":38,"./_hide":39}],36:[function(require,module,exports){
module.exports = function (exec) {
  try {
    return !!exec();
  } catch (e) {
    return true;
  }
};

},{}],37:[function(require,module,exports){
// https://github.com/zloirock/core-js/issues/86#issuecomment-115759028
var global = module.exports = typeof window != 'undefined' && window.Math == Math
  ? window : typeof self != 'undefined' && self.Math == Math ? self
  // eslint-disable-next-line no-new-func
  : Function('return this')();
if (typeof __g == 'number') __g = global; // eslint-disable-line no-undef

},{}],38:[function(require,module,exports){
var hasOwnProperty = {}.hasOwnProperty;
module.exports = function (it, key) {
  return hasOwnProperty.call(it, key);
};

},{}],39:[function(require,module,exports){
var dP = require('./_object-dp');
var createDesc = require('./_property-desc');
module.exports = require('./_descriptors') ? function (object, key, value) {
  return dP.f(object, key, createDesc(1, value));
} : function (object, key, value) {
  object[key] = value;
  return object;
};

},{"./_descriptors":31,"./_object-dp":53,"./_property-desc":65}],40:[function(require,module,exports){
var document = require('./_global').document;
module.exports = document && document.documentElement;

},{"./_global":37}],41:[function(require,module,exports){
module.exports = !require('./_descriptors') && !require('./_fails')(function () {
  return Object.defineProperty(require('./_dom-create')('div'), 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_descriptors":31,"./_dom-create":32,"./_fails":36}],42:[function(require,module,exports){
// fallback for non-array-like ES3 and non-enumerable old V8 strings
var cof = require('./_cof');
// eslint-disable-next-line no-prototype-builtins
module.exports = Object('z').propertyIsEnumerable(0) ? Object : function (it) {
  return cof(it) == 'String' ? it.split('') : Object(it);
};

},{"./_cof":27}],43:[function(require,module,exports){
// 7.2.2 IsArray(argument)
var cof = require('./_cof');
module.exports = Array.isArray || function isArray(arg) {
  return cof(arg) == 'Array';
};

},{"./_cof":27}],44:[function(require,module,exports){
module.exports = function (it) {
  return typeof it === 'object' ? it !== null : typeof it === 'function';
};

},{}],45:[function(require,module,exports){
'use strict';
var create = require('./_object-create');
var descriptor = require('./_property-desc');
var setToStringTag = require('./_set-to-string-tag');
var IteratorPrototype = {};

// 25.1.2.1.1 %IteratorPrototype%[@@iterator]()
require('./_hide')(IteratorPrototype, require('./_wks')('iterator'), function () { return this; });

module.exports = function (Constructor, NAME, next) {
  Constructor.prototype = create(IteratorPrototype, { next: descriptor(1, next) });
  setToStringTag(Constructor, NAME + ' Iterator');
};

},{"./_hide":39,"./_object-create":52,"./_property-desc":65,"./_set-to-string-tag":67,"./_wks":82}],46:[function(require,module,exports){
'use strict';
var LIBRARY = require('./_library');
var $export = require('./_export');
var redefine = require('./_redefine');
var hide = require('./_hide');
var Iterators = require('./_iterators');
var $iterCreate = require('./_iter-create');
var setToStringTag = require('./_set-to-string-tag');
var getPrototypeOf = require('./_object-gpo');
var ITERATOR = require('./_wks')('iterator');
var BUGGY = !([].keys && 'next' in [].keys()); // Safari has buggy iterators w/o `next`
var FF_ITERATOR = '@@iterator';
var KEYS = 'keys';
var VALUES = 'values';

var returnThis = function () { return this; };

module.exports = function (Base, NAME, Constructor, next, DEFAULT, IS_SET, FORCED) {
  $iterCreate(Constructor, NAME, next);
  var getMethod = function (kind) {
    if (!BUGGY && kind in proto) return proto[kind];
    switch (kind) {
      case KEYS: return function keys() { return new Constructor(this, kind); };
      case VALUES: return function values() { return new Constructor(this, kind); };
    } return function entries() { return new Constructor(this, kind); };
  };
  var TAG = NAME + ' Iterator';
  var DEF_VALUES = DEFAULT == VALUES;
  var VALUES_BUG = false;
  var proto = Base.prototype;
  var $native = proto[ITERATOR] || proto[FF_ITERATOR] || DEFAULT && proto[DEFAULT];
  var $default = $native || getMethod(DEFAULT);
  var $entries = DEFAULT ? !DEF_VALUES ? $default : getMethod('entries') : undefined;
  var $anyNative = NAME == 'Array' ? proto.entries || $native : $native;
  var methods, key, IteratorPrototype;
  // Fix native
  if ($anyNative) {
    IteratorPrototype = getPrototypeOf($anyNative.call(new Base()));
    if (IteratorPrototype !== Object.prototype && IteratorPrototype.next) {
      // Set @@toStringTag to native iterators
      setToStringTag(IteratorPrototype, TAG, true);
      // fix for some old engines
      if (!LIBRARY && typeof IteratorPrototype[ITERATOR] != 'function') hide(IteratorPrototype, ITERATOR, returnThis);
    }
  }
  // fix Array#{values, @@iterator}.name in V8 / FF
  if (DEF_VALUES && $native && $native.name !== VALUES) {
    VALUES_BUG = true;
    $default = function values() { return $native.call(this); };
  }
  // Define iterator
  if ((!LIBRARY || FORCED) && (BUGGY || VALUES_BUG || !proto[ITERATOR])) {
    hide(proto, ITERATOR, $default);
  }
  // Plug for library
  Iterators[NAME] = $default;
  Iterators[TAG] = returnThis;
  if (DEFAULT) {
    methods = {
      values: DEF_VALUES ? $default : getMethod(VALUES),
      keys: IS_SET ? $default : getMethod(KEYS),
      entries: $entries
    };
    if (FORCED) for (key in methods) {
      if (!(key in proto)) redefine(proto, key, methods[key]);
    } else $export($export.P + $export.F * (BUGGY || VALUES_BUG), NAME, methods);
  }
  return methods;
};

},{"./_export":35,"./_hide":39,"./_iter-create":45,"./_iterators":48,"./_library":49,"./_object-gpo":59,"./_redefine":66,"./_set-to-string-tag":67,"./_wks":82}],47:[function(require,module,exports){
module.exports = function (done, value) {
  return { value: value, done: !!done };
};

},{}],48:[function(require,module,exports){
module.exports = {};

},{}],49:[function(require,module,exports){
module.exports = true;

},{}],50:[function(require,module,exports){
var META = require('./_uid')('meta');
var isObject = require('./_is-object');
var has = require('./_has');
var setDesc = require('./_object-dp').f;
var id = 0;
var isExtensible = Object.isExtensible || function () {
  return true;
};
var FREEZE = !require('./_fails')(function () {
  return isExtensible(Object.preventExtensions({}));
});
var setMeta = function (it) {
  setDesc(it, META, { value: {
    i: 'O' + ++id, // object ID
    w: {}          // weak collections IDs
  } });
};
var fastKey = function (it, create) {
  // return primitive with prefix
  if (!isObject(it)) return typeof it == 'symbol' ? it : (typeof it == 'string' ? 'S' : 'P') + it;
  if (!has(it, META)) {
    // can't set metadata to uncaught frozen object
    if (!isExtensible(it)) return 'F';
    // not necessary to add metadata
    if (!create) return 'E';
    // add missing metadata
    setMeta(it);
  // return object ID
  } return it[META].i;
};
var getWeak = function (it, create) {
  if (!has(it, META)) {
    // can't set metadata to uncaught frozen object
    if (!isExtensible(it)) return true;
    // not necessary to add metadata
    if (!create) return false;
    // add missing metadata
    setMeta(it);
  // return hash weak collections IDs
  } return it[META].w;
};
// add metadata on freeze-family methods calling
var onFreeze = function (it) {
  if (FREEZE && meta.NEED && isExtensible(it) && !has(it, META)) setMeta(it);
  return it;
};
var meta = module.exports = {
  KEY: META,
  NEED: false,
  fastKey: fastKey,
  getWeak: getWeak,
  onFreeze: onFreeze
};

},{"./_fails":36,"./_has":38,"./_is-object":44,"./_object-dp":53,"./_uid":79}],51:[function(require,module,exports){
'use strict';
// 19.1.2.1 Object.assign(target, source, ...)
var DESCRIPTORS = require('./_descriptors');
var getKeys = require('./_object-keys');
var gOPS = require('./_object-gops');
var pIE = require('./_object-pie');
var toObject = require('./_to-object');
var IObject = require('./_iobject');
var $assign = Object.assign;

// should work with symbols and should have deterministic property order (V8 bug)
module.exports = !$assign || require('./_fails')(function () {
  var A = {};
  var B = {};
  // eslint-disable-next-line no-undef
  var S = Symbol();
  var K = 'abcdefghijklmnopqrst';
  A[S] = 7;
  K.split('').forEach(function (k) { B[k] = k; });
  return $assign({}, A)[S] != 7 || Object.keys($assign({}, B)).join('') != K;
}) ? function assign(target, source) { // eslint-disable-line no-unused-vars
  var T = toObject(target);
  var aLen = arguments.length;
  var index = 1;
  var getSymbols = gOPS.f;
  var isEnum = pIE.f;
  while (aLen > index) {
    var S = IObject(arguments[index++]);
    var keys = getSymbols ? getKeys(S).concat(getSymbols(S)) : getKeys(S);
    var length = keys.length;
    var j = 0;
    var key;
    while (length > j) {
      key = keys[j++];
      if (!DESCRIPTORS || isEnum.call(S, key)) T[key] = S[key];
    }
  } return T;
} : $assign;

},{"./_descriptors":31,"./_fails":36,"./_iobject":42,"./_object-gops":58,"./_object-keys":61,"./_object-pie":62,"./_to-object":77}],52:[function(require,module,exports){
// 19.1.2.2 / 15.2.3.5 Object.create(O [, Properties])
var anObject = require('./_an-object');
var dPs = require('./_object-dps');
var enumBugKeys = require('./_enum-bug-keys');
var IE_PROTO = require('./_shared-key')('IE_PROTO');
var Empty = function () { /* empty */ };
var PROTOTYPE = 'prototype';

// Create object with fake `null` prototype: use iframe Object with cleared prototype
var createDict = function () {
  // Thrash, waste and sodomy: IE GC bug
  var iframe = require('./_dom-create')('iframe');
  var i = enumBugKeys.length;
  var lt = '<';
  var gt = '>';
  var iframeDocument;
  iframe.style.display = 'none';
  require('./_html').appendChild(iframe);
  iframe.src = 'javascript:'; // eslint-disable-line no-script-url
  // createDict = iframe.contentWindow.Object;
  // html.removeChild(iframe);
  iframeDocument = iframe.contentWindow.document;
  iframeDocument.open();
  iframeDocument.write(lt + 'script' + gt + 'document.F=Object' + lt + '/script' + gt);
  iframeDocument.close();
  createDict = iframeDocument.F;
  while (i--) delete createDict[PROTOTYPE][enumBugKeys[i]];
  return createDict();
};

module.exports = Object.create || function create(O, Properties) {
  var result;
  if (O !== null) {
    Empty[PROTOTYPE] = anObject(O);
    result = new Empty();
    Empty[PROTOTYPE] = null;
    // add "__proto__" for Object.getPrototypeOf polyfill
    result[IE_PROTO] = O;
  } else result = createDict();
  return Properties === undefined ? result : dPs(result, Properties);
};

},{"./_an-object":25,"./_dom-create":32,"./_enum-bug-keys":33,"./_html":40,"./_object-dps":54,"./_shared-key":68}],53:[function(require,module,exports){
var anObject = require('./_an-object');
var IE8_DOM_DEFINE = require('./_ie8-dom-define');
var toPrimitive = require('./_to-primitive');
var dP = Object.defineProperty;

exports.f = require('./_descriptors') ? Object.defineProperty : function defineProperty(O, P, Attributes) {
  anObject(O);
  P = toPrimitive(P, true);
  anObject(Attributes);
  if (IE8_DOM_DEFINE) try {
    return dP(O, P, Attributes);
  } catch (e) { /* empty */ }
  if ('get' in Attributes || 'set' in Attributes) throw TypeError('Accessors not supported!');
  if ('value' in Attributes) O[P] = Attributes.value;
  return O;
};

},{"./_an-object":25,"./_descriptors":31,"./_ie8-dom-define":41,"./_to-primitive":78}],54:[function(require,module,exports){
var dP = require('./_object-dp');
var anObject = require('./_an-object');
var getKeys = require('./_object-keys');

module.exports = require('./_descriptors') ? Object.defineProperties : function defineProperties(O, Properties) {
  anObject(O);
  var keys = getKeys(Properties);
  var length = keys.length;
  var i = 0;
  var P;
  while (length > i) dP.f(O, P = keys[i++], Properties[P]);
  return O;
};

},{"./_an-object":25,"./_descriptors":31,"./_object-dp":53,"./_object-keys":61}],55:[function(require,module,exports){
var pIE = require('./_object-pie');
var createDesc = require('./_property-desc');
var toIObject = require('./_to-iobject');
var toPrimitive = require('./_to-primitive');
var has = require('./_has');
var IE8_DOM_DEFINE = require('./_ie8-dom-define');
var gOPD = Object.getOwnPropertyDescriptor;

exports.f = require('./_descriptors') ? gOPD : function getOwnPropertyDescriptor(O, P) {
  O = toIObject(O);
  P = toPrimitive(P, true);
  if (IE8_DOM_DEFINE) try {
    return gOPD(O, P);
  } catch (e) { /* empty */ }
  if (has(O, P)) return createDesc(!pIE.f.call(O, P), O[P]);
};

},{"./_descriptors":31,"./_has":38,"./_ie8-dom-define":41,"./_object-pie":62,"./_property-desc":65,"./_to-iobject":75,"./_to-primitive":78}],56:[function(require,module,exports){
// fallback for IE11 buggy Object.getOwnPropertyNames with iframe and window
var toIObject = require('./_to-iobject');
var gOPN = require('./_object-gopn').f;
var toString = {}.toString;

var windowNames = typeof window == 'object' && window && Object.getOwnPropertyNames
  ? Object.getOwnPropertyNames(window) : [];

var getWindowNames = function (it) {
  try {
    return gOPN(it);
  } catch (e) {
    return windowNames.slice();
  }
};

module.exports.f = function getOwnPropertyNames(it) {
  return windowNames && toString.call(it) == '[object Window]' ? getWindowNames(it) : gOPN(toIObject(it));
};

},{"./_object-gopn":57,"./_to-iobject":75}],57:[function(require,module,exports){
// 19.1.2.7 / 15.2.3.4 Object.getOwnPropertyNames(O)
var $keys = require('./_object-keys-internal');
var hiddenKeys = require('./_enum-bug-keys').concat('length', 'prototype');

exports.f = Object.getOwnPropertyNames || function getOwnPropertyNames(O) {
  return $keys(O, hiddenKeys);
};

},{"./_enum-bug-keys":33,"./_object-keys-internal":60}],58:[function(require,module,exports){
exports.f = Object.getOwnPropertySymbols;

},{}],59:[function(require,module,exports){
// 19.1.2.9 / 15.2.3.2 Object.getPrototypeOf(O)
var has = require('./_has');
var toObject = require('./_to-object');
var IE_PROTO = require('./_shared-key')('IE_PROTO');
var ObjectProto = Object.prototype;

module.exports = Object.getPrototypeOf || function (O) {
  O = toObject(O);
  if (has(O, IE_PROTO)) return O[IE_PROTO];
  if (typeof O.constructor == 'function' && O instanceof O.constructor) {
    return O.constructor.prototype;
  } return O instanceof Object ? ObjectProto : null;
};

},{"./_has":38,"./_shared-key":68,"./_to-object":77}],60:[function(require,module,exports){
var has = require('./_has');
var toIObject = require('./_to-iobject');
var arrayIndexOf = require('./_array-includes')(false);
var IE_PROTO = require('./_shared-key')('IE_PROTO');

module.exports = function (object, names) {
  var O = toIObject(object);
  var i = 0;
  var result = [];
  var key;
  for (key in O) if (key != IE_PROTO) has(O, key) && result.push(key);
  // Don't enum bug & hidden keys
  while (names.length > i) if (has(O, key = names[i++])) {
    ~arrayIndexOf(result, key) || result.push(key);
  }
  return result;
};

},{"./_array-includes":26,"./_has":38,"./_shared-key":68,"./_to-iobject":75}],61:[function(require,module,exports){
// 19.1.2.14 / 15.2.3.14 Object.keys(O)
var $keys = require('./_object-keys-internal');
var enumBugKeys = require('./_enum-bug-keys');

module.exports = Object.keys || function keys(O) {
  return $keys(O, enumBugKeys);
};

},{"./_enum-bug-keys":33,"./_object-keys-internal":60}],62:[function(require,module,exports){
exports.f = {}.propertyIsEnumerable;

},{}],63:[function(require,module,exports){
// most Object methods by ES6 should accept primitives
var $export = require('./_export');
var core = require('./_core');
var fails = require('./_fails');
module.exports = function (KEY, exec) {
  var fn = (core.Object || {})[KEY] || Object[KEY];
  var exp = {};
  exp[KEY] = exec(fn);
  $export($export.S + $export.F * fails(function () { fn(1); }), 'Object', exp);
};

},{"./_core":28,"./_export":35,"./_fails":36}],64:[function(require,module,exports){
var $parseInt = require('./_global').parseInt;
var $trim = require('./_string-trim').trim;
var ws = require('./_string-ws');
var hex = /^[-+]?0[xX]/;

module.exports = $parseInt(ws + '08') !== 8 || $parseInt(ws + '0x16') !== 22 ? function parseInt(str, radix) {
  var string = $trim(String(str), 3);
  return $parseInt(string, (radix >>> 0) || (hex.test(string) ? 16 : 10));
} : $parseInt;

},{"./_global":37,"./_string-trim":71,"./_string-ws":72}],65:[function(require,module,exports){
module.exports = function (bitmap, value) {
  return {
    enumerable: !(bitmap & 1),
    configurable: !(bitmap & 2),
    writable: !(bitmap & 4),
    value: value
  };
};

},{}],66:[function(require,module,exports){
module.exports = require('./_hide');

},{"./_hide":39}],67:[function(require,module,exports){
var def = require('./_object-dp').f;
var has = require('./_has');
var TAG = require('./_wks')('toStringTag');

module.exports = function (it, tag, stat) {
  if (it && !has(it = stat ? it : it.prototype, TAG)) def(it, TAG, { configurable: true, value: tag });
};

},{"./_has":38,"./_object-dp":53,"./_wks":82}],68:[function(require,module,exports){
var shared = require('./_shared')('keys');
var uid = require('./_uid');
module.exports = function (key) {
  return shared[key] || (shared[key] = uid(key));
};

},{"./_shared":69,"./_uid":79}],69:[function(require,module,exports){
var core = require('./_core');
var global = require('./_global');
var SHARED = '__core-js_shared__';
var store = global[SHARED] || (global[SHARED] = {});

(module.exports = function (key, value) {
  return store[key] || (store[key] = value !== undefined ? value : {});
})('versions', []).push({
  version: core.version,
  mode: require('./_library') ? 'pure' : 'global',
  copyright: '© 2019 Denis Pushkarev (zloirock.ru)'
});

},{"./_core":28,"./_global":37,"./_library":49}],70:[function(require,module,exports){
var toInteger = require('./_to-integer');
var defined = require('./_defined');
// true  -> String#at
// false -> String#codePointAt
module.exports = function (TO_STRING) {
  return function (that, pos) {
    var s = String(defined(that));
    var i = toInteger(pos);
    var l = s.length;
    var a, b;
    if (i < 0 || i >= l) return TO_STRING ? '' : undefined;
    a = s.charCodeAt(i);
    return a < 0xd800 || a > 0xdbff || i + 1 === l || (b = s.charCodeAt(i + 1)) < 0xdc00 || b > 0xdfff
      ? TO_STRING ? s.charAt(i) : a
      : TO_STRING ? s.slice(i, i + 2) : (a - 0xd800 << 10) + (b - 0xdc00) + 0x10000;
  };
};

},{"./_defined":30,"./_to-integer":74}],71:[function(require,module,exports){
var $export = require('./_export');
var defined = require('./_defined');
var fails = require('./_fails');
var spaces = require('./_string-ws');
var space = '[' + spaces + ']';
var non = '\u200b\u0085';
var ltrim = RegExp('^' + space + space + '*');
var rtrim = RegExp(space + space + '*$');

var exporter = function (KEY, exec, ALIAS) {
  var exp = {};
  var FORCE = fails(function () {
    return !!spaces[KEY]() || non[KEY]() != non;
  });
  var fn = exp[KEY] = FORCE ? exec(trim) : spaces[KEY];
  if (ALIAS) exp[ALIAS] = fn;
  $export($export.P + $export.F * FORCE, 'String', exp);
};

// 1 -> String#trimLeft
// 2 -> String#trimRight
// 3 -> String#trim
var trim = exporter.trim = function (string, TYPE) {
  string = String(defined(string));
  if (TYPE & 1) string = string.replace(ltrim, '');
  if (TYPE & 2) string = string.replace(rtrim, '');
  return string;
};

module.exports = exporter;

},{"./_defined":30,"./_export":35,"./_fails":36,"./_string-ws":72}],72:[function(require,module,exports){
module.exports = '\x09\x0A\x0B\x0C\x0D\x20\xA0\u1680\u180E\u2000\u2001\u2002\u2003' +
  '\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u202F\u205F\u3000\u2028\u2029\uFEFF';

},{}],73:[function(require,module,exports){
var toInteger = require('./_to-integer');
var max = Math.max;
var min = Math.min;
module.exports = function (index, length) {
  index = toInteger(index);
  return index < 0 ? max(index + length, 0) : min(index, length);
};

},{"./_to-integer":74}],74:[function(require,module,exports){
// 7.1.4 ToInteger
var ceil = Math.ceil;
var floor = Math.floor;
module.exports = function (it) {
  return isNaN(it = +it) ? 0 : (it > 0 ? floor : ceil)(it);
};

},{}],75:[function(require,module,exports){
// to indexed object, toObject with fallback for non-array-like ES3 strings
var IObject = require('./_iobject');
var defined = require('./_defined');
module.exports = function (it) {
  return IObject(defined(it));
};

},{"./_defined":30,"./_iobject":42}],76:[function(require,module,exports){
// 7.1.15 ToLength
var toInteger = require('./_to-integer');
var min = Math.min;
module.exports = function (it) {
  return it > 0 ? min(toInteger(it), 0x1fffffffffffff) : 0; // pow(2, 53) - 1 == 9007199254740991
};

},{"./_to-integer":74}],77:[function(require,module,exports){
// 7.1.13 ToObject(argument)
var defined = require('./_defined');
module.exports = function (it) {
  return Object(defined(it));
};

},{"./_defined":30}],78:[function(require,module,exports){
// 7.1.1 ToPrimitive(input [, PreferredType])
var isObject = require('./_is-object');
// instead of the ES6 spec version, we didn't implement @@toPrimitive case
// and the second argument - flag - preferred type is a string
module.exports = function (it, S) {
  if (!isObject(it)) return it;
  var fn, val;
  if (S && typeof (fn = it.toString) == 'function' && !isObject(val = fn.call(it))) return val;
  if (typeof (fn = it.valueOf) == 'function' && !isObject(val = fn.call(it))) return val;
  if (!S && typeof (fn = it.toString) == 'function' && !isObject(val = fn.call(it))) return val;
  throw TypeError("Can't convert object to primitive value");
};

},{"./_is-object":44}],79:[function(require,module,exports){
var id = 0;
var px = Math.random();
module.exports = function (key) {
  return 'Symbol('.concat(key === undefined ? '' : key, ')_', (++id + px).toString(36));
};

},{}],80:[function(require,module,exports){
var global = require('./_global');
var core = require('./_core');
var LIBRARY = require('./_library');
var wksExt = require('./_wks-ext');
var defineProperty = require('./_object-dp').f;
module.exports = function (name) {
  var $Symbol = core.Symbol || (core.Symbol = LIBRARY ? {} : global.Symbol || {});
  if (name.charAt(0) != '_' && !(name in $Symbol)) defineProperty($Symbol, name, { value: wksExt.f(name) });
};

},{"./_core":28,"./_global":37,"./_library":49,"./_object-dp":53,"./_wks-ext":81}],81:[function(require,module,exports){
exports.f = require('./_wks');

},{"./_wks":82}],82:[function(require,module,exports){
var store = require('./_shared')('wks');
var uid = require('./_uid');
var Symbol = require('./_global').Symbol;
var USE_SYMBOL = typeof Symbol == 'function';

var $exports = module.exports = function (name) {
  return store[name] || (store[name] =
    USE_SYMBOL && Symbol[name] || (USE_SYMBOL ? Symbol : uid)('Symbol.' + name));
};

$exports.store = store;

},{"./_global":37,"./_shared":69,"./_uid":79}],83:[function(require,module,exports){
'use strict';
var addToUnscopables = require('./_add-to-unscopables');
var step = require('./_iter-step');
var Iterators = require('./_iterators');
var toIObject = require('./_to-iobject');

// 22.1.3.4 Array.prototype.entries()
// 22.1.3.13 Array.prototype.keys()
// 22.1.3.29 Array.prototype.values()
// 22.1.3.30 Array.prototype[@@iterator]()
module.exports = require('./_iter-define')(Array, 'Array', function (iterated, kind) {
  this._t = toIObject(iterated); // target
  this._i = 0;                   // next index
  this._k = kind;                // kind
// 22.1.5.2.1 %ArrayIteratorPrototype%.next()
}, function () {
  var O = this._t;
  var kind = this._k;
  var index = this._i++;
  if (!O || index >= O.length) {
    this._t = undefined;
    return step(1);
  }
  if (kind == 'keys') return step(0, index);
  if (kind == 'values') return step(0, O[index]);
  return step(0, [index, O[index]]);
}, 'values');

// argumentsList[@@iterator] is %ArrayProto_values% (9.4.4.6, 9.4.4.7)
Iterators.Arguments = Iterators.Array;

addToUnscopables('keys');
addToUnscopables('values');
addToUnscopables('entries');

},{"./_add-to-unscopables":24,"./_iter-define":46,"./_iter-step":47,"./_iterators":48,"./_to-iobject":75}],84:[function(require,module,exports){
// 20.3.3.1 / 15.9.4.4 Date.now()
var $export = require('./_export');

$export($export.S, 'Date', { now: function () { return new Date().getTime(); } });

},{"./_export":35}],85:[function(require,module,exports){
// 19.1.3.1 Object.assign(target, source)
var $export = require('./_export');

$export($export.S + $export.F, 'Object', { assign: require('./_object-assign') });

},{"./_export":35,"./_object-assign":51}],86:[function(require,module,exports){
var $export = require('./_export');
// 19.1.2.4 / 15.2.3.6 Object.defineProperty(O, P, Attributes)
$export($export.S + $export.F * !require('./_descriptors'), 'Object', { defineProperty: require('./_object-dp').f });

},{"./_descriptors":31,"./_export":35,"./_object-dp":53}],87:[function(require,module,exports){
// 19.1.2.7 Object.getOwnPropertyNames(O)
require('./_object-sap')('getOwnPropertyNames', function () {
  return require('./_object-gopn-ext').f;
});

},{"./_object-gopn-ext":56,"./_object-sap":63}],88:[function(require,module,exports){
// 19.1.2.14 Object.keys(O)
var toObject = require('./_to-object');
var $keys = require('./_object-keys');

require('./_object-sap')('keys', function () {
  return function keys(it) {
    return $keys(toObject(it));
  };
});

},{"./_object-keys":61,"./_object-sap":63,"./_to-object":77}],89:[function(require,module,exports){

},{}],90:[function(require,module,exports){
var $export = require('./_export');
var $parseInt = require('./_parse-int');
// 18.2.5 parseInt(string, radix)
$export($export.G + $export.F * (parseInt != $parseInt), { parseInt: $parseInt });

},{"./_export":35,"./_parse-int":64}],91:[function(require,module,exports){
'use strict';
var $at = require('./_string-at')(true);

// 21.1.3.27 String.prototype[@@iterator]()
require('./_iter-define')(String, 'String', function (iterated) {
  this._t = String(iterated); // target
  this._i = 0;                // next index
// 21.1.5.2.1 %StringIteratorPrototype%.next()
}, function () {
  var O = this._t;
  var index = this._i;
  var point;
  if (index >= O.length) return { value: undefined, done: true };
  point = $at(O, index);
  this._i += point.length;
  return { value: point, done: false };
});

},{"./_iter-define":46,"./_string-at":70}],92:[function(require,module,exports){
'use strict';
// ECMAScript 6 symbols shim
var global = require('./_global');
var has = require('./_has');
var DESCRIPTORS = require('./_descriptors');
var $export = require('./_export');
var redefine = require('./_redefine');
var META = require('./_meta').KEY;
var $fails = require('./_fails');
var shared = require('./_shared');
var setToStringTag = require('./_set-to-string-tag');
var uid = require('./_uid');
var wks = require('./_wks');
var wksExt = require('./_wks-ext');
var wksDefine = require('./_wks-define');
var enumKeys = require('./_enum-keys');
var isArray = require('./_is-array');
var anObject = require('./_an-object');
var isObject = require('./_is-object');
var toObject = require('./_to-object');
var toIObject = require('./_to-iobject');
var toPrimitive = require('./_to-primitive');
var createDesc = require('./_property-desc');
var _create = require('./_object-create');
var gOPNExt = require('./_object-gopn-ext');
var $GOPD = require('./_object-gopd');
var $GOPS = require('./_object-gops');
var $DP = require('./_object-dp');
var $keys = require('./_object-keys');
var gOPD = $GOPD.f;
var dP = $DP.f;
var gOPN = gOPNExt.f;
var $Symbol = global.Symbol;
var $JSON = global.JSON;
var _stringify = $JSON && $JSON.stringify;
var PROTOTYPE = 'prototype';
var HIDDEN = wks('_hidden');
var TO_PRIMITIVE = wks('toPrimitive');
var isEnum = {}.propertyIsEnumerable;
var SymbolRegistry = shared('symbol-registry');
var AllSymbols = shared('symbols');
var OPSymbols = shared('op-symbols');
var ObjectProto = Object[PROTOTYPE];
var USE_NATIVE = typeof $Symbol == 'function' && !!$GOPS.f;
var QObject = global.QObject;
// Don't use setters in Qt Script, https://github.com/zloirock/core-js/issues/173
var setter = !QObject || !QObject[PROTOTYPE] || !QObject[PROTOTYPE].findChild;

// fallback for old Android, https://code.google.com/p/v8/issues/detail?id=687
var setSymbolDesc = DESCRIPTORS && $fails(function () {
  return _create(dP({}, 'a', {
    get: function () { return dP(this, 'a', { value: 7 }).a; }
  })).a != 7;
}) ? function (it, key, D) {
  var protoDesc = gOPD(ObjectProto, key);
  if (protoDesc) delete ObjectProto[key];
  dP(it, key, D);
  if (protoDesc && it !== ObjectProto) dP(ObjectProto, key, protoDesc);
} : dP;

var wrap = function (tag) {
  var sym = AllSymbols[tag] = _create($Symbol[PROTOTYPE]);
  sym._k = tag;
  return sym;
};

var isSymbol = USE_NATIVE && typeof $Symbol.iterator == 'symbol' ? function (it) {
  return typeof it == 'symbol';
} : function (it) {
  return it instanceof $Symbol;
};

var $defineProperty = function defineProperty(it, key, D) {
  if (it === ObjectProto) $defineProperty(OPSymbols, key, D);
  anObject(it);
  key = toPrimitive(key, true);
  anObject(D);
  if (has(AllSymbols, key)) {
    if (!D.enumerable) {
      if (!has(it, HIDDEN)) dP(it, HIDDEN, createDesc(1, {}));
      it[HIDDEN][key] = true;
    } else {
      if (has(it, HIDDEN) && it[HIDDEN][key]) it[HIDDEN][key] = false;
      D = _create(D, { enumerable: createDesc(0, false) });
    } return setSymbolDesc(it, key, D);
  } return dP(it, key, D);
};
var $defineProperties = function defineProperties(it, P) {
  anObject(it);
  var keys = enumKeys(P = toIObject(P));
  var i = 0;
  var l = keys.length;
  var key;
  while (l > i) $defineProperty(it, key = keys[i++], P[key]);
  return it;
};
var $create = function create(it, P) {
  return P === undefined ? _create(it) : $defineProperties(_create(it), P);
};
var $propertyIsEnumerable = function propertyIsEnumerable(key) {
  var E = isEnum.call(this, key = toPrimitive(key, true));
  if (this === ObjectProto && has(AllSymbols, key) && !has(OPSymbols, key)) return false;
  return E || !has(this, key) || !has(AllSymbols, key) || has(this, HIDDEN) && this[HIDDEN][key] ? E : true;
};
var $getOwnPropertyDescriptor = function getOwnPropertyDescriptor(it, key) {
  it = toIObject(it);
  key = toPrimitive(key, true);
  if (it === ObjectProto && has(AllSymbols, key) && !has(OPSymbols, key)) return;
  var D = gOPD(it, key);
  if (D && has(AllSymbols, key) && !(has(it, HIDDEN) && it[HIDDEN][key])) D.enumerable = true;
  return D;
};
var $getOwnPropertyNames = function getOwnPropertyNames(it) {
  var names = gOPN(toIObject(it));
  var result = [];
  var i = 0;
  var key;
  while (names.length > i) {
    if (!has(AllSymbols, key = names[i++]) && key != HIDDEN && key != META) result.push(key);
  } return result;
};
var $getOwnPropertySymbols = function getOwnPropertySymbols(it) {
  var IS_OP = it === ObjectProto;
  var names = gOPN(IS_OP ? OPSymbols : toIObject(it));
  var result = [];
  var i = 0;
  var key;
  while (names.length > i) {
    if (has(AllSymbols, key = names[i++]) && (IS_OP ? has(ObjectProto, key) : true)) result.push(AllSymbols[key]);
  } return result;
};

// 19.4.1.1 Symbol([description])
if (!USE_NATIVE) {
  $Symbol = function Symbol() {
    if (this instanceof $Symbol) throw TypeError('Symbol is not a constructor!');
    var tag = uid(arguments.length > 0 ? arguments[0] : undefined);
    var $set = function (value) {
      if (this === ObjectProto) $set.call(OPSymbols, value);
      if (has(this, HIDDEN) && has(this[HIDDEN], tag)) this[HIDDEN][tag] = false;
      setSymbolDesc(this, tag, createDesc(1, value));
    };
    if (DESCRIPTORS && setter) setSymbolDesc(ObjectProto, tag, { configurable: true, set: $set });
    return wrap(tag);
  };
  redefine($Symbol[PROTOTYPE], 'toString', function toString() {
    return this._k;
  });

  $GOPD.f = $getOwnPropertyDescriptor;
  $DP.f = $defineProperty;
  require('./_object-gopn').f = gOPNExt.f = $getOwnPropertyNames;
  require('./_object-pie').f = $propertyIsEnumerable;
  $GOPS.f = $getOwnPropertySymbols;

  if (DESCRIPTORS && !require('./_library')) {
    redefine(ObjectProto, 'propertyIsEnumerable', $propertyIsEnumerable, true);
  }

  wksExt.f = function (name) {
    return wrap(wks(name));
  };
}

$export($export.G + $export.W + $export.F * !USE_NATIVE, { Symbol: $Symbol });

for (var es6Symbols = (
  // 19.4.2.2, 19.4.2.3, 19.4.2.4, 19.4.2.6, 19.4.2.8, 19.4.2.9, 19.4.2.10, 19.4.2.11, 19.4.2.12, 19.4.2.13, 19.4.2.14
  'hasInstance,isConcatSpreadable,iterator,match,replace,search,species,split,toPrimitive,toStringTag,unscopables'
).split(','), j = 0; es6Symbols.length > j;)wks(es6Symbols[j++]);

for (var wellKnownSymbols = $keys(wks.store), k = 0; wellKnownSymbols.length > k;) wksDefine(wellKnownSymbols[k++]);

$export($export.S + $export.F * !USE_NATIVE, 'Symbol', {
  // 19.4.2.1 Symbol.for(key)
  'for': function (key) {
    return has(SymbolRegistry, key += '')
      ? SymbolRegistry[key]
      : SymbolRegistry[key] = $Symbol(key);
  },
  // 19.4.2.5 Symbol.keyFor(sym)
  keyFor: function keyFor(sym) {
    if (!isSymbol(sym)) throw TypeError(sym + ' is not a symbol!');
    for (var key in SymbolRegistry) if (SymbolRegistry[key] === sym) return key;
  },
  useSetter: function () { setter = true; },
  useSimple: function () { setter = false; }
});

$export($export.S + $export.F * !USE_NATIVE, 'Object', {
  // 19.1.2.2 Object.create(O [, Properties])
  create: $create,
  // 19.1.2.4 Object.defineProperty(O, P, Attributes)
  defineProperty: $defineProperty,
  // 19.1.2.3 Object.defineProperties(O, Properties)
  defineProperties: $defineProperties,
  // 19.1.2.6 Object.getOwnPropertyDescriptor(O, P)
  getOwnPropertyDescriptor: $getOwnPropertyDescriptor,
  // 19.1.2.7 Object.getOwnPropertyNames(O)
  getOwnPropertyNames: $getOwnPropertyNames,
  // 19.1.2.8 Object.getOwnPropertySymbols(O)
  getOwnPropertySymbols: $getOwnPropertySymbols
});

// Chrome 38 and 39 `Object.getOwnPropertySymbols` fails on primitives
// https://bugs.chromium.org/p/v8/issues/detail?id=3443
var FAILS_ON_PRIMITIVES = $fails(function () { $GOPS.f(1); });

$export($export.S + $export.F * FAILS_ON_PRIMITIVES, 'Object', {
  getOwnPropertySymbols: function getOwnPropertySymbols(it) {
    return $GOPS.f(toObject(it));
  }
});

// 24.3.2 JSON.stringify(value [, replacer [, space]])
$JSON && $export($export.S + $export.F * (!USE_NATIVE || $fails(function () {
  var S = $Symbol();
  // MS Edge converts symbol values to JSON as {}
  // WebKit converts symbol values to JSON as null
  // V8 throws on boxed symbols
  return _stringify([S]) != '[null]' || _stringify({ a: S }) != '{}' || _stringify(Object(S)) != '{}';
})), 'JSON', {
  stringify: function stringify(it) {
    var args = [it];
    var i = 1;
    var replacer, $replacer;
    while (arguments.length > i) args.push(arguments[i++]);
    $replacer = replacer = args[1];
    if (!isObject(replacer) && it === undefined || isSymbol(it)) return; // IE8 returns string on undefined
    if (!isArray(replacer)) replacer = function (key, value) {
      if (typeof $replacer == 'function') value = $replacer.call(this, key, value);
      if (!isSymbol(value)) return value;
    };
    args[1] = replacer;
    return _stringify.apply($JSON, args);
  }
});

// 19.4.3.4 Symbol.prototype[@@toPrimitive](hint)
$Symbol[PROTOTYPE][TO_PRIMITIVE] || require('./_hide')($Symbol[PROTOTYPE], TO_PRIMITIVE, $Symbol[PROTOTYPE].valueOf);
// 19.4.3.5 Symbol.prototype[@@toStringTag]
setToStringTag($Symbol, 'Symbol');
// 20.2.1.9 Math[@@toStringTag]
setToStringTag(Math, 'Math', true);
// 24.3.3 JSON[@@toStringTag]
setToStringTag(global.JSON, 'JSON', true);

},{"./_an-object":25,"./_descriptors":31,"./_enum-keys":34,"./_export":35,"./_fails":36,"./_global":37,"./_has":38,"./_hide":39,"./_is-array":43,"./_is-object":44,"./_library":49,"./_meta":50,"./_object-create":52,"./_object-dp":53,"./_object-gopd":55,"./_object-gopn":57,"./_object-gopn-ext":56,"./_object-gops":58,"./_object-keys":61,"./_object-pie":62,"./_property-desc":65,"./_redefine":66,"./_set-to-string-tag":67,"./_shared":69,"./_to-iobject":75,"./_to-object":77,"./_to-primitive":78,"./_uid":79,"./_wks":82,"./_wks-define":80,"./_wks-ext":81}],93:[function(require,module,exports){
require('./_wks-define')('asyncIterator');

},{"./_wks-define":80}],94:[function(require,module,exports){
require('./_wks-define')('observable');

},{"./_wks-define":80}],95:[function(require,module,exports){
require('./es6.array.iterator');
var global = require('./_global');
var hide = require('./_hide');
var Iterators = require('./_iterators');
var TO_STRING_TAG = require('./_wks')('toStringTag');

var DOMIterables = ('CSSRuleList,CSSStyleDeclaration,CSSValueList,ClientRectList,DOMRectList,DOMStringList,' +
  'DOMTokenList,DataTransferItemList,FileList,HTMLAllCollection,HTMLCollection,HTMLFormElement,HTMLSelectElement,' +
  'MediaList,MimeTypeArray,NamedNodeMap,NodeList,PaintRequestList,Plugin,PluginArray,SVGLengthList,SVGNumberList,' +
  'SVGPathSegList,SVGPointList,SVGStringList,SVGTransformList,SourceBufferList,StyleSheetList,TextTrackCueList,' +
  'TextTrackList,TouchList').split(',');

for (var i = 0; i < DOMIterables.length; i++) {
  var NAME = DOMIterables[i];
  var Collection = global[NAME];
  var proto = Collection && Collection.prototype;
  if (proto && !proto[TO_STRING_TAG]) hide(proto, TO_STRING_TAG, NAME);
  Iterators[NAME] = Iterators.Array;
}

},{"./_global":37,"./_hide":39,"./_iterators":48,"./_wks":82,"./es6.array.iterator":83}],96:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _stringify = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/json/stringify"));

var _typeof2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/typeof"));

var _parseInt2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/parse-int"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var dwarf_1 = require("./dwarf");

var fs_1 = require("./fs");

var logic_breakpoint_1 = require("./logic_breakpoint");

var logic_java_1 = require("./logic_java");

var logic_objc_1 = require("./logic_objc");

var logic_initialization_1 = require("./logic_initialization");

var logic_stalker_1 = require("./logic_stalker");

var logic_watchpoint_1 = require("./logic_watchpoint");

var thread_wrapper_1 = require("./thread_wrapper");

var utils_1 = require("./utils");

var watchpoint_1 = require("./watchpoint");

var Api =
/*#__PURE__*/
function () {
  function Api() {
    (0, _classCallCheck2["default"])(this, Api);
  }

  (0, _createClass2["default"])(Api, null, [{
    key: "_internalMemoryScan",
    value: function _internalMemoryScan(start, size, pattern) {
      if (size > 4096) {
        // scan in chunks of 4096
        var _start = (0, _parseInt2["default"])(start);

        var end = _start + size;
        var result = [];
        var _break = false;

        while (true) {
          var s = 4096;

          if (_start + s > end) {
            s = end - _start;
            _break = true;
          }

          result = result.concat(Memory.scanSync(start, s, pattern));

          if (_break || result.length >= 100) {
            break;
          }

          start = start.add(size);
          _start += s;
        }

        return result;
      } else {
        return Memory.scanSync(start, size, pattern);
      }
    }
  }, {
    key: "backtrace",

    /**
     * Shortcut to retrieve native backtrace
     * @param context: the CpuContext object
     */
    value: function backtrace(context) {
      if (!utils_1.Utils.isDefined(context)) {
        context = dwarf_1.Dwarf.threadContexts[Process.getCurrentThreadId()];

        if (!utils_1.Utils.isDefined(context)) {
          return null;
        }
      }

      return Thread.backtrace(context, Backtracer.FUZZY).map(DebugSymbol.fromAddress);
    }
  }, {
    key: "enumerateExports",

    /**
     * Enumerate exports for the given module name or pointer
     * @param module an hex/int address or string name
     */
    value: function enumerateExports(module) {
      if ((0, _typeof2["default"])(module) !== 'object') {
        module = Api.findModule(module);
      }

      if (module !== null) {
        if (dwarf_1.Dwarf.modulesBlacklist.indexOf(module.name) >= 0) {
          return [];
        }

        return module.enumerateExports();
      }

      return [];
    }
  }, {
    key: "enumerateImports",

    /**
     * Enumerate imports for the given module name or pointer
     * @param module an hex/int address or string name
     */
    value: function enumerateImports(module) {
      if ((0, _typeof2["default"])(module) !== 'object') {
        module = Api.findModule(module);
      }

      if (module !== null) {
        if (dwarf_1.Dwarf.modulesBlacklist.indexOf(module.name) >= 0) {
          return [];
        }

        return module.enumerateImports();
      }

      return [];
    }
  }, {
    key: "enumerateJavaClasses",

    /**
     * Enumerate java classes
     * @param useCache false by default
     */
    value: function enumerateJavaClasses(useCache) {
      if (!utils_1.Utils.isDefined(useCache)) {
        useCache = false;
      }

      if (useCache && logic_java_1.LogicJava !== null && logic_java_1.LogicJava.javaClasses.length > 0) {
        dwarf_1.Dwarf.loggedSend('enumerate_java_classes_start:::');

        for (var i = 0; i < logic_java_1.LogicJava.javaClasses.length; i++) {
          send('enumerate_java_classes_match:::' + logic_java_1.LogicJava.javaClasses[i]);
        }

        dwarf_1.Dwarf.loggedSend('enumerate_java_classes_complete:::');
      } else {
        // invalidate cache
        if (logic_java_1.LogicJava !== null) {
          logic_java_1.LogicJava.javaClasses = [];
        }

        Java.performNow(function () {
          dwarf_1.Dwarf.loggedSend('enumerate_java_classes_start:::');

          try {
            Java.enumerateLoadedClasses({
              onMatch: function onMatch(className) {
                if (logic_java_1.LogicJava !== null) {
                  logic_java_1.LogicJava.javaClasses.push(className);
                }

                send('enumerate_java_classes_match:::' + className);
              },
              onComplete: function onComplete() {
                send('enumerate_java_classes_complete:::');
              }
            });
          } catch (e) {
            utils_1.Utils.logErr('enumerateJavaClasses', e);
            dwarf_1.Dwarf.loggedSend('enumerate_java_classes_complete:::');
          }
        });
      }
    }
  }, {
    key: "enumerateJavaMethods",

    /**
     * Enumerate method for the given class
     */
    value: function enumerateJavaMethods(className) {
      if (Java.available) {
        var that = this;
        Java.performNow(function () {
          // 0xdea code -> https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_android_trace.js
          var clazz = Java.use(className);
          var methods = clazz["class"].getDeclaredMethods();
          clazz.$dispose();
          var parsedMethods = [];
          methods.forEach(function (method) {
            parsedMethods.push(method.toString().replace(className + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
          });
          var result = utils_1.Utils.uniqueBy(parsedMethods);
          dwarf_1.Dwarf.loggedSend('enumerate_java_methods_complete:::' + className + ':::' + (0, _stringify["default"])(result));
        });
      }
    }
  }, {
    key: "enumerateObjCModules",

    /**
     * Enumerate modules for ObjC inspector panel
     */
    value: function enumerateObjCModules(className) {
      var modules = Process.enumerateModules();
      var names = modules.map(function (m) {
        return m.name;
      });
      dwarf_1.Dwarf.loggedSend('enumerate_objc_modules:::' + (0, _stringify["default"])(names));
    }
  }, {
    key: "enumerateObjCClasses",

    /**
     * Enumerate objc classes
     * @param useCache false by default
     */
    value: function enumerateObjCClasses(moduleName) {
      dwarf_1.Dwarf.loggedSend('enumerate_objc_classes_start:::');

      try {
        ObjC.enumerateLoadedClasses({
          ownedBy: new ModuleMap(function (m) {
            return moduleName === m['name'];
          })
        }, {
          onMatch: function onMatch(className) {
            if (logic_objc_1.LogicObjC !== null) {
              logic_objc_1.LogicObjC.objcClasses.push(className);
            }

            send('enumerate_objc_classes_match:::' + className);
          },
          onComplete: function onComplete() {
            send('enumerate_objc_classes_complete:::');
          }
        });
      } catch (e) {
        utils_1.Utils.logErr('enumerateObjCClasses', e);
        dwarf_1.Dwarf.loggedSend('enumerate_objc_classes_complete:::');
      }
    }
  }, {
    key: "enumerateObjCMethods",

    /**
     * Enumerate method for the given class
     */
    value: function enumerateObjCMethods(className) {
      if (ObjC.available) {
        dwarf_1.Dwarf.loggedSend('enumerate_objc_methods_start:::');
        var that = this;
        var clazz = ObjC.classes[className];
        var methods = clazz.$ownMethods;
        methods.forEach(function (method) {
          send('enumerate_objc_methods_match:::' + method);
        });
        dwarf_1.Dwarf.loggedSend('enumerate_objc_methods_complete:::');
      }
    }
  }, {
    key: "enumerateModules",

    /**
     * Enumerate loaded modules
     */
    value: function enumerateModules(fillInformation) {
      fillInformation = fillInformation || false;
      var modules = Process.enumerateModules();

      if (fillInformation) {
        for (var i = 0; i < modules.length; i++) {
          if (dwarf_1.Dwarf.modulesBlacklist.indexOf(modules[i].name) >= 0) {
            continue;
          } // skip ntdll on windoof (access_violation)


          if (Process.platform === 'windows') {
            if (modules[i].name === 'ntdll.dll') {
              continue;
            }
          } else if (Process.platform === 'linux') {
            if (logic_java_1.LogicJava !== null) {
              if (logic_java_1.LogicJava.sdk <= 23) {
                if (modules[i].name === 'app_process') {
                  continue;
                }
              }
            }
          }

          modules[i] = Api.enumerateModuleInfo(modules[i]);
        }
      }

      return modules;
    }
  }, {
    key: "enumerateModuleInfo",

    /**
     * Enumerate all information about the module (imports / exports / symbols)
     * @param fridaModule object from frida-gum
     */

    /*
        TODO: recheck! when doc says object from frida-gum it shouldnt used by dwarf with string
              fix on pyside and remove the string stuff here
              return should also DwarfModule as Module is altered
          module_info.py
        def update_details(self, dwarf, base_info):
            details = dwarf.dwarf_api('enumerateModuleInfo', base_info['name'])
    */
    value: function enumerateModuleInfo(fridaModule) {
      var _module = null;

      if (utils_1.Utils.isString(fridaModule)) {
        _module = Process.findModuleByName(fridaModule);
      } else {
        _module = fridaModule;
      }

      if (dwarf_1.Dwarf.modulesBlacklist.indexOf(_module.name) >= 0) {
        Api.log('Error: Module ' + _module.name + ' is blacklisted');
        return _module;
      }

      try {
        _module['imports'] = _module.enumerateImports();
        _module['exports'] = _module.enumerateExports();
        _module['symbols'] = _module.enumerateSymbols();
      } catch (e) {
        return _module;
      }

      _module['entry'] = null;

      var header = _module.base.readByteArray(4);

      if (header[0] !== 0x7f && header[1] !== 0x45 && header[2] !== 0x4c && header[3] !== 0x46) {
        // Elf
        _module['entry'] = _module.base.add(24).readPointer();
      }

      return _module;
    }
  }, {
    key: "enumerateRanges",

    /**
     * Enumerate all mapped ranges
     */
    value: function enumerateRanges() {
      return Process.enumerateRanges('---');
    }
  }, {
    key: "enumerateSymbols",

    /**
     * Enumerate symbols for the given module name or pointer
     * @param module an hex/int address or string name
     */
    value: function enumerateSymbols(module) {
      if ((0, _typeof2["default"])(module) !== 'object') {
        module = Api.findModule(module);
      }

      if (module !== null) {
        if (dwarf_1.Dwarf.modulesBlacklist.indexOf(module.name) >= 0) {
          return [];
        }

        return module.enumerateSymbols();
      }

      return [];
    }
  }, {
    key: "evaluate",

    /**
     * Evaluate javascript. Used from the UI to inject javascript code into the process
     * @param w
     */
    value: function evaluate(w) {
      var Thread = thread_wrapper_1.ThreadWrapper;

      try {
        return eval(w);
      } catch (e) {
        Api.log(e.toString());
        return null;
      }
    }
  }, {
    key: "evaluateFunction",

    /**
     * Evaluate javascript. Used from the UI to inject javascript code into the process
     * @param w
     */
    value: function evaluateFunction(w) {
      try {
        var fn = new Function('Thread', w);
        return fn.apply(this, [thread_wrapper_1.ThreadWrapper]);
      } catch (e) {
        Api.log(e.toString());
        return null;
      }
    }
  }, {
    key: "evaluatePtr",

    /**
     * Evaluate any input and return a NativePointer
     * @param w
     */
    value: function evaluatePtr(w) {
      try {
        return ptr(eval(w));
      } catch (e) {
        return NULL;
      }
    }
  }, {
    key: "findExport",

    /**
     * Shortcut to quickly retrieve an export
     *
     * ```javascript
     * const openAddress = findExport('open');
     * const myTargetAddress = findExport('target_func', 'target_module.so');
     * ```
     *
     * @param name: the name of the export
     * @param module: optional name of the module
     */
    value: function findExport(name, module) {
      if (typeof module === 'undefined') {
        module = null;
      }

      return Module.findExportByName(module, name);
    }
  }, {
    key: "findModule",

    /**
     * Find a module providing any argument. Could be a string/int pointer or module name
     */
    value: function findModule(module) {
      var _module;

      if (utils_1.Utils.isString(module) && module.substring(0, 2) !== '0x') {
        _module = Process.findModuleByName(module);

        if (utils_1.Utils.isDefined(_module)) {
          return _module;
        } else {
          // do wildcard search
          if (module.indexOf('*') !== -1) {
            var modules = Process.enumerateModules();
            var searchName = module.toLowerCase().split('*')[0];

            for (var i = 0; i < modules.length; i++) {
              // remove non matching
              if (modules[i].name.toLowerCase().indexOf(searchName) === -1) {
                modules.splice(i, 1);
                i--;
              }
            }

            if (modules.length === 1) {
              return modules[0];
            } else {
              return modules;
            }
          }
        }
      } else {
        _module = Process.findModuleByAddress(ptr(module));

        if (!utils_1.Utils.isDefined(_module)) {
          _module = {};
        }

        return _module;
      }

      return null;
    }
  }, {
    key: "findSymbol",

    /**
     * Find a symbol matching the given pattern
     */
    value: function findSymbol(pattern) {
      return DebugSymbol.findFunctionsMatching(pattern);
    }
  }, {
    key: "getAddressTs",

    /**
     * get telescope information for the given pointer argument
     * @param p: pointer
     */
    value: function getAddressTs(p) {
      var _ptr = ptr(p);

      var _range = Process.findRangeByAddress(_ptr);

      if (utils_1.Utils.isDefined(_range)) {
        if (_range.protection.indexOf('r') !== -1) {
          try {
            var s = Api.readString(_ptr);

            if (s !== "") {
              return [0, s];
            }
          } catch (e) {}

          try {
            var ptrVal = _ptr.readPointer();

            return [1, ptrVal];
          } catch (e) {}

          return [2, p];
        }
      }

      return [-1, p];
    }
  }, {
    key: "getDebugSymbols",

    /**
     * Return an array of DebugSymbol for the requested pointers
     * @param ptrs: an array of NativePointer
     */
    value: function getDebugSymbols(ptrs) {
      var symbols = [];

      if (utils_1.Utils.isDefined(ptrs)) {
        try {
          ptrs = JSON.parse(ptrs);
        } catch (e) {
          utils_1.Utils.logErr('getDebugSymbols', e);
          return symbols;
        }

        for (var i = 0; i < ptrs.length; i++) {
          symbols.push(Api.getSymbolByAddress(ptrs[i]));
        }
      }

      return symbols;
    }
  }, {
    key: "getInstruction",

    /**
     * Shortcut to retrieve an Instruction object for the given address
     */
    value: function getInstruction(address) {
      try {
        var instruction = Instruction.parse(ptr(address));
        return (0, _stringify["default"])({
          'string': instruction.toString()
        });
      } catch (e) {
        utils_1.Utils.logErr('getInstruction', e);
      }

      return null;
    }
  }, {
    key: "getRange",

    /**
     * Return a RangeDetails object or null for the requested pointer
     */
    value: function getRange(address) {
      try {
        var nativeAddress = ptr(address);

        if (nativeAddress === null || (0, _parseInt2["default"])(nativeAddress.toString()) === 0) {
          return null;
        }

        var ret = Process.findRangeByAddress(nativeAddress);

        if (ret == null) {
          return null;
        }

        return ret;
      } catch (e) {
        utils_1.Utils.logErr('getRange', e);
        return null;
      }
    }
  }, {
    key: "getSymbolByAddress",

    /**
     * Return DebugSymbol or null for the given pointer
     */
    value: function getSymbolByAddress(pt) {
      try {
        pt = ptr(pt);
        return DebugSymbol.fromAddress(pt);
      } catch (e) {
        utils_1.Utils.logErr('getSymbolByAddress', e);
        return null;
      }
    }
  }, {
    key: "hookAllJavaMethods",

    /**
     * Hook all the methods for the given java class
     *
     * ```javascript
     * hookAllJavaMethods('android.app.Activity', function() {
     *     console.log('hello from:', this.className, this.method);
     * })
     * ```
     * @param className
     * @param callback
     */
    value: function hookAllJavaMethods(className, callback) {
      return logic_java_1.LogicJava.hookAllJavaMethods(className, callback);
    }
  }, {
    key: "hookClassLoaderClassInitialization",

    /**
     * Receive a callback whenever a java class is going to be loaded by the class loader.
     *
     * ```javascript
     * hookClassLoaderClassInitialization('com.target.classname', function() {
     *     console.log('target is being loaded');
     * })
     * ```
     * @param className
     * @param callback
     */
    value: function hookClassLoaderClassInitialization(className, callback) {
      return logic_java_1.LogicJava.hookClassLoaderClassInitialization(className, callback);
    }
  }, {
    key: "hookJavaConstructor",

    /**
     * Hook the constructor of the given java class
     * ```javascript
     * hookJavaConstructor('android.app.Activity', function() {
     *     console.log('activity created');
     * })
     * ```
     * @param className
     * @param callback
     */
    value: function hookJavaConstructor(className, callback) {
      return logic_java_1.LogicJava.hook(className, '$init', callback);
    }
  }, {
    key: "hookJavaMethod",

    /**
     * Hook the constructor of the given java class
     * ```javascript
     * hookJavaConstructor('android.app.Activity.onCreate', function() {
     *     console.log('activity created');
     *     var savedInstanceState = arguments[0];
     *     if (savedInstanceState !== null) {
     *         return this.finish();
     *     } else {
     *         return this.overload.call(this, arguments);
     *     }
     * })
     * ```
     * @param targetClassMethod
     * @param callback
     */
    value: function hookJavaMethod(targetClassMethod, callback) {
      return logic_java_1.LogicJava.hookJavaMethod(targetClassMethod, callback);
    }
  }, {
    key: "hookModuleInitialization",

    /**
     * Receive a callback when the native module is being loaded
     * ```javascript
     * hookModuleInitialization('libtarget.so', function() {
     *     console.log('libtarget is being loaded');
     * });
     * ```
     * @param moduleName
     * @param callback
     */
    value: function hookModuleInitialization(moduleName, callback) {
      return logic_initialization_1.LogicInitialization.hookModuleInitialization(moduleName, callback);
    }
    /**
     * Map the given blob as hex string using memfd:create with the given name
     *
     * @return a negative integer if error or fd
     */

  }, {
    key: "injectBlob",
    value: function injectBlob(name, blob) {
      // arm syscall memfd_create
      var sys_num = 385;

      if (Process.arch === 'ia32') {
        sys_num = 356;
      } else if (Process.arch === 'x64') {
        sys_num = 319;
      }

      var syscall_ptr = Api.findExport('syscall');
      var write_ptr = Api.findExport('write');
      var dlopen_ptr = Api.findExport('dlopen');

      if (syscall_ptr !== null && !syscall_ptr.isNull()) {
        var syscall = new NativeFunction(syscall_ptr, 'int', ['int', 'pointer', 'int']);

        if (write_ptr !== null && !write_ptr.isNull()) {
          var write = new NativeFunction(write_ptr, 'int', ['int', 'pointer', 'int']);

          if (dlopen_ptr !== null && !dlopen_ptr.isNull()) {
            var dlopen = new NativeFunction(dlopen_ptr, 'int', ['pointer', 'int']);
            var m = fs_1.FileSystem.allocateRw(128);
            m.writeUtf8String(name);
            var fd = syscall(sys_num, m, 0);

            if (fd > 0) {
              var hexArr = utils_1.Utils.hex2a(blob);
              var blob_space = Memory.alloc(hexArr.length);
              Memory.protect(blob_space, hexArr.length, 'rwx');
              blob_space.writeByteArray(hexArr);
              write(fd, blob_space, hexArr.length);
              m.writeUtf8String('/proc/' + Process.id + '/fd/' + fd);
              return dlopen(m, 1);
            } else {
              return -4;
            }
          } else {
            return -3;
          }
        } else {
          return -2;
        }
      } else {
        return -1;
      }
    }
  }, {
    key: "isAddressWatched",

    /**
     * @return a boolean indicating if the given pointer is currently watched
     */
    value: function isAddressWatched(pt) {
      var watchpoint = logic_watchpoint_1.LogicWatchpoint.memoryWatchpoints[ptr(pt).toString()];
      return utils_1.Utils.isDefined(watchpoint);
    }
  }, {
    key: "isPrintable",
    value: function isPrintable(_char) {
      try {
        var isprint_ptr = Api.findExport('isprint');

        if (utils_1.Utils.isDefined(isprint_ptr)) {
          var isprint_fn = new NativeFunction(isprint_ptr, 'int', ['int']);

          if (utils_1.Utils.isDefined(isprint_fn)) {
            return isprint_fn(_char);
          }
        } else {
          if (_char > 31 && _char < 127) {
            return true;
          }
        }

        return false;
      } catch (e) {
        utils_1.Utils.logErr('isPrintable', e);
        return false;
      }
    }
  }, {
    key: "javaBacktrace",

    /**
     * @return a java stack trace. Must be executed in JVM thread
     */
    value: function javaBacktrace() {
      return logic_java_1.LogicJava.backtrace();
    }
  }, {
    key: "jvmExplorer",

    /**
     * @return the explorer object for the given java handle
     */
    value: function jvmExplorer(handle) {
      return logic_java_1.LogicJava.jvmExplorer(handle);
    }
    /**
     * log whatever to Dwarf console
     */

  }, {
    key: "log",
    value: function log(what) {
      if (utils_1.Utils.isDefined(what)) {
        dwarf_1.Dwarf.loggedSend('log:::' + what);
      }
    }
  }, {
    key: "memoryScan",
    value: function memoryScan(start, size, pattern) {
      var result = [];

      try {
        result = Api._internalMemoryScan(ptr(start), size, pattern);
      } catch (e) {
        utils_1.Utils.logErr('memoryScan', e);
      }

      dwarf_1.Dwarf.loggedSend('memoryscan_result:::' + (0, _stringify["default"])(result));
    }
  }, {
    key: "memoryScanList",
    value: function memoryScanList(ranges, pattern) {
      ranges = JSON.parse(ranges);
      var result = [];

      for (var i = 0; i < ranges.length; i++) {
        try {
          result = result.concat(Api._internalMemoryScan(ptr(ranges[i]['start']), ranges[i]['size'], pattern));
        } catch (e) {
          utils_1.Utils.logErr('memoryScanList', e);
        }

        if (result.length >= 100) {
          break;
        }
      }

      dwarf_1.Dwarf.loggedSend('memoryscan_result:::' + (0, _stringify["default"])(result));
    }
  }, {
    key: "putBreakpoint",

    /**
     * put a breakpoint on a native pointer or a java class with an optional evaluated condition
     *
     * ```javascript
     * var nativeTarget = findExport('memcpy');
     *
     * putBreakpoint(nativeTarget);
     *
     * nativeTarget = findExport('open');
     * putBreakpoint(target, function() {
     *     if (this.context.x0.readUtf8String().indexOf('prefs.json') >= 0) {
     *         return true;
     *     }
     *
     *     return false;
     * });
     *
     * var javaTarget = 'android.app.Activity.onCreate';
     * putBreakpoint(javaTarget);
     * ```
     *
     * @param address_or_class
     * @param condition
     */
    value: function putBreakpoint(address_or_class, condition) {
      return logic_breakpoint_1.LogicBreakpoint.putBreakpoint(address_or_class, condition);
    }
    /**
     * Put a java class initialization breakpoint
     *
     * ```javascript
     * putJavaClassInitializationBreakpoint('android.app.Activity');
     * ```
     * @param className
     */

  }, {
    key: "putJavaClassInitializationBreakpoint",
    value: function putJavaClassInitializationBreakpoint(className) {
      return logic_java_1.LogicJava.putJavaClassInitializationBreakpoint(className);
    }
    /**
     * Put a native module initialization breakpoint
     *
     * ```javascript
     * putModuleInitializationBreakpoint('libtarget.so');
     * ```
     * @param moduleName
     */

  }, {
    key: "putModuleInitializationBreakpoint",
    value: function putModuleInitializationBreakpoint(moduleName) {
      return logic_initialization_1.LogicInitialization.putModuleInitializationBreakpoint(moduleName);
    }
    /**
     * Put a watchpoint on the given address
     *
     * ```javascript
     * putWatchpoint(0x1000, 'r');
     *
     * var target = findExport('memcpy');
     * Interceptor.attach(target, {
     *     onLeave: function(ret) {
     *         putWatchpoint(this.context.x0, 'rw', function() {
     *            log(backtrace(this.context));
     *         });
     *     }
     * });
     * ```
     * @param address
     * @param flags
     * @param callback
     */

  }, {
    key: "putWatchpoint",
    value: function putWatchpoint(address, flags, callback) {
      var intFlags = 0;

      if (flags.indexOf('r') >= 0) {
        intFlags |= watchpoint_1.MEMORY_ACCESS_READ;
      }

      if (flags.indexOf('w') >= 0) {
        intFlags |= watchpoint_1.MEMORY_ACCESS_WRITE;
      }

      if (flags.indexOf('x') >= 0) {
        intFlags |= watchpoint_1.MEMORY_ACCESS_EXECUTE;
      }

      return logic_watchpoint_1.LogicWatchpoint.putWatchpoint(address, intFlags, callback);
    }
  }, {
    key: "readString",

    /**
     * A shortcut and secure way to read a string from a pointer with frida on any os
     *
     * @return the string pointed by address until termination or optional length
     */
    value: function readString(address, length) {
      try {
        address = ptr(address);
        var fstring = "";

        if (!utils_1.Utils.isNumber(length)) {
          length = -1;
        }

        var range = Process.findRangeByAddress(address);

        if (!utils_1.Utils.isDefined(range)) {
          return "";
        }

        if (utils_1.Utils.isString(range.protection) && range.protection.indexOf('r') === -1) {
          //Access violation
          return "";
        }

        var _np = new NativePointer(address);

        if (!utils_1.Utils.isDefined(_np)) {
          return "";
        }

        if (Process.platform === 'windows') {
          fstring = _np.readAnsiString(length);
        }

        if (utils_1.Utils.isString(fstring) && fstring.length === 0) {
          fstring = _np.readCString(length);
        }

        if (utils_1.Utils.isString(fstring) && fstring.length === 0) {
          fstring = _np.readUtf8String(length);
        }

        if (utils_1.Utils.isString(fstring) && fstring.length) {
          for (var i = 0; i < fstring.length; i++) {
            if (!Api.isPrintable(fstring.charCodeAt(i))) {
              fstring = null;
              break;
            }
          }
        }

        if (fstring !== null && utils_1.Utils.isString(fstring) && fstring.length) {
          return fstring;
        } else {
          return "";
        }
      } catch (e) {
        utils_1.Utils.logErr('readString', e);
        return "";
      }
    }
  }, {
    key: "readBytes",

    /**
     * A shortcut for safely reading from memory
     *
     * @return an ArrayBuffer of the given length filled with data starting from target address
     */
    value: function readBytes(address, length) {
      try {
        address = ptr(address); // make sure all involved ranges are read-able

        var ranges = [];
        var range;
        var tmp = ptr(address);
        var tail = (0, _parseInt2["default"])(tmp.add(length).toString(), 16);

        while (true) {
          try {
            range = Process.findRangeByAddress(tmp);
          } catch (e) {
            break;
          }

          if (range) {
            if (range.protection[0] !== 'r') {
              Memory.protect(range.base, range.size, 'r--');
              ranges.push(range);
            }

            tmp = tmp.add(range.size);

            if ((0, _parseInt2["default"])(tmp.toString(), 16) >= tail) {
              break;
            }
          } else {
            break;
          }
        }

        var data = ptr(address).readByteArray(length);
        ranges.forEach(function (range) {
          Memory.protect(range.base, range.size, range.protection);
        });
        return data;
      } catch (e) {
        utils_1.Utils.logErr('readBytes', e);
        return [];
      }
    }
  }, {
    key: "readPointer",

    /**
     * @return a pointer from the given address
     */
    value: function readPointer(pt) {
      try {
        return ptr(pt).readPointer();
      } catch (e) {
        utils_1.Utils.logErr('readPointer', e);
        return NULL;
      }
    }
  }, {
    key: "releaseFromJs",

    /**
     * resume the execution of the given thread id
     */
    value: function releaseFromJs(tid) {
      dwarf_1.Dwarf.loggedSend('release_js:::' + tid);
    }
  }, {
    key: "removeBreakpoint",

    /**
     * Remove a breakpoint on address_or_class
     * @return a boolean indicating if removal was successful
     */
    value: function removeBreakpoint(address_or_class) {
      return logic_breakpoint_1.LogicBreakpoint.removeBreakpoint(address_or_class);
    }
    /**
     * Remove a java class initialization breakpoint on moduleName
     * @return a boolean indicating if removal was successful
     */

  }, {
    key: "removeJavaClassInitializationBreakpoint",
    value: function removeJavaClassInitializationBreakpoint(moduleName) {
      var ret = logic_java_1.LogicJava.removeModuleInitializationBreakpoint(moduleName);

      if (ret) {
        dwarf_1.Dwarf.loggedSend('breakpoint_deleted:::java_class_initialization:::' + moduleName);
      }

      return ret;
    }
    /**
     * Remove a module initialization breakpoint on moduleName
     * @return a boolean indicating if removal was successful
     */

  }, {
    key: "removeModuleInitializationBreakpoint",
    value: function removeModuleInitializationBreakpoint(moduleName) {
      var ret = logic_initialization_1.LogicInitialization.removeModuleInitializationBreakpoint(moduleName);

      if (ret) {
        dwarf_1.Dwarf.loggedSend('breakpoint_deleted:::module_initialization:::' + moduleName);
      }

      return ret;
    }
    /**
     * Remove a watchpoint on the given address
     * @return a boolean indicating if removal was successful
     */

  }, {
    key: "removeWatchpoint",
    value: function removeWatchpoint(address) {
      return logic_watchpoint_1.LogicWatchpoint.removeWatchpoint(address);
    }
    /**
     * Restart the application
     *
     * Android only
     */

  }, {
    key: "restart",
    value: function restart() {
      if (logic_java_1.LogicJava.available) {
        return logic_java_1.LogicJava.restartApplication();
      }

      return false;
    }
  }, {
    key: "resume",
    value: function resume() {
      if (dwarf_1.Dwarf.PROC_RESUMED) {
        dwarf_1.Dwarf.PROC_RESUMED = true;
        dwarf_1.Dwarf.loggedSend('resume:::0');
      } else {
        console.log('Error: Process already resumed');
      }
    }
  }, {
    key: "setBreakpointCondition",
    value: function setBreakpointCondition(address_or_class, condition) {
      return logic_breakpoint_1.LogicBreakpoint.setBreakpointCondition(address_or_class, condition);
    }
    /**
     * Send whatever to the data panel
     *
     * ```javascript
     * var sendCount = 0;
     * Interceptor.attach(findExport('send'), function() {
     *     setData(sendCount + '', this.context.x1.readByteArray(parseInt(this.context.x2)))
     *     sendCount++;
     * });
     * ```
     */

  }, {
    key: "setData",
    value: function setData(key, data) {
      if (typeof key !== 'string' && key.length < 1) {
        return;
      }

      if (data.constructor.name === 'ArrayBuffer') {
        dwarf_1.Dwarf.loggedSend('set_data:::' + key, data);
      } else {
        if ((0, _typeof2["default"])(data) === 'object') {
          data = (0, _stringify["default"])(data, null, 4);
        }

        dwarf_1.Dwarf.loggedSend('set_data:::' + key + ':::' + data);
      }
    }
  }, {
    key: "startJavaTracer",

    /**
     * Start the java tracer on the given classes
     */
    value: function startJavaTracer(classes, callback) {
      return logic_java_1.LogicJava.startTrace(classes, callback);
    }
  }, {
    key: "startNativeTracer",

    /**
     * Start the native tracer on the current thread
     *
     * ```javascript
     * startNativeTracer(function() {
     *     log('===============');
     *     log(this.instruction);
     *     log(this.context);
     *     log('===============');
     *     if (shouldStopTracer) {
     *         this.stop();
     *     }
     * });
     * ```
     */
    value: function startNativeTracer(callback) {
      var stalkerInfo = logic_stalker_1.LogicStalker.stalk();

      if (stalkerInfo !== null) {
        stalkerInfo.currentMode = callback;
        return true;
      }

      return false;
    }
  }, {
    key: "stopJavaTracer",

    /**
     * Stop the java tracer
     */
    value: function stopJavaTracer() {
      return logic_java_1.LogicJava.stopTrace();
    }
  }, {
    key: "strace",

    /**
     * start strace
     */
    value: function strace(callback) {
      return logic_stalker_1.LogicStalker.strace(callback);
    }
  }, {
    key: "updateModules",
    value: function updateModules() {
      var modules = Api.enumerateModules();
      dwarf_1.Dwarf.loggedSend('update_modules:::' + Process.getCurrentThreadId() + ':::' + (0, _stringify["default"])(modules));
    }
  }, {
    key: "updateRanges",
    value: function updateRanges() {
      try {
        dwarf_1.Dwarf.loggedSend('update_ranges:::' + Process.getCurrentThreadId() + ':::' + (0, _stringify["default"])(Process.enumerateRanges('---')));
      } catch (e) {
        utils_1.Utils.logErr('updateRanges', e);
      }
    }
  }, {
    key: "updateSearchableRanges",
    value: function updateSearchableRanges() {
      try {
        dwarf_1.Dwarf.loggedSend('update_searchable_ranges:::' + Process.getCurrentThreadId() + ':::' + (0, _stringify["default"])(Process.enumerateRanges('r--')));
      } catch (e) {
        utils_1.Utils.logErr('updateSearchableRanges', e);
      }
    }
  }, {
    key: "writeBytes",

    /**
     * Write the given hex string or ArrayBuffer into the given address
     */
    value: function writeBytes(address, what) {
      try {
        address = ptr(address);

        if (typeof what === 'string') {
          Api.writeUtf8(address, utils_1.Utils.hex2a(what));
        } else {
          address.writeByteArray(what);
        }

        return true;
      } catch (e) {
        utils_1.Utils.logErr('writeBytes', e);
        return false;
      }
    }
  }, {
    key: "writeUtf8",
    value: function writeUtf8(address, str) {
      try {
        address = ptr(address);
        address.writeUtf8String(str);
        return true;
      } catch (e) {
        utils_1.Utils.logErr('writeUtf8', e);
        return false;
      }
    }
  }]);
  return Api;
}();

exports.Api = Api;

},{"./dwarf":98,"./fs":99,"./logic_breakpoint":102,"./logic_initialization":103,"./logic_java":104,"./logic_objc":105,"./logic_stalker":106,"./logic_watchpoint":107,"./thread_wrapper":111,"./utils":112,"./watchpoint":113,"@babel/runtime-corejs2/core-js/json/stringify":2,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/core-js/parse-int":7,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/createClass":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":12,"@babel/runtime-corejs2/helpers/typeof":13}],97:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var Breakpoint = function Breakpoint(target) {
  (0, _classCallCheck2["default"])(this, Breakpoint);
  this.target = target;
};

exports.Breakpoint = Breakpoint;

},{"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],98:[function(require,module,exports){
(function (global){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _stringify = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/json/stringify"));

var _getOwnPropertyNames = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/get-own-property-names"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var api_1 = require("./api");

var logic_breakpoint_1 = require("./logic_breakpoint");

var interceptor_1 = require("./interceptor");

var logic_java_1 = require("./logic_java");

var logic_initialization_1 = require("./logic_initialization");

var logic_watchpoint_1 = require("./logic_watchpoint");

var utils_1 = require("./utils");

var Dwarf =
/*#__PURE__*/
function () {
  function Dwarf() {
    (0, _classCallCheck2["default"])(this, Dwarf);
  }

  (0, _createClass2["default"])(Dwarf, null, [{
    key: "init",
    value: function init(breakStart, debug, spawned) {
      Dwarf.BREAK_START = breakStart;
      Dwarf.DEBUG = debug;
      Dwarf.SPAWNED = spawned;

      if (logic_java_1.LogicJava.available) {
        logic_java_1.LogicJava.init();
      }

      logic_initialization_1.LogicInitialization.init();
      interceptor_1.DwarfInterceptor.init(); // register all api as global

      var exclusions = ['constructor', 'length', 'name', 'prototype'];
      (0, _getOwnPropertyNames["default"])(api_1.Api).forEach(function (prop) {
        if (exclusions.indexOf(prop) < 0) {
          global[prop] = api_1.Api[prop];
        }
      });

      if (Process.platform === 'windows') {
        this.modulesBlacklist.push('ntdll.dll');

        if (Process.arch === 'x64') {
          //TODO: debug later why module needs blacklisted on x64 targets only
          this.modulesBlacklist.push('win32u.dll');
        }
      } else if (Process.platform === 'linux') {
        if (utils_1.Utils.isDefined(logic_java_1.LogicJava) && logic_java_1.LogicJava.sdk <= 23) {
          this.modulesBlacklist.push('app_process');
        }
      }

      Process.setExceptionHandler(Dwarf.handleException);

      if (Process.platform === 'windows') {
        // break proc at main
        if (Dwarf.SPAWNED && Dwarf.BREAK_START) {
          var initialHook = Interceptor.attach(api_1.Api.findExport('RtlUserThreadStart'), function () {
            var address = null;

            if (Process.arch === 'ia32') {
              var context = this.context;
              address = context.eax;
            } else if (Process.arch === 'x64') {
              var _context = this.context;
              address = _context.rax;
            }

            if (utils_1.Utils.isDefined(address)) {
              var startInterceptor = Interceptor.attach(address, function () {
                logic_breakpoint_1.LogicBreakpoint.breakpoint(logic_breakpoint_1.LogicBreakpoint.REASON_BREAKPOINT, this.context.pc, this.context);
                startInterceptor.detach();
              });
              initialHook.detach();
            }
          });
        }
      }

      Dwarf.dispatchContextInfo(logic_breakpoint_1.LogicBreakpoint.REASON_SET_INITIAL_CONTEXT);
    }
  }, {
    key: "dispatchContextInfo",
    value: function dispatchContextInfo(reason, address_or_class, context) {
      var tid = Process.getCurrentThreadId();
      var data = {
        "tid": tid,
        "reason": reason,
        "ptr": address_or_class
      };

      if (reason === logic_breakpoint_1.LogicBreakpoint.REASON_SET_INITIAL_CONTEXT) {
        data['arch'] = Process.arch;
        data['platform'] = Process.platform;
        data['java'] = Java.available;
        data['objc'] = ObjC.available;
        data['pid'] = Process.id;
        data['pointerSize'] = Process.pointerSize;
      }

      if (utils_1.Utils.isDefined(context)) {
        if (Dwarf.DEBUG) {
          utils_1.Utils.logDebug('[' + tid + '] sendInfos - preparing infos for valid context');
        }

        data['context'] = context;

        if (utils_1.Utils.isDefined(context['pc'])) {
          var symbol = null;

          try {
            symbol = DebugSymbol.fromAddress(context.pc);
          } catch (e) {
            utils_1.Utils.logErr('_sendInfos', e);
          }

          if (Dwarf.DEBUG) {
            utils_1.Utils.logDebug('[' + tid + '] sendInfos - preparing native backtrace');
          }

          data['backtrace'] = {
            'bt': api_1.Api.backtrace(context),
            'type': 'native'
          };
          data['is_java'] = false;

          if (Dwarf.DEBUG) {
            utils_1.Utils.logDebug('[' + tid + '] sendInfos - preparing context registers');
          }

          var newCtx = {};

          for (var reg in context) {
            var val = context[reg];
            var isValidPtr = false;

            if (Dwarf.DEBUG) {
              utils_1.Utils.logDebug('[' + tid + '] getting register information:', reg, val);
            }

            var ts = api_1.Api.getAddressTs(val);
            isValidPtr = ts[0] > 0;
            newCtx[reg] = {
              'value': val,
              'isValidPointer': isValidPtr,
              'telescope': ts
            };

            if (reg === 'pc') {
              if (symbol !== null) {
                newCtx[reg]['symbol'] = symbol;
              }

              try {
                var inst = Instruction.parse(val);
                newCtx[reg]['instruction'] = {
                  'size': inst.size,
                  'groups': inst.groups,
                  'thumb': inst.groups.indexOf('thumb') >= 0 || inst.groups.indexOf('thumb2') >= 0
                };
              } catch (e) {
                utils_1.Utils.logErr('_sendInfos', e);
              }
            }
          }

          data['context'] = newCtx;
        } else {
          data['is_java'] = true;

          if (Dwarf.DEBUG) {
            utils_1.Utils.logDebug('[' + tid + '] sendInfos - preparing java backtrace');
          }

          data['backtrace'] = {
            'bt': api_1.Api.javaBacktrace(),
            'type': 'java'
          };
        }
      }

      if (Dwarf.DEBUG) {
        utils_1.Utils.logDebug('[' + tid + '] sendInfos - dispatching infos');
      }

      Dwarf.loggedSend('set_context:::' + (0, _stringify["default"])(data));
    }
  }, {
    key: "handleException",
    value: function handleException(exception) {
      if (Dwarf.DEBUG) {
        var dontLog = false;

        if (Process.platform === 'windows') {
          // hide SetThreadName - https://github.com/frida/glib/blob/master/glib/gthread-win32.c#L579
          var reg = null;

          if (Process.arch === 'x64') {
            reg = exception['context']['rax'];
          } else if (Process.arch === 'ia32') {
            reg = exception['context']['eax'];
          }

          if (reg !== null && reg.readInt() === 0x406d1388) {
            dontLog = true;
          }
        }

        if (!dontLog) {
          console.log('[' + Process.getCurrentThreadId() + '] exception handler: ' + (0, _stringify["default"])(exception));
        }
      }

      if (Process.platform === 'windows') {
        if (exception['type'] === 'access-violation') {
          return true;
        }
      }

      var watchpoint = logic_watchpoint_1.LogicWatchpoint.handleException(exception);
      return watchpoint !== null;
    }
  }, {
    key: "loggedSend",
    value: function loggedSend(w, p) {
      if (Dwarf.DEBUG) {
        console.log('[' + Process.getCurrentThreadId() + '] send | ' + w);
      }

      return send(w, p);
    }
  }]);
  return Dwarf;
}();

Dwarf.PROC_RESUMED = false;
Dwarf.threadContexts = {};
Dwarf.modulesBlacklist = [];
exports.Dwarf = Dwarf;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"./api":96,"./interceptor":101,"./logic_breakpoint":102,"./logic_initialization":103,"./logic_java":104,"./logic_watchpoint":107,"./utils":112,"@babel/runtime-corejs2/core-js/json/stringify":2,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/core-js/object/get-own-property-names":5,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/createClass":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],99:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var api_1 = require("./api");

var FileSystem =
/*#__PURE__*/
function () {
  function FileSystem() {
    (0, _classCallCheck2["default"])(this, FileSystem);
  }

  (0, _createClass2["default"])(FileSystem, null, [{
    key: "init",
    value: function init() {
      FileSystem._fclose = FileSystem.exportToFunction('fclose', 'int', ['pointer']);
      FileSystem._fcntl = FileSystem.exportToFunction('fcntl', 'int', ['int', 'int', 'int']);
      FileSystem._fgets = FileSystem.exportToFunction('fgets', 'int', ['pointer', 'int', 'pointer']);
      FileSystem._fileno = FileSystem.exportToFunction('fileno', 'int', ['pointer']);
      FileSystem._fopen = FileSystem.exportToFunction('fopen', 'pointer', ['pointer', 'pointer']);
      FileSystem._fputs = FileSystem.exportToFunction('fputs', 'int', ['pointer', 'pointer']);
      FileSystem._fread = FileSystem.exportToFunction('fread', 'uint32', ['pointer', 'uint32', 'uint32', 'pointer']);
      FileSystem._fseek = FileSystem.exportToFunction('fseek', 'int', ['pointer', 'int', 'int']);
      FileSystem._getline = FileSystem.exportToFunction('getline', 'int', ['pointer', 'pointer', 'pointer']);
      FileSystem._pclose = FileSystem.exportToFunction('pclose', 'int', ['pointer']);
      FileSystem._popen = FileSystem.exportToFunction('popen', 'pointer', ['pointer', 'pointer']);
    }
  }, {
    key: "exportToFunction",
    value: function exportToFunction(exp, ret, args) {
      var p = api_1.Api.findExport(exp);

      if (p !== null && !p.isNull()) {
        return new NativeFunction(p, ret, args);
      }

      return null;
    }
    /**
     * Allocate the given size in the heap
     */

  }, {
    key: "allocateRw",
    value: function allocateRw(size) {
      var pt = Memory.alloc(size);
      Memory.protect(pt, size, 'rw-');
      return pt;
    }
  }, {
    key: "allocateString",

    /**
     * Allocate and write the given string in the heap
     */
    value: function allocateString(what) {
      return Memory.allocUtf8String(what);
    }
  }, {
    key: "fopen",

    /**
     * Call native fopen with filePath and perm
     */
    value: function fopen(filePath, perm) {
      if (FileSystem._fopen === null) {
        return NULL;
      }

      var filePathPtr = Memory.allocUtf8String(filePath);
      var p = Memory.allocUtf8String(perm);
      return FileSystem._fopen(filePathPtr, p);
    }
  }, {
    key: "popen",

    /**
     * Call native popen with filePath and perm
     */
    value: function popen(filePath, perm) {
      if (FileSystem._popen === null) {
        return NULL;
      }

      var filePathPtr = Memory.allocUtf8String(filePath);
      var p = Memory.allocUtf8String(perm);
      return FileSystem._popen(filePathPtr, p);
    }
  }, {
    key: "readStringFromFile",

    /**
     * Read a file as string
     */
    value: function readStringFromFile(filePath) {
      var fp = FileSystem.fopen(filePath, 'r');

      if (fp === NULL) {
        return "";
      }

      var ret = FileSystem.readStringFromFp(fp);

      if (FileSystem._fclose != null) {
        FileSystem._fclose(fp);
      }

      return ret;
    }
  }, {
    key: "readStringFromFp",

    /**
     * Read string from descriptor
     */
    value: function readStringFromFp(fp) {
      if (FileSystem._fgets === null) {
        return "";
      }

      var ret = "";

      if (fp !== null) {
        var buf = FileSystem.allocateRw(1024);

        while (FileSystem._fgets(buf, 1024, fp) > 0) {
          ret += buf.readUtf8String();
        }

        return ret;
      }

      return ret;
    }
  }, {
    key: "writeStringToFile",

    /**
     * Write string to file
     */
    value: function writeStringToFile(filePath, content, append) {
      // use frida api
      if (typeof append === 'undefined') {
        append = false;
      }

      var f = new File(filePath, append ? 'wa' : 'w');
      f.write(content);
      f.flush();
      f.close();
    }
  }]);
  return FileSystem;
}();

exports.FileSystem = FileSystem;

},{"./api":96,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/createClass":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],100:[function(require,module,exports){
(function (global){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _getOwnPropertyNames = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/get-own-property-names"));

var _now = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/date/now"));

var _keys = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/keys"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
/**
 Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>
 **/

var api_1 = require("./api");

var dwarf_1 = require("./dwarf");

var thread_api_1 = require("./thread_api");

var utils_1 = require("./utils");

var isDefined = utils_1.Utils.isDefined;

Date.prototype['getTwoDigitHour'] = function () {
  return this.getHours() < 10 ? '0' + this.getHours() : this.getHours();
};

Date.prototype['getTwoDigitMinute'] = function () {
  return this.getMinutes() < 10 ? '0' + this.getMinutes() : this.getMinutes();
};

Date.prototype['getTwoDigitSecond'] = function () {
  return this.getSeconds() < 10 ? '0' + this.getSeconds() : this.getSeconds();
};

Date.prototype['getHourMinuteSecond'] = function () {
  return this.getTwoDigitHour() + ':' + this.getTwoDigitMinute() + ':' + this.getTwoDigitSecond();
};

var dwarf;
rpc.exports = {
  api: function api(tid, apiFunction, apiArguments) {
    if (dwarf_1.Dwarf.DEBUG) {
      utils_1.Utils.logDebug('[' + tid + '] RPC-API: ' + apiFunction + ' | ' + 'args: ' + apiArguments + ' (' + Process.getCurrentThreadId() + ')');
    }

    if (typeof apiArguments === 'undefined' || apiArguments === null) {
      apiArguments = [];
    }

    if ((0, _keys["default"])(dwarf_1.Dwarf.threadContexts).length > 0) {
      var threadContext = dwarf_1.Dwarf.threadContexts[tid];

      if (utils_1.Utils.isDefined(threadContext)) {
        var threadApi = new thread_api_1.ThreadApi(apiFunction, apiArguments);
        threadContext.apiQueue.push(threadApi);
        var start = (0, _now["default"])();

        while (!threadApi.consumed) {
          Thread.sleep(0.5);

          if (dwarf_1.Dwarf.DEBUG) {
            utils_1.Utils.logDebug('[' + tid + '] RPC-API: ' + apiFunction + ' waiting for api result');
          }

          if ((0, _now["default"])() - start > 3 * 1000) {
            threadApi.result = '';
            break;
          }
        }

        var ret = threadApi.result;

        if (!isDefined(ret)) {
          ret = '';
        }

        if (dwarf_1.Dwarf.DEBUG) {
          utils_1.Utils.logDebug('[' + tid + '] RPC-API: ' + apiFunction + ' api result: ' + ret);
        }

        return ret;
      }
    }

    return api_1.Api[apiFunction].apply(this, apiArguments);
  },
  init: function init(breakStart, debug, spawned) {
    dwarf_1.Dwarf.init(breakStart, debug, spawned);
  },
  keywords: function keywords() {
    var map = [];
    (0, _getOwnPropertyNames["default"])(global).forEach(function (name) {
      map.push(name); // second level

      if (utils_1.Utils.isDefined(global[name])) {
        (0, _getOwnPropertyNames["default"])(global[name]).forEach(function (sec_name) {
          map.push(sec_name);
        });
      }
    });
    return utils_1.Utils.uniqueBy(map);
  }
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"./api":96,"./dwarf":98,"./thread_api":109,"./utils":112,"@babel/runtime-corejs2/core-js/date/now":1,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/core-js/object/get-own-property-names":5,"@babel/runtime-corejs2/core-js/object/keys":6,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],101:[function(require,module,exports){
(function (global){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _typeof2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/typeof"));

var _assign = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/assign"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var utils_1 = require("./utils");

var dwarf_1 = require("./dwarf");

var thread_context_1 = require("./thread_context");

var DwarfInterceptor =
/*#__PURE__*/
function () {
  function DwarfInterceptor() {
    (0, _classCallCheck2["default"])(this, DwarfInterceptor);
  }

  (0, _createClass2["default"])(DwarfInterceptor, null, [{
    key: "onAttach",
    value: function onAttach(context) {
      var tid = Process.getCurrentThreadId();
      var that = {};
      var proxiedContext = null;

      if (context !== null) {
        proxiedContext = new Proxy(context, {
          get: function get(object, prop) {
            return object[prop];
          },
          set: function set(object, prop, value) {
            if (dwarf_1.Dwarf.DEBUG) {
              utils_1.Utils.logDebug('[' + tid + '] setting context ' + prop.toString() + ': ' + value);
            }

            send('set_context_value:::' + prop.toString() + ':::' + value);
            object[prop] = value;
            return true;
          }
        });
      }

      that['context'] = proxiedContext;
      var threadContext = new thread_context_1.ThreadContext(tid);
      threadContext.context = context;
      dwarf_1.Dwarf.threadContexts[tid] = threadContext;
    }
  }, {
    key: "onDetach",
    value: function onDetach() {
      var tid = Process.getCurrentThreadId();
      delete dwarf_1.Dwarf.threadContexts[tid];
    }
  }, {
    key: "init",
    value: function init() {
      var clone = (0, _assign["default"])({}, Interceptor);

      clone.attach = function attach(target, callbacks) {
        target.readU8();
        var replacement;

        if (typeof callbacks === 'function') {
          replacement = function replacement() {
            DwarfInterceptor.onAttach(this.context);
            var ret = callbacks.apply(this, arguments);
            DwarfInterceptor.onDetach();
            return ret;
          };
        } else if ((0, _typeof2["default"])(callbacks) === 'object') {
          if (utils_1.Utils.isDefined(callbacks['onEnter'])) {
            replacement = {
              onEnter: function onEnter() {
                DwarfInterceptor.onAttach(this.context);
                var ret = callbacks['onEnter'].apply(this, arguments);
                DwarfInterceptor.onDetach();
                return ret;
              }
            };

            if (utils_1.Utils.isDefined(callbacks['onLeave'])) {
              replacement['onLeave'] = callbacks['onLeave'];
            }
          } else {
            replacement = callbacks;
          }
        }

        return Interceptor['_attach'](target, replacement);
      };

      global['Interceptor'] = clone;
    }
  }]);
  return DwarfInterceptor;
}();

exports.DwarfInterceptor = DwarfInterceptor;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"./dwarf":98,"./thread_context":110,"./utils":112,"@babel/runtime-corejs2/core-js/object/assign":3,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/createClass":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":12,"@babel/runtime-corejs2/helpers/typeof":13}],102:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var api_1 = require("./api");

var breakpoint_1 = require("./breakpoint");

var dwarf_1 = require("./dwarf");

var logic_java_1 = require("./logic_java");

var logic_objc_1 = require("./logic_objc");

var logic_stalker_1 = require("./logic_stalker");

var thread_context_1 = require("./thread_context");

var utils_1 = require("./utils");

var LogicBreakpoint =
/*#__PURE__*/
function () {
  function LogicBreakpoint() {
    (0, _classCallCheck2["default"])(this, LogicBreakpoint);
  }

  (0, _createClass2["default"])(LogicBreakpoint, null, [{
    key: "breakpoint",
    value: function breakpoint(reason, address_or_class, context, java_handle, condition) {
      var tid = Process.getCurrentThreadId();

      if (!utils_1.Utils.isDefined(reason)) {
        reason = LogicBreakpoint.REASON_BREAKPOINT;
      }

      if (dwarf_1.Dwarf.DEBUG) {
        utils_1.Utils.logDebug('[' + tid + '] breakpoint ' + address_or_class + ' - reason: ' + reason);
      }

      var threadContext = dwarf_1.Dwarf.threadContexts[tid];

      if (!utils_1.Utils.isDefined(threadContext) && utils_1.Utils.isDefined(context)) {
        threadContext = new thread_context_1.ThreadContext(tid);
        threadContext.context = context;
        dwarf_1.Dwarf.threadContexts[tid] = threadContext;
      }

      if (utils_1.Utils.isDefined(condition)) {
        if (typeof condition === "string") {
          condition = new Function(condition);
        }

        if (!condition.call(threadContext)) {
          delete dwarf_1.Dwarf.threadContexts[tid];
          return;
        }
      }

      if (!utils_1.Utils.isDefined(threadContext) || !threadContext.preventSleep) {
        if (dwarf_1.Dwarf.DEBUG) {
          utils_1.Utils.logDebug('[' + tid + '] break ' + address_or_class + ' - dispatching context info');
        }

        dwarf_1.Dwarf.dispatchContextInfo(reason, address_or_class, context);

        if (dwarf_1.Dwarf.DEBUG) {
          utils_1.Utils.logDebug('[' + tid + '] break ' + address_or_class + ' - sleeping context. goodnight!');
        }

        LogicBreakpoint.loopApi(threadContext);

        if (dwarf_1.Dwarf.DEBUG) {
          utils_1.Utils.logDebug('[' + tid + '] ThreadContext has been released');
        }

        dwarf_1.Dwarf.loggedSend('release:::' + tid + ':::' + reason);
      }
    }
  }, {
    key: "loopApi",
    value: function loopApi(that) {
      var tid = Process.getCurrentThreadId();

      if (dwarf_1.Dwarf.DEBUG) {
        utils_1.Utils.logDebug('[' + tid + '] looping api');
      }

      var op = recv('' + tid, function () {});
      op.wait();
      var threadContext = dwarf_1.Dwarf.threadContexts[tid];

      if (utils_1.Utils.isDefined(threadContext)) {
        while (threadContext.apiQueue.length === 0) {
          if (dwarf_1.Dwarf.DEBUG) {
            utils_1.Utils.logDebug('[' + tid + '] waiting api queue to be populated');
          }

          Thread.sleep(0.2);
        }

        var release = false;

        while (threadContext.apiQueue.length > 0) {
          var threadApi = threadContext.apiQueue.shift();

          if (dwarf_1.Dwarf.DEBUG) {
            utils_1.Utils.logDebug('[' + tid + '] executing ' + threadApi.apiFunction);
          }

          try {
            if (utils_1.Utils.isDefined(api_1.Api[threadApi.apiFunction])) {
              threadApi.result = api_1.Api[threadApi.apiFunction].apply(that, threadApi.apiArguments);
            } else {
              threadApi.result = null;
            }
          } catch (e) {
            threadApi.result = null;

            if (dwarf_1.Dwarf.DEBUG) {
              utils_1.Utils.logDebug('[' + tid + '] error executing ' + threadApi.apiFunction + ':\n' + e);
            }
          }

          threadApi.consumed = true;

          if (threadApi.apiFunction === '_step') {
            release = true;
            break;
          } else if (threadApi.apiFunction === 'release') {
            var stalkerInfo = logic_stalker_1.LogicStalker.stalkerInfoMap[tid];

            if (utils_1.Utils.isDefined(stalkerInfo)) {
              stalkerInfo.terminated = true;
            }

            release = true;
            break;
          }
        }

        if (!release) {
          LogicBreakpoint.loopApi(that);
        }
      }
    }
  }, {
    key: "putBreakpoint",
    value: function putBreakpoint(target, condition) {
      if (typeof target === 'string') {
        if (target.startsWith('0x')) {
          target = ptr(target);
        } else if (target.indexOf('.') >= 0 && logic_java_1.LogicJava.available) {
          var added = logic_java_1.LogicJava.putBreakpoint(target, condition);

          if (added) {
            dwarf_1.Dwarf.loggedSend('breakpoint_java_callback:::' + target + ':::' + (utils_1.Utils.isDefined(condition) ? condition.toString() : ''));
          }

          return added;
        } else if (target.indexOf('.') >= 0 && logic_objc_1.LogicObjC.available) {
          var _added = logic_objc_1.LogicObjC.putBreakpoint(target, condition);

          if (_added) {
            dwarf_1.Dwarf.loggedSend('breakpoint_objc_callback:::' + target + ':::' + (utils_1.Utils.isDefined(condition) ? condition.toString() : ''));
          }

          return _added;
        }
      } else if (typeof target === 'number') {
        target = ptr(target);
      }

      if (utils_1.Utils.isDefined(LogicBreakpoint.breakpoints[target.toString()])) {
        console.log(target + ' already has a breakpoint');
        return false;
      }

      if (target.constructor.name === 'NativePointer') {
        target = target;
        var breakpoint = new breakpoint_1.Breakpoint(target);

        if (!utils_1.Utils.isDefined(condition)) {
          condition = null;
        }

        breakpoint.condition = condition;
        LogicBreakpoint.breakpoints[target.toString()] = breakpoint;
        LogicBreakpoint.putNativeBreakpoint(breakpoint);
        dwarf_1.Dwarf.loggedSend('breakpoint_native_callback:::' + breakpoint.target.toString() + ':::' + (utils_1.Utils.isDefined(breakpoint.condition) ? breakpoint.condition.toString() : ''));
        return true;
      }

      return false;
    }
  }, {
    key: "putNativeBreakpoint",
    value: function putNativeBreakpoint(breakpoint) {
      breakpoint.interceptor = Interceptor.attach(breakpoint.target, function () {
        breakpoint.interceptor.detach();
        Interceptor['flush']();
        LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_BREAKPOINT, this.context.pc, this.context, null, breakpoint.condition);

        if (typeof LogicBreakpoint.breakpoints[breakpoint.target.toString()] !== 'undefined') {
          LogicBreakpoint.putNativeBreakpoint(breakpoint);
        }
      });
      return true;
    }
  }, {
    key: "removeBreakpoint",
    value: function removeBreakpoint(target) {
      if (typeof target === 'string') {
        if (target.startsWith('0x')) {
          target = ptr(target);
        } else if (target.indexOf('.') >= 0 && logic_java_1.LogicJava.available) {
          var removed = logic_java_1.LogicJava.removeBreakpoint(target);

          if (removed) {
            dwarf_1.Dwarf.loggedSend('breakpoint_deleted:::java:::' + target);
          }

          return removed;
        } else if (target.indexOf('.') >= 0 && logic_objc_1.LogicObjC.available) {
          var _removed = logic_objc_1.LogicObjC.removeBreakpoint(target);

          if (_removed) {
            dwarf_1.Dwarf.loggedSend('breakpoint_deleted:::objc:::' + target);
          }

          return _removed;
        }
      } else if (typeof target === 'number') {
        target = ptr(target);
      }

      var breakpoint = LogicBreakpoint.breakpoints[target.toString()];
      console.log(breakpoint.interceptor);

      if (utils_1.Utils.isDefined(breakpoint)) {
        if (utils_1.Utils.isDefined(breakpoint.interceptor)) {
          breakpoint.interceptor.detach();
        }

        delete LogicBreakpoint.breakpoints[target.toString()];
        dwarf_1.Dwarf.loggedSend('breakpoint_deleted:::native:::' + target.toString());
        return true;
      }

      return false;
    }
  }, {
    key: "setBreakpointCondition",
    value: function setBreakpointCondition(target, condition) {
      if (typeof target === 'string') {
        if (target.startsWith('0x')) {
          target = ptr(target);
        }
      } else if (typeof target === 'number') {
        target = ptr(target);
      }

      var breakpoint = LogicBreakpoint.breakpoints[target.toString()];

      if (!utils_1.Utils.isDefined(breakpoint)) {
        console.log(target + ' is not in breakpoint list');
        return false;
      }

      breakpoint.condition = condition;
      return true;
    }
  }]);
  return LogicBreakpoint;
}();

LogicBreakpoint.REASON_SET_INITIAL_CONTEXT = -1;
LogicBreakpoint.REASON_BREAKPOINT = 0;
LogicBreakpoint.REASON_WATCHPOINT = 1;
LogicBreakpoint.REASON_BREAKPOINT_INITIALIZATION = 2;
LogicBreakpoint.REASON_STEP = 3;
LogicBreakpoint.breakpoints = {};
exports.LogicBreakpoint = LogicBreakpoint;

},{"./api":96,"./breakpoint":97,"./dwarf":98,"./logic_java":104,"./logic_objc":105,"./logic_stalker":106,"./thread_context":110,"./utils":112,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/createClass":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],103:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _keys = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/keys"));

var _stringify = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/json/stringify"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var api_1 = require("./api");

var dwarf_1 = require("./dwarf");

var logic_breakpoint_1 = require("./logic_breakpoint");

var logic_java_1 = require("./logic_java");

var utils_1 = require("./utils");

var LogicInitialization =
/*#__PURE__*/
function () {
  function LogicInitialization() {
    (0, _classCallCheck2["default"])(this, LogicInitialization);
  }

  (0, _createClass2["default"])(LogicInitialization, null, [{
    key: "hitModuleLoading",
    value: function hitModuleLoading(moduleName) {
      if (!utils_1.Utils.isString(moduleName)) {
        return;
      }

      if (dwarf_1.Dwarf.modulesBlacklist.indexOf(moduleName) >= 0) {
        return;
      }

      var module = Process.findModuleByName(moduleName);

      if (module === null) {
        return;
      }

      var moduleInfo = api_1.Api.enumerateModuleInfo(module);
      var tid = Process.getCurrentThreadId();
      dwarf_1.Dwarf.loggedSend('module_initialized:::' + tid + ':::' + (0, _stringify["default"])(moduleInfo));
      var modIndex = (0, _keys["default"])(LogicInitialization.nativeModuleInitializationCallbacks).find(function (ownModuleName) {
        if (ownModuleName === moduleName) {
          return moduleName;
        }
      });

      if (utils_1.Utils.isDefined(modIndex)) {
        var userCallback = LogicInitialization.nativeModuleInitializationCallbacks[modIndex];

        if (utils_1.Utils.isDefined(userCallback)) {
          userCallback.call(this); //TODO: this == this class == LogicInitialization
        } else {
          dwarf_1.Dwarf.loggedSend("breakpoint_module_initialization_callback:::" + tid + ':::' + (0, _stringify["default"])({
            'module': moduleInfo['name'],
            'moduleBase': moduleInfo['base'],
            'moduleEntry': moduleInfo['entry']
          }));
          logic_breakpoint_1.LogicBreakpoint.breakpoint(logic_breakpoint_1.LogicBreakpoint.REASON_BREAKPOINT_INITIALIZATION, this['context'].pc, this['context']);
        }
      }
    }
  }, {
    key: "init",
    value: function init() {
      if (Process.platform === 'windows') {
        // windows native onload code
        var module = Process.findModuleByName('kernel32.dll');

        if (module !== null) {
          var symbols = module.enumerateExports();
          var loadliba_ptr = NULL;
          var loadlibexa_ptr = NULL;
          var loadlibw_ptr = NULL;
          var loadlibexw_ptr = NULL;
          symbols.forEach(function (symbol) {
            if (symbol.name.indexOf('LoadLibraryA') >= 0) {
              loadliba_ptr = symbol.address;
            } else if (symbol.name.indexOf('LoadLibraryW') >= 0) {
              loadlibw_ptr = symbol.address;
            } else if (symbol.name.indexOf('LoadLibraryExA') >= 0) {
              loadlibexa_ptr = symbol.address;
            } else if (symbol.name.indexOf('LoadLibraryExW') >= 0) {
              loadlibexw_ptr = symbol.address;
            }

            if (loadliba_ptr != NULL && loadlibw_ptr != NULL && loadlibexa_ptr != NULL && loadlibexw_ptr != NULL) {
              return;
            }
          });

          if (loadliba_ptr != NULL && loadlibw_ptr != NULL && loadlibexa_ptr != NULL && loadlibexw_ptr != NULL) {
            Interceptor.attach(loadliba_ptr, function (args) {
              try {
                var w = args[0].readAnsiString();
                LogicInitialization.hitModuleLoading.apply(this, [w]);
              } catch (e) {
                utils_1.Utils.logErr('Dwarf.start', e);
              }
            });
            Interceptor.attach(loadlibexa_ptr, function (args) {
              try {
                var w = args[0].readAnsiString();
                LogicInitialization.hitModuleLoading.apply(this, [w]);
              } catch (e) {
                utils_1.Utils.logErr('Dwarf.start', e);
              }
            });
            Interceptor.attach(loadlibw_ptr, function (args) {
              try {
                var w = args[0].readUtf16String();
                LogicInitialization.hitModuleLoading.apply(this, [w]);
              } catch (e) {
                utils_1.Utils.logErr('Dwarf.start', e);
              }
            });
            Interceptor.attach(loadlibexw_ptr, function (args) {
              try {
                var w = args[0].readUtf16String();
                LogicInitialization.hitModuleLoading.apply(this, [w]);
              } catch (e) {
                utils_1.Utils.logErr('Dwarf.start', e);
              }
            });
          }
        }
      } else if (logic_java_1.LogicJava.available) {
        // android native onload code
        if (logic_java_1.LogicJava.sdk >= 23) {
          var _module = Process.findModuleByName(Process.arch.indexOf('64') >= 0 ? 'linker64' : "linker");

          if (_module !== null) {
            var _symbols = _module.enumerateSymbols();

            var call_constructors = _symbols.find(function (symbol) {
              return symbol.name.indexOf('call_constructors') >= 0;
            });

            if (utils_1.Utils.isDefined(call_constructors)) {
              Interceptor.attach(call_constructors.address, function (args) {
                try {
                  LogicInitialization.hitModuleLoading.apply(this, [args[4].readUtf8String()]);
                } catch (e) {}
              });
            }
          }
        } else {
          if (Process.arch === 'ia32') {
            // this suck hard but it's the best way i can think
            // working on latest nox emulator 5.1.1
            var linkerRanges = Process.findModuleByName('linker').enumerateRanges('r-x');

            for (var i = 0; i < linkerRanges.length; i++) {
              var range = linkerRanges[i];
              var res = Memory.scanSync(range.base, range.size, '89 FD C7 44 24 30 00 00 00 00');

              if (res.length > 0) {
                Interceptor.attach(res[0].address, function () {
                  var context = this.context;

                  if (context.ecx.toInt32() !== 0x8) {
                    return;
                  }

                  try {
                    var w = context.esi.readCString();
                    LogicInitialization.hitModuleLoading.apply(this, [w]);
                  } catch (e) {
                    utils_1.Utils.logErr('Dwarf.onLoad setup', e);
                  }
                });
                break;
              }
            }
          }
        }
      }
    }
  }, {
    key: "hookModuleInitialization",
    value: function hookModuleInitialization(moduleName, callback) {
      if (!utils_1.Utils.isString(moduleName) || utils_1.Utils.isDefined(LogicInitialization.nativeModuleInitializationCallbacks[moduleName])) {
        return false;
      }

      LogicInitialization.nativeModuleInitializationCallbacks[moduleName] = callback;
      return true;
    }
  }, {
    key: "putModuleInitializationBreakpoint",
    value: function putModuleInitializationBreakpoint(moduleName) {
      var applied = LogicInitialization.hookModuleInitialization(moduleName, null);

      if (applied) {
        dwarf_1.Dwarf.loggedSend('module_initialization_callback:::' + moduleName);
      }

      return applied;
    }
  }, {
    key: "removeModuleInitializationBreakpoint",
    value: function removeModuleInitializationBreakpoint(moduleName) {
      if (typeof LogicInitialization.nativeModuleInitializationCallbacks[moduleName] !== 'undefined') {
        delete LogicInitialization.nativeModuleInitializationCallbacks[moduleName];
        return true;
      }

      return false;
    }
  }]);
  return LogicInitialization;
}();

LogicInitialization.nativeModuleInitializationCallbacks = {};
exports.LogicInitialization = LogicInitialization;

},{"./api":96,"./dwarf":98,"./logic_breakpoint":102,"./logic_java":104,"./utils":112,"@babel/runtime-corejs2/core-js/json/stringify":2,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/core-js/object/keys":6,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/createClass":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],104:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _getOwnPropertyNames = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/get-own-property-names"));

var _stringify = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/json/stringify"));

var _typeof2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/typeof"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var breakpoint_1 = require("./breakpoint");

var dwarf_1 = require("./dwarf");

var logic_breakpoint_1 = require("./logic_breakpoint");

var utils_1 = require("./utils");

var isDefined = utils_1.Utils.isDefined;

var LogicJava =
/*#__PURE__*/
function () {
  function LogicJava() {
    (0, _classCallCheck2["default"])(this, LogicJava);
  }

  (0, _createClass2["default"])(LogicJava, null, [{
    key: "applyTracerImplementation",
    value: function applyTracerImplementation(attach, callback) {
      Java.performNow(function () {
        LogicJava.tracedClasses.forEach(function (className) {
          try {
            var clazz = Java.use(className);
            var overloadCount = clazz["$init"].overloads.length;

            if (overloadCount > 0) {
              for (var i = 0; i < overloadCount; i++) {
                if (attach) {
                  clazz["$init"].overloads[i].implementation = LogicJava.traceImplementation(callback, className, '$init');
                } else {
                  clazz["$init"].overloads[i].implementation = null;
                }
              }
            }

            var methods = clazz["class"].getDeclaredMethods();
            var parsedMethods = [];
            methods.forEach(function (method) {
              parsedMethods.push(method.toString().replace(className + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
            });
            methods = utils_1.Utils.uniqueBy(parsedMethods);
            methods.forEach(function (method) {
              var overloadCount = clazz[method].overloads.length;

              if (overloadCount > 0) {
                for (var _i = 0; _i < overloadCount; _i++) {
                  if (attach) {
                    clazz[method].overloads[_i].implementation = LogicJava.traceImplementation(callback, className, method);
                  } else {
                    clazz[method].overloads[_i].implementation = null;
                  }
                }
              }
            });
            clazz.$dispose();
          } catch (e) {
            utils_1.Utils.logErr('LogicJava.startTrace', e);
          }
        });
      });
    }
  }, {
    key: "backtrace",
    value: function backtrace() {
      return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }
  }, {
    key: "getApplicationContext",
    value: function getApplicationContext() {
      if (!LogicJava.available) {
        return;
      }

      var ActivityThread = Java.use('android.app.ActivityThread');
      var Context = Java.use('android.content.Context');
      var context = Java.cast(ActivityThread.currentApplication().getApplicationContext(), Context);
      ActivityThread.$dispose();
      Context.$dispose();
      return context;
    }
  }, {
    key: "hook",
    value: function hook(className, method, implementation) {
      if (!LogicJava.available) {
        return false;
      }

      Java.performNow(function () {
        LogicJava.hookInJVM(className, method, implementation);
      });
      return true;
    }
  }, {
    key: "hookAllJavaMethods",
    value: function hookAllJavaMethods(className, implementation) {
      if (!Java.available) {
        return false;
      }

      if (!utils_1.Utils.isDefined(className)) {
        return false;
      }

      var that = this;
      Java.performNow(function () {
        var clazz = Java.use(className);
        var methods = clazz["class"].getDeclaredMethods();
        var parsedMethods = [];
        methods.forEach(function (method) {
          parsedMethods.push(method.toString().replace(className + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
        });
        var result = utils_1.Utils.uniqueBy(parsedMethods);
        result.forEach(function (method) {
          LogicJava.hookInJVM(className, method, implementation);
        });
        clazz.$dispose();
      });
      return true;
    }
  }, {
    key: "hookClassLoaderClassInitialization",
    value: function hookClassLoaderClassInitialization(clazz, callback) {
      if (!utils_1.Utils.isString(clazz) || utils_1.Utils.isDefined(LogicJava.javaClassLoaderCallbacks[clazz])) {
        return false;
      }

      LogicJava.javaClassLoaderCallbacks[clazz] = callback;
      return true;
    }
  }, {
    key: "hookInJVM",
    value: function hookInJVM(className, method, implementation) {
      var handler = null;

      try {
        handler = Java.use(className);
      } catch (err) {
        try {
          className = className + '.' + method;
          method = '$init';
          handler = Java.use(className);
        } catch (err) {}

        utils_1.Utils.logErr('LogicJava.hook', err);

        if (handler === null) {
          return;
        }
      }

      try {
        if (handler == null || typeof handler[method] === 'undefined') {
          return;
        }
      } catch (e) {
        // catching here not supported overload error from frida
        utils_1.Utils.logErr('LogicJava.hook', e);
        return;
      }

      var overloadCount = handler[method].overloads.length;

      if (overloadCount > 0) {
        var _loop = function _loop(i) {
          var overload = handler[method].overloads[i];

          if (utils_1.Utils.isDefined(implementation)) {
            overload.implementation = function () {
              LogicJava.javaContexts[Process.getCurrentThreadId()] = this;
              this.className = className;
              this.method = method;
              this.overload = overload;
              var ret = implementation.apply(this, arguments);

              if (typeof ret !== 'undefined') {
                return ret;
              }

              delete LogicJava.javaContexts[Process.getCurrentThreadId()];
              return this.overload.apply(this, arguments);
            };
          } else {
            overload.implementation = implementation;
          }
        };

        for (var i = 0; i < overloadCount; i++) {
          _loop(i);
        }
      }

      handler.$dispose();
    }
  }, {
    key: "hookJavaMethod",
    value: function hookJavaMethod(targetClassMethod, implementation) {
      if (utils_1.Utils.isDefined(targetClassMethod)) {
        var delim = targetClassMethod.lastIndexOf(".");

        if (delim === -1) {
          return false;
        }

        var targetClass = targetClassMethod.slice(0, delim);
        var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);
        LogicJava.hook(targetClass, targetMethod, implementation);
        return true;
      }

      return false;
    }
  }, {
    key: "init",
    value: function init() {
      Java.performNow(function () {
        LogicJava.sdk = Java.use('android.os.Build$VERSION')['SDK_INT']['value'];

        if (dwarf_1.Dwarf.DEBUG) {
          utils_1.Utils.logDebug('[' + Process.getCurrentThreadId() + '] ' + 'initializing logicJava with sdk: ' + LogicJava.sdk);
        }

        if (dwarf_1.Dwarf.SPAWNED && dwarf_1.Dwarf.BREAK_START) {
          if (LogicJava.sdk >= 23) {
            // attach to commonInit for init debugging
            LogicJava.hookInJVM('com.android.internal.os.RuntimeInit', 'commonInit', function () {
              LogicJava.jvmBreakpoint.call(this, 'com.android.internal.os.RuntimeInit', 'commonInit', arguments, this.overload.argumentTypes);
            });
          } else {
            LogicJava.hookInJVM('android.app.Application', 'onCreate', function () {
              LogicJava.jvmBreakpoint.call(this, 'android.app.Application', 'onCreate', arguments, this.overload.argumentTypes);
            });
          }
        } // attach to ClassLoader to notify for new loaded class


        var handler = Java.use('java.lang.ClassLoader');
        var overload = handler.loadClass.overload('java.lang.String', 'boolean');

        overload.implementation = function (clazz, resolve) {
          if (LogicJava.javaClasses.indexOf(clazz) === -1) {
            LogicJava.javaClasses.push(clazz);
            dwarf_1.Dwarf.loggedSend('class_loader_loading_class:::' + Process.getCurrentThreadId() + ':::' + clazz);
            var userCallback = LogicJava.javaClassLoaderCallbacks[clazz];

            if (typeof userCallback !== 'undefined') {
              if (userCallback !== null) {
                userCallback.call(this);
              } else {
                dwarf_1.Dwarf.loggedSend("java_class_initialization_callback:::" + clazz + ':::' + Process.getCurrentThreadId());
                logic_breakpoint_1.LogicBreakpoint.breakpoint(logic_breakpoint_1.LogicBreakpoint.REASON_BREAKPOINT, clazz, {}, this);
              }
            }
          }

          return overload.call(this, clazz, resolve);
        };
      });
    }
  }, {
    key: "jvmBreakpoint",
    value: function jvmBreakpoint(className, method, args, types, condition) {
      var classMethod = className + '.' + method;
      var newArgs = {};

      for (var i = 0; i < args.length; i++) {
        var value = '';

        if (args[i] === null || typeof args[i] === 'undefined') {
          value = 'null';
        } else {
          if ((0, _typeof2["default"])(args[i]) === 'object') {
            value = (0, _stringify["default"])(args[i]);

            if (types[i]['className'] === '[B') {
              value += ' (' + Java.use('java.lang.String').$new(args[i]) + ")";
            }
          } else {
            value = args[i].toString();
          }
        }

        newArgs[i] = {
          arg: value,
          name: types[i]['name'],
          handle: args[i],
          className: types[i]['className']
        };
      }

      logic_breakpoint_1.LogicBreakpoint.breakpoint(logic_breakpoint_1.LogicBreakpoint.REASON_BREAKPOINT, classMethod, newArgs, this, condition);
    }
  }, {
    key: "jvmExplorer",
    value: function jvmExplorer(what) {
      var handle;

      if (typeof what === 'undefined') {
        // flush handles
        LogicJava.javaHandles = {};
        handle = LogicJava.javaContexts[Process.getCurrentThreadId()];

        if (!isDefined(handle)) {
          console.log('jvm explorer outside context scope');
          return null;
        }
      } else if ((0, _typeof2["default"])(what) === 'object') {
        if (typeof what['handle_class'] !== 'undefined') {
          var cl = Java.use(what['handle_class']);
          handle = what['handle'];

          if (typeof handle === 'string') {
            handle = LogicJava.javaHandles[handle];

            if (typeof handle === 'undefined') {
              return null;
            }
          } else if ((0, _typeof2["default"])(handle) === 'object') {
            try {
              handle = Java.cast(ptr(handle['$handle']), cl);
            } catch (e) {
              utils_1.Utils.logErr('jvmExplorer', e + ' | ' + handle['$handle']);
              return null;
            }
          } else {
            try {
              handle = Java.cast(ptr(handle), cl);
            } catch (e) {
              utils_1.Utils.logErr('jvmExplorer', e + ' | ' + handle);
              return null;
            }
          }

          cl.$dispose();
        } else {
          handle = what;
        }
      } else {
        console.log('Explorer handle not found');
        return {};
      }

      if (handle === null || typeof handle === 'undefined') {
        console.log('Explorer handle null');
        return {};
      }

      var ol;

      try {
        ol = (0, _getOwnPropertyNames["default"])(handle.__proto__);
      } catch (e) {
        utils_1.Utils.logErr('jvmExplorer-1', e);
        return null;
      }

      var clazz = '';

      if (typeof handle['$className'] !== 'undefined') {
        clazz = handle['$className'];
      }

      var ret = {
        'class': clazz,
        'data': {}
      };

      for (var o in ol) {
        var name = ol[o];

        try {
          var overloads = [];
          var t = (0, _typeof2["default"])(handle[name]);
          var value = '';
          var sub_handle = null;
          var sub_handle_class = '';

          if (t === 'function') {
            if (typeof handle[name].overloads !== 'undefined') {
              var overloadCount = handle[name].overloads.length;

              if (overloadCount > 0) {
                for (var i in handle[name].overloads) {
                  overloads.push({
                    'args': handle[name].overloads[i].argumentTypes,
                    'return': handle[name].overloads[i].returnType
                  });
                }
              }
            }
          } else if (t === 'object') {
            if (handle[name] !== null) {
              sub_handle_class = handle[name]['$className'];
            }

            if (typeof handle[name]['$handle'] !== 'undefined' && handle[name]['$handle'] !== null) {
              value = handle[name]['$handle'];
              sub_handle = handle[name]['$handle'];
            } else {
              if (handle[name] !== null && handle[name]['value'] !== null) {
                sub_handle_class = handle[name]['value']['$className'];
              }

              if (handle[name] !== null && handle[name]['value'] !== null && (0, _typeof2["default"])(handle[name]['value']) === 'object') {
                if (typeof handle[name]['fieldReturnType'] !== 'undefined') {
                  sub_handle = handle[name]['value'];

                  if (typeof sub_handle['$handle'] !== 'undefined') {
                    var pt = sub_handle['$handle'];
                    LogicJava.javaHandles[pt] = sub_handle;
                    sub_handle = pt;
                    value = handle[name]['fieldReturnType']['className'];
                    sub_handle_class = value;
                  } else {
                    t = handle[name]['fieldReturnType']['type'];
                    sub_handle_class = handle[name]['fieldReturnType']['className'];

                    if (handle[name]['fieldReturnType']['type'] !== 'pointer') {
                      value = sub_handle_class;
                    } else {
                      if (handle[name]['value'] !== null) {
                        value = handle[name]['value'].toString();
                        t = (0, _typeof2["default"])(value);
                      }
                    }
                  }
                } else if (handle[name]['value'] !== null) {
                  value = handle[name]['value'].toString();
                  t = (0, _typeof2["default"])(value);
                }
              } else if (handle[name]['value'] !== null) {
                t = (0, _typeof2["default"])(handle[name]['value']);
                value = handle[name]['value'].toString();
              }
            }
          } else {
            value = handle[name];
          }

          ret['data'][name] = {
            'value': value,
            'handle': sub_handle,
            'handle_class': sub_handle_class,
            'type': t,
            'overloads': overloads
          };
        } catch (e) {
          utils_1.Utils.logErr('jvmExplorer-2', e);
        }
      }

      return ret;
    }
  }, {
    key: "putBreakpoint",
    value: function putBreakpoint(target, condition) {
      if (!utils_1.Utils.isString(target) || utils_1.Utils.isDefined(LogicJava.breakpoints[target])) {
        return false;
      }

      var breakpoint = new breakpoint_1.Breakpoint(target);

      if (!utils_1.Utils.isDefined(condition)) {
        condition = null;
      }

      breakpoint.condition = condition;
      LogicJava.breakpoints[target] = breakpoint;

      if (target.endsWith('.$init')) {
        LogicJava.hook(target, '$init', function () {
          LogicJava.jvmBreakpoint(this.className, this.method, arguments, this.overload.argumentTypes, condition);
        });
      } else {
        LogicJava.hookJavaMethod(target, function () {
          LogicJava.jvmBreakpoint(this.className, this.method, arguments, this.overload.argumentTypes, condition);
        });
      }

      return true;
    }
  }, {
    key: "putJavaClassInitializationBreakpoint",
    value: function putJavaClassInitializationBreakpoint(className) {
      var applied = LogicJava.hookClassLoaderClassInitialization(className, null);

      if (applied) {
        dwarf_1.Dwarf.loggedSend('java_class_initialization_callback:::' + className);
      }

      return applied;
    }
  }, {
    key: "removeBreakpoint",
    value: function removeBreakpoint(target) {
      if (!utils_1.Utils.isString(target)) {
        return false;
      }

      var breakpoint = LogicJava.breakpoints[target];

      if (utils_1.Utils.isDefined(breakpoint)) {
        delete logic_breakpoint_1.LogicBreakpoint.breakpoints[target.toString()];
        LogicJava.hookJavaMethod(breakpoint.target, null);
        return true;
      }

      return false;
    }
  }, {
    key: "removeModuleInitializationBreakpoint",
    value: function removeModuleInitializationBreakpoint(clazz) {
      if (typeof LogicJava.javaClassLoaderCallbacks[clazz] !== 'undefined') {
        delete LogicJava.javaClassLoaderCallbacks[clazz];
        return true;
      }

      return false;
    }
  }, {
    key: "restartApplication",
    value: function restartApplication() {
      if (!LogicJava.available) {
        return false;
      }

      Java.performNow(function () {
        var Intent = Java.use('android.content.Intent');
        var ctx = LogicJava.getApplicationContext();
        var intent = ctx.getPackageManager().getLaunchIntentForPackage(ctx.getPackageName());
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP['value']);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK['value']);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK['value']);
        ctx.startActivity(intent);
      });
      return true;
    }
  }, {
    key: "startTrace",
    value: function startTrace(classes, callback) {
      if (!LogicJava.available || LogicJava.tracing) {
        return false;
      }

      LogicJava.tracing = true;
      LogicJava.tracedClasses = classes;
      LogicJava.applyTracerImplementation(true, callback);
      return true;
    }
  }, {
    key: "stopTrace",
    value: function stopTrace() {
      if (!LogicJava.available || !LogicJava.tracing) {
        return false;
      }

      LogicJava.tracing = false;
      LogicJava.applyTracerImplementation(true);
      return true;
    }
  }, {
    key: "traceImplementation",
    value: function traceImplementation(callback, className, method) {
      return function () {
        var uiCallback = !utils_1.Utils.isDefined(callback);
        var classMethod = className + '.' + method;

        if (uiCallback) {
          dwarf_1.Dwarf.loggedSend('java_trace:::enter:::' + classMethod + ':::' + (0, _stringify["default"])(arguments));
        } else {
          if (utils_1.Utils.isDefined(callback['onEnter'])) {
            callback['onEnter'](arguments);
          }
        }

        var ret = this[method].apply(this, arguments);

        if (uiCallback) {
          var traceRet = ret;

          if ((0, _typeof2["default"])(traceRet) === 'object') {
            traceRet = (0, _stringify["default"])(ret);
          } else if (typeof traceRet === 'undefined') {
            traceRet = "";
          }

          dwarf_1.Dwarf.loggedSend('java_trace:::leave:::' + classMethod + ':::' + traceRet);
        } else {
          if (utils_1.Utils.isDefined(callback['onLeave'])) {
            var tempRet = callback['onLeave'](ret);

            if (typeof tempRet !== 'undefined') {
              ret = tempRet;
            }
          }
        }

        return ret;
      };
    }
  }]);
  return LogicJava;
}();

LogicJava.available = Java.available;
LogicJava.breakpoints = {};
LogicJava.javaClasses = [];
LogicJava.javaClassLoaderCallbacks = {};
LogicJava.javaContexts = {};
LogicJava.javaHandles = {};
LogicJava.tracedClasses = [];
LogicJava.tracing = false;
LogicJava.sdk = 0;
exports.LogicJava = LogicJava;

},{"./breakpoint":97,"./dwarf":98,"./logic_breakpoint":102,"./utils":112,"@babel/runtime-corejs2/core-js/json/stringify":2,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/core-js/object/get-own-property-names":5,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/createClass":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":12,"@babel/runtime-corejs2/helpers/typeof":13}],105:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var breakpoint_1 = require("./breakpoint");

var dwarf_1 = require("./dwarf");

var logic_breakpoint_1 = require("./logic_breakpoint");

var utils_1 = require("./utils");

var LogicObjC =
/*#__PURE__*/
function () {
  function LogicObjC() {
    (0, _classCallCheck2["default"])(this, LogicObjC);
  }

  (0, _createClass2["default"])(LogicObjC, null, [{
    key: "applyTracerImplementation",
    value: function applyTracerImplementation(attach, callback) {
      /*ObjC.performNow(() => {
          LogicObjC.tracedClasses.forEach((className) => {
              try {
                  const clazz = ObjC.use(className);
                    const overloadCount = clazz["$init"].overloads.length;
                  if (overloadCount > 0) {
                      for (let i = 0; i < overloadCount; i++) {
                          if (attach) {
                              clazz["$init"].overloads[i].implementation =
                                  LogicObjC.traceImplementation(callback, className, '$init');
                          } else {
                              clazz["$init"].overloads[i].implementation = null;
                          }
                      }
                  }
                    let methods = clazz.class.getDeclaredMethods();
                  const parsedMethods = [];
                  methods.forEach(function (method) {
                      parsedMethods.push(method.toString().replace(className + ".",
                          "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
                  });
                  methods = Utils.uniqueBy(parsedMethods);
                  methods.forEach((method) => {
                      const overloadCount = clazz[method].overloads.length;
                      if (overloadCount > 0) {
                          for (let i = 0; i < overloadCount; i++) {
                              if (attach) {
                                  clazz[method].overloads[i].implementation =
                                      LogicObjC.traceImplementation(callback, className, method);
                              } else {
                                  clazz[method].overloads[i].implementation = null;
                              }
                          }
                      }
                  });
                    clazz.$dispose();
              } catch (e) {
                  Utils.logErr('LogicObjC.startTrace', e);
              }
          });
      });*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
    }
  }, {
    key: "backtrace",
    value: function backtrace() {
      /*return ObjC.use("android.util.Log")
          .getStackTraceString(ObjC.use("objc.lang.Exception").$new());*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
    }
  }, {
    key: "getApplicationContext",
    value: function getApplicationContext() {
      /*if (!LogicObjC.available) {
          return;
      }
        const ActivityThread = ObjC.use('android.app.ActivityThread');
      const Context = ObjC.use('android.content.Context');
        const context = ObjC.cast(ActivityThread.currentApplication().getApplicationContext(), Context);
        ActivityThread.$dispose();
      Context.$dispose();
        return context;*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
    }
  }, {
    key: "hookAllObjCMethods",
    value: function hookAllObjCMethods(className, implementation) {
      /*if (!ObjC.available) {
          return false;
      }
        if (!Utils.isDefined(className)) {
          return false;
      }
        const that = this;
        ObjC.performNow(function () {
          const clazz = ObjC.use(className);
          const methods = clazz.class.getDeclaredMethods();
            const parsedMethods = [];
          methods.forEach(function (method) {
              parsedMethods.push(method.toString().replace(className + ".",
                  "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
          });
          const result = Utils.uniqueBy(parsedMethods);
          result.forEach(method => {
              LogicObjC.hook(className, method, implementation);
          });
          clazz.$dispose();
      });
      return true;*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
      return false;
    }
  }, {
    key: "hookClassLoaderClassInitialization",
    value: function hookClassLoaderClassInitialization(clazz, callback) {
      /*if (!Utils.isString(clazz) || Utils.isDefined(LogicObjC.objcClassLoaderCallbacks[clazz])) {
          return false;
      }
        LogicObjC.objcClassLoaderCallbacks[clazz] = callback;
      return true;*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
      return false;
    }
  }, {
    key: "hook",
    value: function hook(className, method, implementation) {
      if (!LogicObjC.available) {
        return false;
      }

      var handler = ObjC.classes[className];

      try {
        handler = ObjC.classes[className];
      } catch (err) {
        utils_1.Utils.logErr('LogicObjC.hook', err);

        if (handler === null) {
          return;
        }
      }

      try {
        if (handler == null || typeof handler[method] === 'undefined') {
          return;
        }
      } catch (e) {
        // catching here not supported overload error from frida
        utils_1.Utils.logErr('LogicObjC.hook', e);
        return;
      }

      var overloadCount = handler[method].overloads.length;

      if (overloadCount > 0) {
        var _loop = function _loop(i) {
          var overload = handler[method].overloads[i];

          if (utils_1.Utils.isDefined(implementation)) {
            overload.implementation = function () {
              LogicObjC.objcContexts[Process.getCurrentThreadId()] = this;
              this.className = className;
              this.method = method;
              this.overload = overload;
              var ret = implementation.apply(this, arguments);

              if (typeof ret !== 'undefined') {
                return ret;
              }

              delete LogicObjC.objcContexts[Process.getCurrentThreadId()];
              return this.overload.apply(this, arguments);
            };
          } else {
            overload.implementation = implementation;
          }
        };

        for (var i = 0; i < overloadCount; i++) {
          _loop(i);
        }
      }

      return true;
    }
  }, {
    key: "hookObjCMethod",
    value: function hookObjCMethod(targetClassMethod, implementation) {
      if (utils_1.Utils.isDefined(targetClassMethod)) {
        var delim = targetClassMethod.indexOf(".");

        if (delim === -1) {
          return false;
        }

        var targetClass = targetClassMethod.slice(0, delim);
        var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);
        LogicObjC.hook(targetClass, targetMethod, implementation);
        return true;
      }

      return false;
    }
  }, {
    key: "init",
    value: function init() {
      /*
          LogicObjC.sdk = ObjC.use('android.os.Build$VERSION')['SDK_INT']['value'];
          if (Dwarf.DEBUG) {
              Utils.logDebug('[' + Process.getCurrentThreadId() + '] ' +
                  'initializing logicObjC with sdk: ' + LogicObjC.sdk);
          }
            if (Dwarf.SPAWNED && Dwarf.BREAK_START) {
              if (LogicObjC.sdk >= 23) {
                  // attach to commonInit for init debugging
                  LogicObjC.hook('com.android.internal.os.RuntimeInit',
                      'commonInit', function () {
                          LogicObjC.jvmBreakpoint.call(this, 'com.android.internal.os.RuntimeInit',
                          'commonInit', arguments, this.overload.argumentTypes)
                  });
              } else {
                  LogicObjC.hook('android.app.Application', 'onCreate',
                      function () {
                          LogicObjC.jvmBreakpoint.call(this, 'android.app.Application',
                              'onCreate', arguments, this.overload.argumentTypes)
                      });
              }
          }
            // attach to ClassLoader to notify for new loaded class
          const handler = ObjC.use('objc.lang.ClassLoader');
          const overload = handler.loadClass.overload('objc.lang.String', 'boolean');
          overload.implementation = function(clazz, resolve) {
              if (LogicObjC.objcClasses.indexOf(clazz) === -1) {
                  LogicObjC.objcClasses.push(clazz);
                  Dwarf.loggedSend('class_loader_loading_class:::' + Process.getCurrentThreadId() + ':::' + clazz);
                    const userCallback = LogicObjC.objcClassLoaderCallbacks[clazz];
                  if (typeof userCallback !== 'undefined') {
                      if (userCallback !== null) {
                          userCallback.call(this);
                      } else {
                          Dwarf.loggedSend("objc_class_initialization_callback:::" + clazz + ':::' + Process.getCurrentThreadId());
                          LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_BREAKPOINT, clazz, {}, this);
                      }
                  }
              }
              return overload.call(this, clazz, resolve);
          };
      });*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
    }
  }, {
    key: "jvmBreakpoint",
    value: function jvmBreakpoint(className, method, args, types, condition) {
      /*const classMethod = className + '.' + method;
      const newArgs = {};
      for (let i = 0; i < args.length; i++) {
          let value = '';
          if (args[i] === null || typeof args[i] === 'undefined') {
              value = 'null';
          } else {
              if (typeof args[i] === 'object') {
                  value = JSON.stringify(args[i]);
                  if (types[i]['className'] === '[B') {
                      value += ' (' + ObjC.use('objc.lang.String').$new(args[i]) + ")";
                  }
              } else {
                  value = args[i].toString();
              }
          }
          newArgs[i] = {
              arg: value,
              name: types[i]['name'],
              handle: args[i],
              className: types[i]['className'],
          }
      }
        LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_BREAKPOINT, classMethod, newArgs, this, condition);*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
    }
  }, {
    key: "jvmExplorer",
    value: function jvmExplorer(what) {
      /*let handle;
      if (typeof what === 'undefined') {
          // flush handles
          LogicObjC.objcHandles = {};
            handle = LogicObjC.objcContexts[Process.getCurrentThreadId()];
          if (!isDefined(handle)) {
              console.log('jvm explorer outside context scope');
              return null;
          }
      } else if (typeof what === 'object') {
          if (typeof what['handle_class'] !== 'undefined') {
              const cl = ObjC.use(what['handle_class']);
              handle = what['handle'];
              if (typeof handle === 'string') {
                  handle = LogicObjC.objcHandles[handle];
                  if (typeof handle === 'undefined') {
                      return null;
                  }
              } else if (typeof handle === 'object') {
                  try {
                      handle = ObjC.cast(ptr(handle['$handle']), cl);
                  } catch (e) {
                      Utils.logErr('jvmExplorer', e + ' | ' + handle['$handle']);
                      return null;
                  }
              } else {
                  try {
                      handle = ObjC.cast(ptr(handle), cl);
                  } catch (e) {
                      Utils.logErr('jvmExplorer', e + ' | ' + handle);
                      return null;
                  }
              }
              cl.$dispose();
          } else {
              handle = what;
          }
      } else {
          console.log('Explorer handle not found');
          return {};
      }
      if (handle === null || typeof handle === 'undefined') {
          console.log('Explorer handle null');
          return {};
      }
      let ol;
      try {
          ol = Object.getOwnPropertyNames(handle.__proto__);
      } catch (e) {
          Utils.logErr('jvmExplorer-1', e);
          return null;
      }
      let clazz = '';
      if (typeof handle['$className'] !== 'undefined') {
          clazz = handle['$className'];
      }
      const ret = {
          'class': clazz,
          'data': {}
      };
      for (const o in ol) {
          const name = ol[o];
          try {
              const overloads = [];
              let t = typeof handle[name];
              let value = '';
              let sub_handle = null;
              let sub_handle_class = '';
                if (t === 'function') {
                  if (typeof handle[name].overloads !== 'undefined') {
                      const overloadCount = handle[name].overloads.length;
                      if (overloadCount > 0) {
                          for (const i in handle[name].overloads) {
                              overloads.push({
                                  'args': handle[name].overloads[i].argumentTypes,
                                  'return': handle[name].overloads[i].returnType
                              });
                          }
                      }
                  }
              } else if (t === 'object') {
                  if (handle[name] !== null) {
                      sub_handle_class = handle[name]['$className'];
                  }
                    if (typeof handle[name]['$handle'] !== 'undefined' && handle[name]['$handle'] !== null) {
                      value = handle[name]['$handle'];
                      sub_handle = handle[name]['$handle'];
                  } else {
                      if (handle[name] !== null && handle[name]['value'] !== null) {
                          sub_handle_class = handle[name]['value']['$className'];
                      }
                        if (handle[name] !== null && handle[name]['value'] !== null &&
                          typeof handle[name]['value'] === 'object') {
                          if (typeof handle[name]['fieldReturnType'] !== 'undefined') {
                              sub_handle = handle[name]['value'];
                              if (typeof sub_handle['$handle'] !== 'undefined') {
                                  const pt = sub_handle['$handle'];
                                  LogicObjC.objcHandles[pt] = sub_handle;
                                  sub_handle = pt;
                                  value = handle[name]['fieldReturnType']['className'];
                                  sub_handle_class = value;
                              } else {
                                  t = handle[name]['fieldReturnType']['type'];
                                  sub_handle_class = handle[name]['fieldReturnType']['className'];
                                    if (handle[name]['fieldReturnType']['type'] !== 'pointer') {
                                      value = sub_handle_class;
                                  } else {
                                      if (handle[name]['value'] !== null) {
                                          value = handle[name]['value'].toString();
                                          t = typeof (value);
                                      }
                                  }
                              }
                          } else if (handle[name]['value'] !== null) {
                              value = handle[name]['value'].toString();
                              t = typeof (value);
                          }
                      } else if (handle[name]['value'] !== null) {
                          t = typeof (handle[name]['value']);
                          value = handle[name]['value'].toString();
                      }
                  }
              } else {
                  value = handle[name];
              }
                ret['data'][name] = {
                  'value': value,
                  'handle': sub_handle,
                  'handle_class': sub_handle_class,
                  'type': t,
                  'overloads': overloads
              };
          } catch (e) {
              Utils.logErr('jvmExplorer-2', e);
          }
      }
      return ret;*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
    }
  }, {
    key: "putBreakpoint",
    value: function putBreakpoint(target, condition) {
      if (!utils_1.Utils.isString(target) || utils_1.Utils.isDefined(LogicObjC.breakpoints[target])) {
        return false;
      }

      var parts = target.split('.');
      var targetAddress = ptr(ObjC.classes[parts[0]][parts[1]].implementation.toString());
      var breakpoint = new breakpoint_1.Breakpoint(targetAddress);

      if (!utils_1.Utils.isDefined(condition)) {
        condition = null;
      }

      breakpoint.condition = condition;
      LogicObjC.breakpoints[target] = breakpoint;
      return LogicObjC.putObjCBreakpoint(breakpoint, target);
    }
  }, {
    key: "putObjCBreakpoint",
    value: function putObjCBreakpoint(breakpoint, target) {
      breakpoint.interceptor = Interceptor.attach(breakpoint.target, function () {
        breakpoint.interceptor.detach();
        Interceptor['flush']();
        logic_breakpoint_1.LogicBreakpoint.breakpoint(logic_breakpoint_1.LogicBreakpoint.REASON_BREAKPOINT, this.context.pc, this.context, null, breakpoint.condition);

        if (typeof LogicObjC.breakpoints[target] !== 'undefined') {
          LogicObjC.putObjCBreakpoint(breakpoint, target);
        }
      });
      return true;
    }
  }, {
    key: "putObjCClassInitializationBreakpoint",
    value: function putObjCClassInitializationBreakpoint(className) {
      /*const applied = LogicObjC.hookClassLoaderClassInitialization(className, null);
      if (applied) {
          Dwarf.loggedSend('objc_class_initialization_callback:::' + className);
      }
      return applied;*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
      return false;
    }
  }, {
    key: "removeBreakpoint",
    value: function removeBreakpoint(target) {
      if (!utils_1.Utils.isString(target)) {
        return false;
      }

      var breakpoint = LogicObjC.breakpoints[target];

      if (utils_1.Utils.isDefined(breakpoint)) {
        breakpoint.interceptor.detach();
        delete LogicObjC.breakpoints[target.toString()]; //LogicObjC.hookObjCMethod(target, null);

        return true;
      }

      return false;
    }
  }, {
    key: "removeModuleInitializationBreakpoint",
    value: function removeModuleInitializationBreakpoint(clazz) {
      /*if (typeof LogicObjC.objcClassLoaderCallbacks[clazz] !== 'undefined') {
          delete LogicObjC.objcClassLoaderCallbacks[clazz];
          return true;
      }
        return false;*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
    }
  }, {
    key: "restartApplication",
    value: function restartApplication() {
      /*if (!LogicObjC.available) {
          return false;
      }
        ObjC.performNow(function () {
          const Intent = ObjC.use('android.content.Intent');
          const ctx = LogicObjC.getApplicationContext();
          const intent = ctx.getPackageManager().getLaunchIntentForPackage(ctx.getPackageName());
          intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP['value']);
          intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK['value']);
          intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK['value']);
          ctx.startActivity(intent);
      });
      return true;*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
      return false;
    }
  }, {
    key: "startTrace",
    value: function startTrace(classes, callback) {
      /*if (!LogicObjC.available || LogicObjC.tracing) {
          return false;
      }
        LogicObjC.tracing = true;
      LogicObjC.tracedClasses = classes;
      LogicObjC.applyTracerImplementation(true, callback);
        return true;*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
      return false;
    }
  }, {
    key: "stopTrace",
    value: function stopTrace() {
      /*if (!LogicObjC.available || !LogicObjC.tracing) {
          return false;
      }
        LogicObjC.tracing = false;
      LogicObjC.applyTracerImplementation(true);
        return true;*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
      return false;
    }
  }, {
    key: "traceImplementation",
    value: function traceImplementation(callback, className, method) {
      /*return function () {
          const uiCallback = !Utils.isDefined(callback);
          const classMethod = className + '.' + method;
            if (uiCallback) {
              Dwarf.loggedSend('objc_trace:::enter:::' + classMethod + ':::' + JSON.stringify(arguments));
          } else {
              if (Utils.isDefined(callback['onEnter'])) {
                  callback['onEnter'](arguments);
              }
          }
            let ret = this[method].apply(this, arguments);
            if (uiCallback) {
              let traceRet = ret;
              if (typeof traceRet === 'object') {
                  traceRet = JSON.stringify(ret);
              } else if (typeof traceRet === 'undefined') {
                  traceRet = "";
              }
              Dwarf.loggedSend('objc_trace:::leave:::' + classMethod + ':::' + traceRet);
          } else {
              if (Utils.isDefined(callback['onLeave'])) {
                  let tempRet = callback['onLeave'](ret);
                  if (typeof tempRet !== 'undefined') {
                      ret = tempRet;
                  }
              }
          }
          return ret;
      }*/
      dwarf_1.Dwarf.loggedSend('Not implemented');
    }
  }]);
  return LogicObjC;
}();

LogicObjC.available = ObjC.available;
LogicObjC.breakpoints = {};
LogicObjC.objcClasses = [];
LogicObjC.objcClassLoaderCallbacks = {};
LogicObjC.objcContexts = {};
LogicObjC.objcHandles = {};
LogicObjC.tracedClasses = [];
LogicObjC.tracing = false;
LogicObjC.sdk = 0;
exports.LogicObjC = LogicObjC;

},{"./breakpoint":97,"./dwarf":98,"./logic_breakpoint":102,"./utils":112,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/createClass":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],106:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _parseInt2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/parse-int"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var dwarf_1 = require("./dwarf");

var logic_breakpoint_1 = require("./logic_breakpoint");

var stalker_info_1 = require("./stalker_info");

var utils_1 = require("./utils");

var LogicStalker =
/*#__PURE__*/
function () {
  function LogicStalker() {
    (0, _classCallCheck2["default"])(this, LogicStalker);
  }

  (0, _createClass2["default"])(LogicStalker, null, [{
    key: "hitPreventRelease",
    value: function hitPreventRelease() {
      var tid = Process.getCurrentThreadId();
      var threadContext = dwarf_1.Dwarf.threadContexts[tid];

      if (utils_1.Utils.isDefined(threadContext)) {
        threadContext.preventSleep = true;
      }
    }
  }, {
    key: "stalk",
    value: function stalk(threadId) {
      LogicStalker.hitPreventRelease();
      var arch = Process.arch;
      var isArm64 = arch === 'arm64';

      if (!isArm64 && arch !== 'x64') {
        console.log('stalker is not supported on current arch: ' + arch);
        return null;
      }

      var tid;

      if (utils_1.Utils.isDefined(threadId)) {
        tid = threadId;
      } else {
        tid = Process.getCurrentThreadId();
      }

      var stalkerInfo = LogicStalker.stalkerInfoMap[tid];

      if (!utils_1.Utils.isDefined(stalkerInfo)) {
        var context = dwarf_1.Dwarf.threadContexts[tid];

        if (!utils_1.Utils.isDefined(context)) {
          console.log('cant start stalker outside a valid native context');
          return null;
        }

        stalkerInfo = new stalker_info_1.StalkerInfo(tid);
        LogicStalker.stalkerInfoMap[tid] = stalkerInfo;
        var initialContextAddress = ptr((0, _parseInt2["default"])(context.pc)); // this will maybe be replaced in the future
        // when we start stepping, the first basic block is copied into frida space and executed there
        // we need to calculate when it is executed somehow

        var retCount = 0;
        var arm64BlockCount = 0;
        var firstInstructionExec = false;
        var firstBlockCallout = false;
        var calloutHandled = false;

        if (dwarf_1.Dwarf.DEBUG) {
          utils_1.Utils.logDebug('[' + tid + '] stalk: ' + 'attaching stalker');
        }

        Stalker.follow(tid, {
          transform: function transform(iterator) {
            var instruction;

            if (dwarf_1.Dwarf.DEBUG) {
              utils_1.Utils.logDebug('[' + tid + '] stalk: ' + 'transform begin');
            }

            while ((instruction = iterator.next()) !== null) {
              iterator.keep();

              if (instruction.groups.indexOf('jump') < 0 && instruction.groups.indexOf('call') < 0) {
                stalkerInfo.lastBlockInstruction = {
                  groups: instruction.groups,
                  address: instruction.address
                };
              } else {
                stalkerInfo.lastCallJumpInstruction = {
                  groups: instruction.groups,
                  address: instruction.address
                };
              }

              if (!calloutHandled) {
                if (retCount > 4) {
                  if (isArm64 && arm64BlockCount < 2) {
                    continue;
                  }

                  if (!firstInstructionExec) {
                    if (dwarf_1.Dwarf.DEBUG) {
                      utils_1.Utils.logDebug('[' + tid + '] stalk: ' + 'executing first instruction', instruction.address.toString(), instruction.toString());
                    }

                    stalkerInfo.initialContextAddress = initialContextAddress.add(instruction.size);
                    firstInstructionExec = true;
                    continue;
                  }

                  if (dwarf_1.Dwarf.DEBUG) {
                    utils_1.Utils.logDebug('[' + tid + '] stalk: ' + 'executing first basic block instructions', instruction.address.toString(), instruction.toString());
                  }

                  calloutHandled = true;
                  firstBlockCallout = true;
                  LogicStalker.putCalloutIfNeeded(iterator, stalkerInfo, instruction);
                }

                if (instruction.mnemonic === 'ret') {
                  retCount++;
                }
              } else {
                LogicStalker.putCalloutIfNeeded(iterator, stalkerInfo, instruction);
              }
            }

            if (dwarf_1.Dwarf.DEBUG) {
              utils_1.Utils.logDebug('[' + tid + '] stalk: ' + 'transform done');
            }

            if (stalkerInfo.terminated) {
              if (dwarf_1.Dwarf.DEBUG) {
                utils_1.Utils.logDebug('[' + tid + '] stopStep: ' + 'unfollowing tid');
              }

              Stalker.flush();
              Stalker.unfollow(tid);
              Stalker.garbageCollect();
              delete LogicStalker.stalkerInfoMap[stalkerInfo.tid];
            }

            if (retCount > 4 && isArm64) {
              arm64BlockCount += 1;
            }

            if (firstBlockCallout) {
              firstBlockCallout = false;
            }
          }
        });
      }

      return stalkerInfo;
    }
  }, {
    key: "putCalloutIfNeeded",
    value: function putCalloutIfNeeded(iterator, stalkerInfo, instruction) {
      var putCallout = true; // todo: add conditions

      if (putCallout) {
        if (dwarf_1.Dwarf.DEBUG) {
          utils_1.Utils.logDebug('[' + Process.getCurrentThreadId() + '] stalk: ' + 'executing instruction', instruction.address.toString(), instruction.toString());
        }

        iterator.putCallout(LogicStalker.stalkerCallout);
      }
    }
  }, {
    key: "stalkerCallout",
    value: function stalkerCallout(context) {
      var tid = Process.getCurrentThreadId();
      var stalkerInfo = LogicStalker.stalkerInfoMap[tid];

      if (!utils_1.Utils.isDefined(stalkerInfo) || stalkerInfo.terminated) {
        return;
      }

      var pc = context.pc;
      var insn = Instruction.parse(pc);

      if (dwarf_1.Dwarf.DEBUG) {
        utils_1.Utils.logDebug('[' + tid + '] stalkerCallout: ' + 'running callout', insn.address, insn.toString());
      }

      if (!stalkerInfo.didFistJumpOut) {
        pc = stalkerInfo.initialContextAddress;
        var lastInt = (0, _parseInt2["default"])(stalkerInfo.lastContextAddress);

        if (lastInt > 0) {
          var pcInt = (0, _parseInt2["default"])(context.pc);

          if (pcInt < lastInt || pcInt > lastInt + insn.size) {
            pc = context.pc;
            stalkerInfo.didFistJumpOut = true;
          }
        }
      }

      var shouldBreak = false;

      if (stalkerInfo.currentMode !== null) {
        if (typeof stalkerInfo.currentMode === 'function') {
          shouldBreak = false;
          var that = {
            context: context,
            instruction: insn,
            stop: function stop() {
              stalkerInfo.terminated = true;
            }
          };
          stalkerInfo.currentMode.apply(that);
        } else if (stalkerInfo.lastContextAddress !== null && stalkerInfo.lastCallJumpInstruction !== null) {
          if (dwarf_1.Dwarf.DEBUG) {
            utils_1.Utils.logDebug('[' + tid + '] stalkerCallout: ' + 'using mode ->', stalkerInfo.currentMode);
          } // call and jumps doesn't receive callout


          var isAddressBeforeJumpOrCall = (0, _parseInt2["default"])(context.pc) === (0, _parseInt2["default"])(stalkerInfo.lastBlockInstruction.address);

          if (isAddressBeforeJumpOrCall) {
            if (stalkerInfo.currentMode === 'call') {
              if (stalkerInfo.lastCallJumpInstruction.groups.indexOf('call') >= 0) {
                shouldBreak = true;
              }
            } else if (stalkerInfo.currentMode === 'block') {
              if (stalkerInfo.lastCallJumpInstruction.groups.indexOf('jump') >= 0) {
                shouldBreak = true;
              }
            }
          }
        }
      } else {
        shouldBreak = true;
      }

      if (shouldBreak) {
        stalkerInfo.context = context;
        stalkerInfo.lastContextAddress = context.pc;
        logic_breakpoint_1.LogicBreakpoint.breakpoint(logic_breakpoint_1.LogicBreakpoint.REASON_STEP, pc, stalkerInfo.context, null);

        if (dwarf_1.Dwarf.DEBUG) {
          utils_1.Utils.logDebug('[' + tid + '] callOut: ' + 'post onHook');
        }
      }

      if (!stalkerInfo.didFistJumpOut) {
        stalkerInfo.initialContextAddress = stalkerInfo.initialContextAddress.add(insn.size);
      }
    }
  }, {
    key: "strace",
    value: function strace(callback) {
      if (LogicStalker.straceCallback !== null) {
        return false;
      }

      LogicStalker.straceCallback = callback;

      if (typeof callback === 'function') {
        Process.enumerateThreads().forEach(function (thread) {
          Stalker.follow(thread.id, {
            transform: function transform(iterator) {
              var instruction;

              while ((instruction = iterator.next()) !== null) {
                iterator.keep();

                if (instruction.mnemonic === 'svc' || instruction.mnemonic === 'int') {
                  iterator.putCallout(LogicStalker.straceCallout);
                }
              }

              if (LogicStalker.straceCallback === null) {
                Stalker.flush();
                Stalker.unfollow(thread.id);
                Stalker.garbageCollect();
              }
            }
          });
        });
        return true;
      }

      return false;
    }
  }, {
    key: "straceCallout",
    value: function straceCallout(context) {
      var that = {
        context: context,
        instruction: Instruction.parse(context.pc),
        stop: function stop() {
          LogicStalker.straceCallback = null;
        }
      };
      LogicStalker.straceCallback.apply(that);
    }
  }]);
  return LogicStalker;
}();

LogicStalker.stalkerInfoMap = {};
LogicStalker.straceCallback = null;
exports.LogicStalker = LogicStalker;

},{"./dwarf":98,"./logic_breakpoint":102,"./stalker_info":108,"./utils":112,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/core-js/parse-int":7,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/createClass":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],107:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _stringify = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/json/stringify"));

var _keys = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/keys"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var dwarf_1 = require("./dwarf");

var watchpoint_1 = require("./watchpoint");

var utils_1 = require("./utils");

var logic_breakpoint_1 = require("./logic_breakpoint");

var isDefined = utils_1.Utils.isDefined;

var LogicWatchpoint =
/*#__PURE__*/
function () {
  function LogicWatchpoint() {
    (0, _classCallCheck2["default"])(this, LogicWatchpoint);
  }

  (0, _createClass2["default"])(LogicWatchpoint, null, [{
    key: "attachMemoryAccessMonitor",
    value: function attachMemoryAccessMonitor() {
      var monitorAddresses = [];
      (0, _keys["default"])(LogicWatchpoint.memoryWatchpoints).forEach(function (pt) {
        monitorAddresses.push({
          'base': ptr(pt),
          'size': 1
        });
      });
      MemoryAccessMonitor.enable(monitorAddresses, {
        onAccess: LogicWatchpoint.onMemoryAccess
      });
    }
  }, {
    key: "handleException",
    value: function handleException(exception) {
      var tid = Process.getCurrentThreadId();
      var watchpoint = null;

      if ((0, _keys["default"])(LogicWatchpoint.memoryWatchpoints).length > 0) {
        // make sure it's access violation
        if (exception['type'] === 'access-violation') {
          watchpoint = LogicWatchpoint.memoryWatchpoints[exception['memory']['address']];

          if (utils_1.Utils.isDefined(watchpoint)) {
            var operation = exception.memory.operation;

            if (utils_1.Utils.isDefined(operation)) {
              if (watchpoint.flags & watchpoint_1.MEMORY_ACCESS_READ && operation === 'read') {
                watchpoint.restore();
                dwarf_1.Dwarf.loggedSend('watchpoint:::' + (0, _stringify["default"])(exception) + ':::' + tid);
              } else if (watchpoint.flags & watchpoint_1.MEMORY_ACCESS_WRITE && operation === 'write') {
                watchpoint.restore();
                dwarf_1.Dwarf.loggedSend('watchpoint:::' + (0, _stringify["default"])(exception) + ':::' + tid);
              } else if (watchpoint.flags & watchpoint_1.MEMORY_ACCESS_EXECUTE && operation === 'execute') {
                watchpoint.restore();
                dwarf_1.Dwarf.loggedSend('watchpoint:::' + (0, _stringify["default"])(exception) + ':::' + tid);
              } else {
                watchpoint = null;
              }
            } else {
              watchpoint.restore();
              dwarf_1.Dwarf.loggedSend('watchpoint:::' + (0, _stringify["default"])(exception) + ':::' + tid);
            }
          } else {
            watchpoint = null;
          }
        }
      }

      if (watchpoint !== null) {
        var interceptor = Interceptor.attach(exception.address, function (args) {
          interceptor.detach();
          Interceptor['flush']();

          if (watchpoint.callback !== null) {
            watchpoint.callback.call(this, args);
          } else {
            logic_breakpoint_1.LogicBreakpoint.breakpoint(logic_breakpoint_1.LogicBreakpoint.REASON_WATCHPOINT, this.context.pc, this.context);
          }

          if (isDefined(LogicWatchpoint.memoryWatchpoints[exception.memory.address]) && !(watchpoint.flags & watchpoint_1.MEMORY_WATCH_SINGLE_SHOT)) {
            watchpoint.watch();
          }
        });
      }

      return watchpoint;
    }
  }, {
    key: "onMemoryAccess",
    value: function onMemoryAccess(details) {
      var tid = Process.getCurrentThreadId();
      var operation = details.operation; // 'read' - 'write' - 'execute'

      var fromPtr = details.from;
      var address = details.address;
      var watchpoint = null; // watchpoints

      if ((0, _keys["default"])(LogicWatchpoint.memoryWatchpoints).length > 0) {
        watchpoint = LogicWatchpoint.memoryWatchpoints[address];

        if (typeof watchpoint !== 'undefined') {
          var returnval = {
            'memory': {
              'operation': operation,
              'address': address
            }
          };

          if (watchpoint.flags & watchpoint_1.MEMORY_ACCESS_READ && operation === 'read') {
            MemoryAccessMonitor.disable();
            dwarf_1.Dwarf.loggedSend('watchpoint:::' + (0, _stringify["default"])(returnval) + ':::' + tid);
          } else if (watchpoint.flags & watchpoint_1.MEMORY_ACCESS_WRITE && operation === 'write') {
            MemoryAccessMonitor.disable();
            dwarf_1.Dwarf.loggedSend('watchpoint:::' + (0, _stringify["default"])(returnval) + ':::' + tid);
          } else if (watchpoint.flags & watchpoint_1.MEMORY_ACCESS_EXECUTE && operation === 'execute') {
            MemoryAccessMonitor.disable();
            dwarf_1.Dwarf.loggedSend('watchpoint:::' + (0, _stringify["default"])(returnval) + ':::' + tid);
          } else {
            watchpoint = null;
          }
        } else {
          watchpoint = null;
        }
      }

      if (watchpoint !== null) {
        var interceptor = Interceptor.attach(fromPtr, function (args) {
          interceptor.detach();
          Interceptor['flush']();

          if (watchpoint.callback !== null) {
            watchpoint.callback.call(this, args);
          } else {
            logic_breakpoint_1.LogicBreakpoint.breakpoint(logic_breakpoint_1.LogicBreakpoint.REASON_WATCHPOINT, this.context.pc, this.context);
          }

          if (isDefined(LogicWatchpoint.memoryWatchpoints[address]) && !(watchpoint.flags & watchpoint_1.MEMORY_WATCH_SINGLE_SHOT)) {
            LogicWatchpoint.attachMemoryAccessMonitor();
          }
        });
      }

      return watchpoint !== null;
    }
  }, {
    key: "putWatchpoint",
    value: function putWatchpoint(address, flags, callback) {
      address = ptr(address);
      var range;
      var watchpoint;

      if (typeof callback === 'undefined') {
        callback = null;
      } // default '--?'


      if (!utils_1.Utils.isNumber(flags)) {
        flags = watchpoint_1.MEMORY_ACCESS_READ | watchpoint_1.MEMORY_ACCESS_WRITE;
      }

      if (!utils_1.Utils.isDefined(LogicWatchpoint.memoryWatchpoints[address.toString()])) {
        range = Process.findRangeByAddress(address);

        if (range === null) {
          console.log('failed to find memory range for ' + address.toString());
          return null;
        }

        watchpoint = new watchpoint_1.Watchpoint(address, flags, range.protection, callback);
        LogicWatchpoint.memoryWatchpoints[address.toString()] = watchpoint;
        dwarf_1.Dwarf.loggedSend('watchpoint_added:::' + address.toString() + ':::' + flags + ':::' + (0, _stringify["default"])(watchpoint.debugSymbol));

        if (Process.platform === 'windows') {
          LogicWatchpoint.attachMemoryAccessMonitor();
        } else {
          if (watchpoint) {
            watchpoint.watch();
          }
        }

        return watchpoint;
      } else {
        console.log(address.toString() + ' is already watched');
        return null;
      }
    }
  }, {
    key: "removeWatchpoint",
    value: function removeWatchpoint(address) {
      address = ptr(address);
      var watchpoint = LogicWatchpoint.memoryWatchpoints[address.toString()];

      if (!utils_1.Utils.isDefined(watchpoint)) {
        return false;
      }

      watchpoint.restore();
      delete LogicWatchpoint.memoryWatchpoints[address.toString()];

      if (Process.platform === 'windows') {
        LogicWatchpoint.attachMemoryAccessMonitor();
      }

      dwarf_1.Dwarf.loggedSend('watchpoint_removed:::' + address.toString());
      return true;
    }
  }]);
  return LogicWatchpoint;
}();

LogicWatchpoint.memoryWatchpoints = {};
exports.LogicWatchpoint = LogicWatchpoint;

},{"./dwarf":98,"./logic_breakpoint":102,"./utils":112,"./watchpoint":113,"@babel/runtime-corejs2/core-js/json/stringify":2,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/core-js/object/keys":6,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/createClass":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],108:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var StalkerInfo = function StalkerInfo(tid) {
  (0, _classCallCheck2["default"])(this, StalkerInfo);
  this.context = null;
  this.initialContextAddress = NULL;
  this.lastContextAddress = NULL;
  this.didFistJumpOut = false;
  this.terminated = false;
  this.currentMode = null;
  this.lastBlockInstruction = null;
  this.lastCallJumpInstruction = null;
  this.tid = tid;
};

exports.StalkerInfo = StalkerInfo;

},{"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],109:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var ThreadApi = function ThreadApi(apiFunction, apiArguments) {
  (0, _classCallCheck2["default"])(this, ThreadApi);
  this.result = null;
  this.consumed = false;
  this.apiFunction = apiFunction;
  this.apiArguments = apiArguments;
};

exports.ThreadApi = ThreadApi;

},{"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],110:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var ThreadContext = function ThreadContext(tid) {
  (0, _classCallCheck2["default"])(this, ThreadContext);
  this.context = null;
  this.javaHandle = null;
  this.apiQueue = [];
  this.preventSleep = false;
  this.tid = tid;
};

exports.ThreadContext = ThreadContext;

},{"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],111:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});

var dwarf_1 = require("./dwarf");

var ThreadWrapper =
/*#__PURE__*/
function () {
  function ThreadWrapper() {
    (0, _classCallCheck2["default"])(this, ThreadWrapper);
  }

  (0, _createClass2["default"])(ThreadWrapper, null, [{
    key: "init",
    value: function init() {
      // attempt to retrieve pthread_create
      ThreadWrapper.pthreadCreateAddress = Module.findExportByName(null, 'pthread_create');

      if (ThreadWrapper.pthreadCreateAddress != null && !ThreadWrapper.pthreadCreateAddress.isNull()) {
        ThreadWrapper.pthreadCreateImplementation = new NativeFunction(ThreadWrapper.pthreadCreateAddress, 'int', ['pointer', 'pointer', 'pointer', 'pointer']); // allocate space for a fake handler which we intercept to run the callback

        ThreadWrapper.handler = Memory.alloc(Process.pointerSize); // set permissions

        Memory.protect(ThreadWrapper.handler, Process.pointerSize, 'rwx');

        if (Process.arch === 'arm64') {
          // arm64 require some fake code to get a trampoline from frida
          ThreadWrapper.handler.writeByteArray([0xE1, 0x03, 0x01, 0xAA, 0xC0, 0x03, 0x5F, 0xD6]);
        } // hook the fake handler


        Interceptor.replace(ThreadWrapper.handler, new NativeCallback(function () {
          // null check for handler function
          if (ThreadWrapper.handlerFunction !== null) {
            // invoke callback
            var ret = ThreadWrapper.handlerFunction.apply(this); // reset callback (unsafe asf... but we don't care)

            ThreadWrapper.handlerFunction = null; // return result

            return ret;
          }

          return 0;
        }, 'int', [])); // replace pthread_create for fun and profit

        Interceptor.attach(ThreadWrapper.pthreadCreateAddress, function (args) {
          dwarf_1.Dwarf.loggedSend('new_thread:::' + Process.getCurrentThreadId() + ':::' + args[2]);

          if (ThreadWrapper.onCreateCallback !== null && typeof ThreadWrapper.onCreateCallback === 'function') {
            ThreadWrapper.onCreateCallback(args[2]);
          }
        });
      }
    }
  }, {
    key: "backtrace",
    value: function backtrace(context, backtracer) {
      return Thread.backtrace(context, backtracer);
    }
  }, {
    key: "new",
    value: function _new(fn) {
      // check if pthread_create is defined
      if (ThreadWrapper.pthreadCreateAddress !== null) {
        return 1;
      } // check if fn is a valid function


      if (typeof fn !== 'function') {
        return 2;
      } // alocate space for struct pthread_t


      var pthread_t = Memory.alloc(Process.pointerSize); // set necessary permissions

      Memory.protect(pthread_t, Process.pointerSize, 'rwx'); // store the function into thread object

      ThreadWrapper.handlerFunction = fn; // spawn the thread

      return ThreadWrapper.pthreadCreateImplementation(pthread_t, ptr(0), ThreadWrapper.handler, ptr(0));
    }
  }, {
    key: "sleep",
    value: function sleep(delay) {
      Thread.sleep(delay);
    }
  }, {
    key: "onCreate",
    // set a callback for thread creation
    value: function onCreate(callback) {
      ThreadWrapper.onCreateCallback = callback;
    }
  }]);
  return ThreadWrapper;
}();

ThreadWrapper.onCreateCallback = null;
ThreadWrapper.pthreadCreateAddress = null;
ThreadWrapper.handler = NULL;
ThreadWrapper.handlerFunction = null;
exports.ThreadWrapper = ThreadWrapper;

},{"./dwarf":98,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/createClass":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],112:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _keys = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/keys"));

var _stringify = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/json/stringify"));

var _parseInt2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/parse-int"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
var Utils;

(function (Utils) {
  function isDefined(value) {
    return value !== undefined && value !== null && typeof value !== 'undefined';
  }

  Utils.isDefined = isDefined;

  function isNumber(value) {
    if (isDefined(value)) {
      return typeof value === "number" && !isNaN(value);
    }

    return false;
  }

  Utils.isNumber = isNumber;

  function isString(value) {
    if (isDefined(value)) {
      return typeof value === "string";
    }

    return false;
  }

  Utils.isString = isString;

  function ba2hex(b) {
    var uint8arr = new Uint8Array(b);

    if (!uint8arr) {
      return '';
    }

    var hexStr = '';

    for (var i = 0; i < uint8arr.length; i++) {
      var hex = (uint8arr[i] & 0xff).toString(16);
      hex = hex.length === 1 ? '0' + hex : hex;
      hexStr += hex;
    }

    return hexStr;
  }

  Utils.ba2hex = ba2hex;

  function hex2a(hex) {
    var bytes = [];

    for (var c = 0; c < hex.length; c += 2) {
      bytes.push((0, _parseInt2["default"])(hex.substr(c, 2), 16));
    }

    return bytes;
  }

  Utils.hex2a = hex2a;

  function dethumbify(pt) {
    if (Process.arch.indexOf('arm') !== -1) {
      if (((0, _parseInt2["default"])(pt.toString(), 16) & 1) === 1) {
        pt = pt.sub(1);
      }
    }

    return pt;
  }

  Utils.dethumbify = dethumbify;

  function uniqueBy(array) {
    var seen = {};
    return array.filter(function (item) {
      var k = (0, _stringify["default"])(item);
      return seen.hasOwnProperty(k) ? false : seen[k] = true;
    });
  }

  Utils.uniqueBy = uniqueBy;

  function logDebug() {
    for (var _len = arguments.length, data = new Array(_len), _key = 0; _key < _len; _key++) {
      data[_key] = arguments[_key];
    }

    var date = new Date();
    var now = date['getHourMinuteSecond']();
    var to_log = '';
    (0, _keys["default"])(data).forEach(function (argN) {
      var what = data[argN];

      if (what instanceof ArrayBuffer) {
        console.log(hexdump(what));
      } else if (what instanceof Object) {
        what = (0, _stringify["default"])(what, null, 2);
      }

      if (to_log !== '') {
        to_log += '\t';
      }

      to_log += what;
    });

    if (to_log !== '') {
      console.log(now, to_log);
    }
  }

  Utils.logDebug = logDebug;

  function logErr(tag, err) {
    logDebug('[ERROR-' + tag + '] ' + err);
  }

  Utils.logErr = logErr;
})(Utils = exports.Utils || (exports.Utils = {}));

},{"@babel/runtime-corejs2/core-js/json/stringify":2,"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/core-js/object/keys":6,"@babel/runtime-corejs2/core-js/parse-int":7,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}],113:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.MEMORY_ACCESS_READ = 1;
exports.MEMORY_ACCESS_WRITE = 2;
exports.MEMORY_ACCESS_EXECUTE = 4;
exports.MEMORY_WATCH_SINGLE_SHOT = 8;

var Watchpoint =
/*#__PURE__*/
function () {
  function Watchpoint(address, flags, perm, callback) {
    (0, _classCallCheck2["default"])(this, Watchpoint);
    this.address = address;
    this.debugSymbol = DebugSymbol.fromAddress(address);
    this.flags = flags;
    this.originalPermissions = perm;
    this.callback = callback;
  }

  (0, _createClass2["default"])(Watchpoint, [{
    key: "watch",
    value: function watch() {
      var perm = '';

      if (this.flags & exports.MEMORY_ACCESS_READ) {
        perm += '-';
      } else {
        perm += this.originalPermissions[0];
      }

      if (this.flags & exports.MEMORY_ACCESS_WRITE) {
        perm += '-';
      } else {
        perm += this.originalPermissions[1];
      }

      if (this.flags & exports.MEMORY_ACCESS_EXECUTE) {
        perm += '-';
      } else {
        if (this.originalPermissions[2] === 'x') {
          perm += 'x';
        } else {
          perm += '-';
        }
      }

      Memory.protect(this.address, 1, perm);
    }
  }, {
    key: "restore",
    value: function restore() {
      Memory.protect(this.address, 1, this.originalPermissions);
    }
  }]);
  return Watchpoint;
}();

exports.Watchpoint = Watchpoint;

},{"@babel/runtime-corejs2/core-js/object/define-property":4,"@babel/runtime-corejs2/helpers/classCallCheck":10,"@babel/runtime-corejs2/helpers/createClass":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":12}]},{},[100])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9jb3JlLWpzL2RhdGUvbm93LmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL0BiYWJlbC9ydW50aW1lLWNvcmVqczIvY29yZS1qcy9qc29uL3N0cmluZ2lmeS5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2NvcmUtanMvb2JqZWN0L2Fzc2lnbi5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2NvcmUtanMvb2JqZWN0L2RlZmluZS1wcm9wZXJ0eS5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2NvcmUtanMvb2JqZWN0L2dldC1vd24tcHJvcGVydHktbmFtZXMuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9jb3JlLWpzL29iamVjdC9rZXlzLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL0BiYWJlbC9ydW50aW1lLWNvcmVqczIvY29yZS1qcy9wYXJzZS1pbnQuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9jb3JlLWpzL3N5bWJvbC5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2NvcmUtanMvc3ltYm9sL2l0ZXJhdG9yLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL0BiYWJlbC9ydW50aW1lLWNvcmVqczIvaGVscGVycy9jbGFzc0NhbGxDaGVjay5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2hlbHBlcnMvY3JlYXRlQ2xhc3MuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9oZWxwZXJzL2ludGVyb3BSZXF1aXJlRGVmYXVsdC5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2hlbHBlcnMvdHlwZW9mLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9kYXRlL25vdy5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vanNvbi9zdHJpbmdpZnkuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L2ZuL29iamVjdC9hc3NpZ24uanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L2ZuL29iamVjdC9kZWZpbmUtcHJvcGVydHkuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L2ZuL29iamVjdC9nZXQtb3duLXByb3BlcnR5LW5hbWVzLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9vYmplY3Qva2V5cy5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vcGFyc2UtaW50LmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9zeW1ib2wvaW5kZXguanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L2ZuL3N5bWJvbC9pdGVyYXRvci5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fYS1mdW5jdGlvbi5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fYWRkLXRvLXVuc2NvcGFibGVzLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19hbi1vYmplY3QuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2FycmF5LWluY2x1ZGVzLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19jb2YuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2NvcmUuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2N0eC5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZGVmaW5lZC5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZGVzY3JpcHRvcnMuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2RvbS1jcmVhdGUuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2VudW0tYnVnLWtleXMuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2VudW0ta2V5cy5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZXhwb3J0LmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19mYWlscy5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZ2xvYmFsLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19oYXMuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2hpZGUuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2h0bWwuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2llOC1kb20tZGVmaW5lLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19pb2JqZWN0LmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19pcy1hcnJheS5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faXMtb2JqZWN0LmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19pdGVyLWNyZWF0ZS5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faXRlci1kZWZpbmUuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2l0ZXItc3RlcC5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faXRlcmF0b3JzLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19saWJyYXJ5LmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19tZXRhLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtYXNzaWduLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtY3JlYXRlLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtZHAuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX29iamVjdC1kcHMuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX29iamVjdC1nb3BkLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtZ29wbi1leHQuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX29iamVjdC1nb3BuLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtZ29wcy5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fb2JqZWN0LWdwby5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fb2JqZWN0LWtleXMtaW50ZXJuYWwuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX29iamVjdC1rZXlzLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtcGllLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3Qtc2FwLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19wYXJzZS1pbnQuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3Byb3BlcnR5LWRlc2MuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3JlZGVmaW5lLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19zZXQtdG8tc3RyaW5nLXRhZy5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fc2hhcmVkLWtleS5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fc2hhcmVkLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19zdHJpbmctYXQuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3N0cmluZy10cmltLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19zdHJpbmctd3MuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3RvLWFic29sdXRlLWluZGV4LmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL190by1pbnRlZ2VyLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL190by1pb2JqZWN0LmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL190by1sZW5ndGguanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3RvLW9iamVjdC5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fdG8tcHJpbWl0aXZlLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL191aWQuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3drcy1kZWZpbmUuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3drcy1leHQuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3drcy5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9lczYuYXJyYXkuaXRlcmF0b3IuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2LmRhdGUubm93LmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNi5vYmplY3QuYXNzaWduLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNi5vYmplY3QuZGVmaW5lLXByb3BlcnR5LmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNi5vYmplY3QuZ2V0LW93bi1wcm9wZXJ0eS1uYW1lcy5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9lczYub2JqZWN0LmtleXMuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2Lm9iamVjdC50by1zdHJpbmcuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2LnBhcnNlLWludC5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9lczYuc3RyaW5nLml0ZXJhdG9yLmpzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNi5zeW1ib2wuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM3LnN5bWJvbC5hc3luYy1pdGVyYXRvci5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9lczcuc3ltYm9sLm9ic2VydmFibGUuanMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvd2ViLmRvbS5pdGVyYWJsZS5qcyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL3NyYy9hcGkudHMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9zcmMvYnJlYWtwb2ludC50cyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL3NyYy9kd2FyZi50cyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL3NyYy9mcy50cyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL3NyYy9pbmRleC50cyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL3NyYy9pbnRlcmNlcHRvci50cyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL3NyYy9sb2dpY19icmVha3BvaW50LnRzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvc3JjL2xvZ2ljX2luaXRpYWxpemF0aW9uLnRzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvc3JjL2xvZ2ljX2phdmEudHMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9zcmMvbG9naWNfb2JqYy50cyIsIi4uLy4uLy4uL0RvY3VtZW50cy9naXQvRHdhcmZDb3JlL3NyYy9sb2dpY19zdGFsa2VyLnRzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvc3JjL2xvZ2ljX3dhdGNocG9pbnQudHMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9zcmMvc3RhbGtlcl9pbmZvLnRzIiwiLi4vLi4vLi4vRG9jdW1lbnRzL2dpdC9Ed2FyZkNvcmUvc3JjL3RocmVhZF9hcGkudHMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9zcmMvdGhyZWFkX2NvbnRleHQudHMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9zcmMvdGhyZWFkX3dyYXBwZXIudHMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9zcmMvdXRpbHMudHMiLCIuLi8uLi8uLi9Eb2N1bWVudHMvZ2l0L0R3YXJmQ29yZS9zcmMvd2F0Y2hwb2ludC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtBQ0FBOztBQ0FBOztBQ0FBOztBQ0FBOztBQ0FBOztBQ0FBOztBQ0FBOztBQ0FBOztBQ0FBOztBQ0FBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ05BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDbkJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ05BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNwQkE7QUFDQTtBQUNBOztBQ0ZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7O0FDRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0xBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7O0FDRkE7QUFDQTtBQUNBOztBQ0ZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7QUFDQTs7QUNIQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7O0FDREE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0xBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN2QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0xBO0FBQ0E7QUFDQTs7QUNGQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDcEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNmQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDOURBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDTkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUkE7QUFDQTtBQUNBOztBQ0ZBO0FBQ0E7QUFDQTtBQUNBOztBQ0hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ05BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7QUFDQTs7QUNIQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3JFQTtBQUNBO0FBQ0E7QUFDQTs7QUNIQTtBQUNBOztBQ0RBO0FBQ0E7O0FDREE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3JEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdENBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN6Q0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNiQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2hCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ25CQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1BBO0FBQ0E7O0FDREE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNiQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDakJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUEE7QUFDQTs7QUNEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1ZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1RBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNSQTtBQUNBOztBQ0RBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0xBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1pBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNqQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDOUJBO0FBQ0E7QUFDQTs7QUNGQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1BBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ05BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ05BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ05BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNaQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDTEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDVEE7QUFDQTs7QUNEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDWEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNsQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7QUFDQTtBQUNBOztBQ0hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDSkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDVEE7O0FDQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDakJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3RQQTtBQUNBOztBQ0RBO0FBQ0E7O0FDREE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ25CQSxJQUFBLE9BQUEsR0FBQSxPQUFBLENBQUEsU0FBQSxDQUFBOztBQUNBLElBQUEsSUFBQSxHQUFBLE9BQUEsQ0FBQSxNQUFBLENBQUE7O0FBQ0EsSUFBQSxrQkFBQSxHQUFBLE9BQUEsQ0FBQSxvQkFBQSxDQUFBOztBQUNBLElBQUEsWUFBQSxHQUFBLE9BQUEsQ0FBQSxjQUFBLENBQUE7O0FBQ0EsSUFBQSxZQUFBLEdBQUEsT0FBQSxDQUFBLGNBQUEsQ0FBQTs7QUFDQSxJQUFBLHNCQUFBLEdBQUEsT0FBQSxDQUFBLHdCQUFBLENBQUE7O0FBQ0EsSUFBQSxlQUFBLEdBQUEsT0FBQSxDQUFBLGlCQUFBLENBQUE7O0FBQ0EsSUFBQSxrQkFBQSxHQUFBLE9BQUEsQ0FBQSxvQkFBQSxDQUFBOztBQUNBLElBQUEsZ0JBQUEsR0FBQSxPQUFBLENBQUEsa0JBQUEsQ0FBQTs7QUFDQSxJQUFBLE9BQUEsR0FBQSxPQUFBLENBQUEsU0FBQSxDQUFBOztBQUNB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
