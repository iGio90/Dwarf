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


(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
module.exports = require("core-js/library/fn/date/now");
},{"core-js/library/fn/date/now":15}],2:[function(require,module,exports){
module.exports = require("core-js/library/fn/get-iterator");
},{"core-js/library/fn/get-iterator":16}],3:[function(require,module,exports){
module.exports = require("core-js/library/fn/json/stringify");
},{"core-js/library/fn/json/stringify":17}],4:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/assign");
},{"core-js/library/fn/object/assign":18}],5:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/define-property");
},{"core-js/library/fn/object/define-property":19}],6:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/get-own-property-names");
},{"core-js/library/fn/object/get-own-property-names":20}],7:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/keys");
},{"core-js/library/fn/object/keys":21}],8:[function(require,module,exports){
module.exports = require("core-js/library/fn/parse-int");
},{"core-js/library/fn/parse-int":22}],9:[function(require,module,exports){
module.exports = require("core-js/library/fn/symbol");
},{"core-js/library/fn/symbol":23}],10:[function(require,module,exports){
module.exports = require("core-js/library/fn/symbol/iterator");
},{"core-js/library/fn/symbol/iterator":24}],11:[function(require,module,exports){
function _classCallCheck(instance, Constructor) {
  if (!(instance instanceof Constructor)) {
    throw new TypeError("Cannot call a class as a function");
  }
}

module.exports = _classCallCheck;
},{}],12:[function(require,module,exports){
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
},{"../core-js/object/define-property":5}],13:[function(require,module,exports){
function _interopRequireDefault(obj) {
  return obj && obj.__esModule ? obj : {
    "default": obj
  };
}

module.exports = _interopRequireDefault;
},{}],14:[function(require,module,exports){
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
},{"../core-js/symbol":9,"../core-js/symbol/iterator":10}],15:[function(require,module,exports){
require('../../modules/es6.date.now');
module.exports = require('../../modules/_core').Date.now;

},{"../../modules/_core":31,"../../modules/es6.date.now":89}],16:[function(require,module,exports){
require('../modules/web.dom.iterable');
require('../modules/es6.string.iterator');
module.exports = require('../modules/core.get-iterator');

},{"../modules/core.get-iterator":87,"../modules/es6.string.iterator":96,"../modules/web.dom.iterable":100}],17:[function(require,module,exports){
var core = require('../../modules/_core');
var $JSON = core.JSON || (core.JSON = { stringify: JSON.stringify });
module.exports = function stringify(it) { // eslint-disable-line no-unused-vars
  return $JSON.stringify.apply($JSON, arguments);
};

},{"../../modules/_core":31}],18:[function(require,module,exports){
require('../../modules/es6.object.assign');
module.exports = require('../../modules/_core').Object.assign;

},{"../../modules/_core":31,"../../modules/es6.object.assign":90}],19:[function(require,module,exports){
require('../../modules/es6.object.define-property');
var $Object = require('../../modules/_core').Object;
module.exports = function defineProperty(it, key, desc) {
  return $Object.defineProperty(it, key, desc);
};

},{"../../modules/_core":31,"../../modules/es6.object.define-property":91}],20:[function(require,module,exports){
require('../../modules/es6.object.get-own-property-names');
var $Object = require('../../modules/_core').Object;
module.exports = function getOwnPropertyNames(it) {
  return $Object.getOwnPropertyNames(it);
};

},{"../../modules/_core":31,"../../modules/es6.object.get-own-property-names":92}],21:[function(require,module,exports){
require('../../modules/es6.object.keys');
module.exports = require('../../modules/_core').Object.keys;

},{"../../modules/_core":31,"../../modules/es6.object.keys":93}],22:[function(require,module,exports){
require('../modules/es6.parse-int');
module.exports = require('../modules/_core').parseInt;

},{"../modules/_core":31,"../modules/es6.parse-int":95}],23:[function(require,module,exports){
require('../../modules/es6.symbol');
require('../../modules/es6.object.to-string');
require('../../modules/es7.symbol.async-iterator');
require('../../modules/es7.symbol.observable');
module.exports = require('../../modules/_core').Symbol;

},{"../../modules/_core":31,"../../modules/es6.object.to-string":94,"../../modules/es6.symbol":97,"../../modules/es7.symbol.async-iterator":98,"../../modules/es7.symbol.observable":99}],24:[function(require,module,exports){
require('../../modules/es6.string.iterator');
require('../../modules/web.dom.iterable');
module.exports = require('../../modules/_wks-ext').f('iterator');

},{"../../modules/_wks-ext":84,"../../modules/es6.string.iterator":96,"../../modules/web.dom.iterable":100}],25:[function(require,module,exports){
module.exports = function (it) {
  if (typeof it != 'function') throw TypeError(it + ' is not a function!');
  return it;
};

},{}],26:[function(require,module,exports){
module.exports = function () { /* empty */ };

},{}],27:[function(require,module,exports){
var isObject = require('./_is-object');
module.exports = function (it) {
  if (!isObject(it)) throw TypeError(it + ' is not an object!');
  return it;
};

},{"./_is-object":47}],28:[function(require,module,exports){
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

},{"./_to-absolute-index":76,"./_to-iobject":78,"./_to-length":79}],29:[function(require,module,exports){
// getting tag from 19.1.3.6 Object.prototype.toString()
var cof = require('./_cof');
var TAG = require('./_wks')('toStringTag');
// ES3 wrong here
var ARG = cof(function () { return arguments; }()) == 'Arguments';

// fallback for IE11 Script Access Denied error
var tryGet = function (it, key) {
  try {
    return it[key];
  } catch (e) { /* empty */ }
};

module.exports = function (it) {
  var O, T, B;
  return it === undefined ? 'Undefined' : it === null ? 'Null'
    // @@toStringTag case
    : typeof (T = tryGet(O = Object(it), TAG)) == 'string' ? T
    // builtinTag case
    : ARG ? cof(O)
    // ES3 arguments fallback
    : (B = cof(O)) == 'Object' && typeof O.callee == 'function' ? 'Arguments' : B;
};

},{"./_cof":30,"./_wks":85}],30:[function(require,module,exports){
var toString = {}.toString;

module.exports = function (it) {
  return toString.call(it).slice(8, -1);
};

},{}],31:[function(require,module,exports){
var core = module.exports = { version: '2.6.10' };
if (typeof __e == 'number') __e = core; // eslint-disable-line no-undef

},{}],32:[function(require,module,exports){
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

},{"./_a-function":25}],33:[function(require,module,exports){
// 7.2.1 RequireObjectCoercible(argument)
module.exports = function (it) {
  if (it == undefined) throw TypeError("Can't call method on  " + it);
  return it;
};

},{}],34:[function(require,module,exports){
// Thank's IE8 for his funny defineProperty
module.exports = !require('./_fails')(function () {
  return Object.defineProperty({}, 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_fails":39}],35:[function(require,module,exports){
var isObject = require('./_is-object');
var document = require('./_global').document;
// typeof document.createElement is 'object' in old IE
var is = isObject(document) && isObject(document.createElement);
module.exports = function (it) {
  return is ? document.createElement(it) : {};
};

},{"./_global":40,"./_is-object":47}],36:[function(require,module,exports){
// IE 8- don't enum bug keys
module.exports = (
  'constructor,hasOwnProperty,isPrototypeOf,propertyIsEnumerable,toLocaleString,toString,valueOf'
).split(',');

},{}],37:[function(require,module,exports){
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

},{"./_object-gops":61,"./_object-keys":64,"./_object-pie":65}],38:[function(require,module,exports){
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

},{"./_core":31,"./_ctx":32,"./_global":40,"./_has":41,"./_hide":42}],39:[function(require,module,exports){
module.exports = function (exec) {
  try {
    return !!exec();
  } catch (e) {
    return true;
  }
};

},{}],40:[function(require,module,exports){
// https://github.com/zloirock/core-js/issues/86#issuecomment-115759028
var global = module.exports = typeof window != 'undefined' && window.Math == Math
  ? window : typeof self != 'undefined' && self.Math == Math ? self
  // eslint-disable-next-line no-new-func
  : Function('return this')();
if (typeof __g == 'number') __g = global; // eslint-disable-line no-undef

},{}],41:[function(require,module,exports){
var hasOwnProperty = {}.hasOwnProperty;
module.exports = function (it, key) {
  return hasOwnProperty.call(it, key);
};

},{}],42:[function(require,module,exports){
var dP = require('./_object-dp');
var createDesc = require('./_property-desc');
module.exports = require('./_descriptors') ? function (object, key, value) {
  return dP.f(object, key, createDesc(1, value));
} : function (object, key, value) {
  object[key] = value;
  return object;
};

},{"./_descriptors":34,"./_object-dp":56,"./_property-desc":68}],43:[function(require,module,exports){
var document = require('./_global').document;
module.exports = document && document.documentElement;

},{"./_global":40}],44:[function(require,module,exports){
module.exports = !require('./_descriptors') && !require('./_fails')(function () {
  return Object.defineProperty(require('./_dom-create')('div'), 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_descriptors":34,"./_dom-create":35,"./_fails":39}],45:[function(require,module,exports){
// fallback for non-array-like ES3 and non-enumerable old V8 strings
var cof = require('./_cof');
// eslint-disable-next-line no-prototype-builtins
module.exports = Object('z').propertyIsEnumerable(0) ? Object : function (it) {
  return cof(it) == 'String' ? it.split('') : Object(it);
};

},{"./_cof":30}],46:[function(require,module,exports){
// 7.2.2 IsArray(argument)
var cof = require('./_cof');
module.exports = Array.isArray || function isArray(arg) {
  return cof(arg) == 'Array';
};

},{"./_cof":30}],47:[function(require,module,exports){
module.exports = function (it) {
  return typeof it === 'object' ? it !== null : typeof it === 'function';
};

},{}],48:[function(require,module,exports){
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

},{"./_hide":42,"./_object-create":55,"./_property-desc":68,"./_set-to-string-tag":70,"./_wks":85}],49:[function(require,module,exports){
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

},{"./_export":38,"./_hide":42,"./_iter-create":48,"./_iterators":51,"./_library":52,"./_object-gpo":62,"./_redefine":69,"./_set-to-string-tag":70,"./_wks":85}],50:[function(require,module,exports){
module.exports = function (done, value) {
  return { value: value, done: !!done };
};

},{}],51:[function(require,module,exports){
module.exports = {};

},{}],52:[function(require,module,exports){
module.exports = true;

},{}],53:[function(require,module,exports){
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

},{"./_fails":39,"./_has":41,"./_is-object":47,"./_object-dp":56,"./_uid":82}],54:[function(require,module,exports){
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

},{"./_descriptors":34,"./_fails":39,"./_iobject":45,"./_object-gops":61,"./_object-keys":64,"./_object-pie":65,"./_to-object":80}],55:[function(require,module,exports){
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

},{"./_an-object":27,"./_dom-create":35,"./_enum-bug-keys":36,"./_html":43,"./_object-dps":57,"./_shared-key":71}],56:[function(require,module,exports){
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

},{"./_an-object":27,"./_descriptors":34,"./_ie8-dom-define":44,"./_to-primitive":81}],57:[function(require,module,exports){
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

},{"./_an-object":27,"./_descriptors":34,"./_object-dp":56,"./_object-keys":64}],58:[function(require,module,exports){
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

},{"./_descriptors":34,"./_has":41,"./_ie8-dom-define":44,"./_object-pie":65,"./_property-desc":68,"./_to-iobject":78,"./_to-primitive":81}],59:[function(require,module,exports){
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

},{"./_object-gopn":60,"./_to-iobject":78}],60:[function(require,module,exports){
// 19.1.2.7 / 15.2.3.4 Object.getOwnPropertyNames(O)
var $keys = require('./_object-keys-internal');
var hiddenKeys = require('./_enum-bug-keys').concat('length', 'prototype');

exports.f = Object.getOwnPropertyNames || function getOwnPropertyNames(O) {
  return $keys(O, hiddenKeys);
};

},{"./_enum-bug-keys":36,"./_object-keys-internal":63}],61:[function(require,module,exports){
exports.f = Object.getOwnPropertySymbols;

},{}],62:[function(require,module,exports){
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

},{"./_has":41,"./_shared-key":71,"./_to-object":80}],63:[function(require,module,exports){
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

},{"./_array-includes":28,"./_has":41,"./_shared-key":71,"./_to-iobject":78}],64:[function(require,module,exports){
// 19.1.2.14 / 15.2.3.14 Object.keys(O)
var $keys = require('./_object-keys-internal');
var enumBugKeys = require('./_enum-bug-keys');

module.exports = Object.keys || function keys(O) {
  return $keys(O, enumBugKeys);
};

},{"./_enum-bug-keys":36,"./_object-keys-internal":63}],65:[function(require,module,exports){
exports.f = {}.propertyIsEnumerable;

},{}],66:[function(require,module,exports){
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

},{"./_core":31,"./_export":38,"./_fails":39}],67:[function(require,module,exports){
var $parseInt = require('./_global').parseInt;
var $trim = require('./_string-trim').trim;
var ws = require('./_string-ws');
var hex = /^[-+]?0[xX]/;

module.exports = $parseInt(ws + '08') !== 8 || $parseInt(ws + '0x16') !== 22 ? function parseInt(str, radix) {
  var string = $trim(String(str), 3);
  return $parseInt(string, (radix >>> 0) || (hex.test(string) ? 16 : 10));
} : $parseInt;

},{"./_global":40,"./_string-trim":74,"./_string-ws":75}],68:[function(require,module,exports){
module.exports = function (bitmap, value) {
  return {
    enumerable: !(bitmap & 1),
    configurable: !(bitmap & 2),
    writable: !(bitmap & 4),
    value: value
  };
};

},{}],69:[function(require,module,exports){
module.exports = require('./_hide');

},{"./_hide":42}],70:[function(require,module,exports){
var def = require('./_object-dp').f;
var has = require('./_has');
var TAG = require('./_wks')('toStringTag');

module.exports = function (it, tag, stat) {
  if (it && !has(it = stat ? it : it.prototype, TAG)) def(it, TAG, { configurable: true, value: tag });
};

},{"./_has":41,"./_object-dp":56,"./_wks":85}],71:[function(require,module,exports){
var shared = require('./_shared')('keys');
var uid = require('./_uid');
module.exports = function (key) {
  return shared[key] || (shared[key] = uid(key));
};

},{"./_shared":72,"./_uid":82}],72:[function(require,module,exports){
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

},{"./_core":31,"./_global":40,"./_library":52}],73:[function(require,module,exports){
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

},{"./_defined":33,"./_to-integer":77}],74:[function(require,module,exports){
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

},{"./_defined":33,"./_export":38,"./_fails":39,"./_string-ws":75}],75:[function(require,module,exports){
module.exports = '\x09\x0A\x0B\x0C\x0D\x20\xA0\u1680\u180E\u2000\u2001\u2002\u2003' +
  '\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u202F\u205F\u3000\u2028\u2029\uFEFF';

},{}],76:[function(require,module,exports){
var toInteger = require('./_to-integer');
var max = Math.max;
var min = Math.min;
module.exports = function (index, length) {
  index = toInteger(index);
  return index < 0 ? max(index + length, 0) : min(index, length);
};

},{"./_to-integer":77}],77:[function(require,module,exports){
// 7.1.4 ToInteger
var ceil = Math.ceil;
var floor = Math.floor;
module.exports = function (it) {
  return isNaN(it = +it) ? 0 : (it > 0 ? floor : ceil)(it);
};

},{}],78:[function(require,module,exports){
// to indexed object, toObject with fallback for non-array-like ES3 strings
var IObject = require('./_iobject');
var defined = require('./_defined');
module.exports = function (it) {
  return IObject(defined(it));
};

},{"./_defined":33,"./_iobject":45}],79:[function(require,module,exports){
// 7.1.15 ToLength
var toInteger = require('./_to-integer');
var min = Math.min;
module.exports = function (it) {
  return it > 0 ? min(toInteger(it), 0x1fffffffffffff) : 0; // pow(2, 53) - 1 == 9007199254740991
};

},{"./_to-integer":77}],80:[function(require,module,exports){
// 7.1.13 ToObject(argument)
var defined = require('./_defined');
module.exports = function (it) {
  return Object(defined(it));
};

},{"./_defined":33}],81:[function(require,module,exports){
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

},{"./_is-object":47}],82:[function(require,module,exports){
var id = 0;
var px = Math.random();
module.exports = function (key) {
  return 'Symbol('.concat(key === undefined ? '' : key, ')_', (++id + px).toString(36));
};

},{}],83:[function(require,module,exports){
var global = require('./_global');
var core = require('./_core');
var LIBRARY = require('./_library');
var wksExt = require('./_wks-ext');
var defineProperty = require('./_object-dp').f;
module.exports = function (name) {
  var $Symbol = core.Symbol || (core.Symbol = LIBRARY ? {} : global.Symbol || {});
  if (name.charAt(0) != '_' && !(name in $Symbol)) defineProperty($Symbol, name, { value: wksExt.f(name) });
};

},{"./_core":31,"./_global":40,"./_library":52,"./_object-dp":56,"./_wks-ext":84}],84:[function(require,module,exports){
exports.f = require('./_wks');

},{"./_wks":85}],85:[function(require,module,exports){
var store = require('./_shared')('wks');
var uid = require('./_uid');
var Symbol = require('./_global').Symbol;
var USE_SYMBOL = typeof Symbol == 'function';

var $exports = module.exports = function (name) {
  return store[name] || (store[name] =
    USE_SYMBOL && Symbol[name] || (USE_SYMBOL ? Symbol : uid)('Symbol.' + name));
};

$exports.store = store;

},{"./_global":40,"./_shared":72,"./_uid":82}],86:[function(require,module,exports){
var classof = require('./_classof');
var ITERATOR = require('./_wks')('iterator');
var Iterators = require('./_iterators');
module.exports = require('./_core').getIteratorMethod = function (it) {
  if (it != undefined) return it[ITERATOR]
    || it['@@iterator']
    || Iterators[classof(it)];
};

},{"./_classof":29,"./_core":31,"./_iterators":51,"./_wks":85}],87:[function(require,module,exports){
var anObject = require('./_an-object');
var get = require('./core.get-iterator-method');
module.exports = require('./_core').getIterator = function (it) {
  var iterFn = get(it);
  if (typeof iterFn != 'function') throw TypeError(it + ' is not iterable!');
  return anObject(iterFn.call(it));
};

},{"./_an-object":27,"./_core":31,"./core.get-iterator-method":86}],88:[function(require,module,exports){
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

},{"./_add-to-unscopables":26,"./_iter-define":49,"./_iter-step":50,"./_iterators":51,"./_to-iobject":78}],89:[function(require,module,exports){
// 20.3.3.1 / 15.9.4.4 Date.now()
var $export = require('./_export');

$export($export.S, 'Date', { now: function () { return new Date().getTime(); } });

},{"./_export":38}],90:[function(require,module,exports){
// 19.1.3.1 Object.assign(target, source)
var $export = require('./_export');

$export($export.S + $export.F, 'Object', { assign: require('./_object-assign') });

},{"./_export":38,"./_object-assign":54}],91:[function(require,module,exports){
var $export = require('./_export');
// 19.1.2.4 / 15.2.3.6 Object.defineProperty(O, P, Attributes)
$export($export.S + $export.F * !require('./_descriptors'), 'Object', { defineProperty: require('./_object-dp').f });

},{"./_descriptors":34,"./_export":38,"./_object-dp":56}],92:[function(require,module,exports){
// 19.1.2.7 Object.getOwnPropertyNames(O)
require('./_object-sap')('getOwnPropertyNames', function () {
  return require('./_object-gopn-ext').f;
});

},{"./_object-gopn-ext":59,"./_object-sap":66}],93:[function(require,module,exports){
// 19.1.2.14 Object.keys(O)
var toObject = require('./_to-object');
var $keys = require('./_object-keys');

require('./_object-sap')('keys', function () {
  return function keys(it) {
    return $keys(toObject(it));
  };
});

},{"./_object-keys":64,"./_object-sap":66,"./_to-object":80}],94:[function(require,module,exports){

},{}],95:[function(require,module,exports){
var $export = require('./_export');
var $parseInt = require('./_parse-int');
// 18.2.5 parseInt(string, radix)
$export($export.G + $export.F * (parseInt != $parseInt), { parseInt: $parseInt });

},{"./_export":38,"./_parse-int":67}],96:[function(require,module,exports){
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

},{"./_iter-define":49,"./_string-at":73}],97:[function(require,module,exports){
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

},{"./_an-object":27,"./_descriptors":34,"./_enum-keys":37,"./_export":38,"./_fails":39,"./_global":40,"./_has":41,"./_hide":42,"./_is-array":46,"./_is-object":47,"./_library":52,"./_meta":53,"./_object-create":55,"./_object-dp":56,"./_object-gopd":58,"./_object-gopn":60,"./_object-gopn-ext":59,"./_object-gops":61,"./_object-keys":64,"./_object-pie":65,"./_property-desc":68,"./_redefine":69,"./_set-to-string-tag":70,"./_shared":72,"./_to-iobject":78,"./_to-object":80,"./_to-primitive":81,"./_uid":82,"./_wks":85,"./_wks-define":83,"./_wks-ext":84}],98:[function(require,module,exports){
require('./_wks-define')('asyncIterator');

},{"./_wks-define":83}],99:[function(require,module,exports){
require('./_wks-define')('observable');

},{"./_wks-define":83}],100:[function(require,module,exports){
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

},{"./_global":40,"./_hide":42,"./_iterators":51,"./_wks":85,"./es6.array.iterator":88}],101:[function(require,module,exports){
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
exports.Api = void 0;

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

var Api = /*#__PURE__*/function () {
  function Api() {
    (0, _classCallCheck2["default"])(this, Api);
  }

  (0, _createClass2["default"])(Api, null, [{
    key: "_internalMemoryScan",
    value: function _internalMemoryScan(start, size, pattern) {
      if (size > 4096) {
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
    value: function backtrace(context) {
      if (!utils_1.Utils.isDefined(context)) {
        context = dwarf_1.Dwarf.threadContexts[Process.getCurrentThreadId()];

        if (!utils_1.Utils.isDefined(context)) {
          return null;
        }
      }

      return Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    }
  }, {
    key: "enumerateExports",
    value: function enumerateExports(module) {
      if ((0, _typeof2["default"])(module) !== "object") {
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
    value: function enumerateImports(module) {
      if ((0, _typeof2["default"])(module) !== "object") {
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
    value: function enumerateJavaClasses(useCache) {
      if (!utils_1.Utils.isDefined(useCache)) {
        useCache = false;
      }

      if (useCache && logic_java_1.LogicJava !== null && logic_java_1.LogicJava.javaClasses.length > 0) {
        dwarf_1.Dwarf.loggedSend("enumerate_java_classes_start:::");

        for (var i = 0; i < logic_java_1.LogicJava.javaClasses.length; i++) {
          send("enumerate_java_classes_match:::" + logic_java_1.LogicJava.javaClasses[i]);
        }

        dwarf_1.Dwarf.loggedSend("enumerate_java_classes_complete:::");
      } else {
        if (logic_java_1.LogicJava !== null) {
          logic_java_1.LogicJava.javaClasses = [];
        }

        Java.performNow(function () {
          dwarf_1.Dwarf.loggedSend("enumerate_java_classes_start:::");

          try {
            var mainLoader = Java.classFactory.loader;
            var ldr = Java.enumerateClassLoadersSync();
            var n = 0;
            ldr.forEach(function (loaderz) {
              Java.classFactory.loader = loaderz;
              Java.enumerateLoadedClasses({
                onMatch: function onMatch(className) {
                  if (logic_java_1.LogicJava !== null) {
                    logic_java_1.LogicJava.javaClasses.push(className);
                  }

                  send("enumerate_java_classes_match:::" + className);
                },
                onComplete: function onComplete() {
                  n++;

                  if (n === ldr.length) {
                    dwarf_1.Dwarf.loggedSend("enumerate_java_classes_complete:::");
                  }
                }
              });
            });
            Java.classFactory.loader = mainLoader;
          } catch (e) {
            utils_1.Utils.logErr("enumerateJavaClasses", e);
            dwarf_1.Dwarf.loggedSend("enumerate_java_classes_complete:::");
          }
        });
      }
    }
  }, {
    key: "enumerateJavaMethods",
    value: function enumerateJavaMethods(className) {
      if (Java.available) {
        var that = this;
        Java.performNow(function () {
          try {
            var clazz = Java.use(className);
            var methods = clazz["class"].getDeclaredMethods();
            var parsedMethods = [];
            methods.forEach(function (method) {
              parsedMethods.push(method.toString().replace(className + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
            });
            var result = utils_1.Utils.uniqueBy(parsedMethods);
            dwarf_1.Dwarf.loggedSend("enumerate_java_methods_complete:::" + className + ":::" + (0, _stringify["default"])(result));
          } catch (e) {
            utils_1.Utils.logErr("classMethods", e);
          }
        });
      }
    }
  }, {
    key: "enumerateObjCModules",
    value: function enumerateObjCModules() {
      var modules = Process.enumerateModules();
      var names = modules.map(function (m) {
        return m.name;
      });
      dwarf_1.Dwarf.loggedSend("enumerate_objc_modules:::" + (0, _stringify["default"])(names));
    }
  }, {
    key: "enumerateObjCClasses",
    value: function enumerateObjCClasses(moduleName) {
      dwarf_1.Dwarf.loggedSend("enumerate_objc_classes_start:::");

      try {
        ObjC.enumerateLoadedClasses({
          ownedBy: new ModuleMap(function (m) {
            return moduleName === m["name"];
          })
        }, {
          onMatch: function onMatch(className) {
            if (logic_objc_1.LogicObjC !== null) {
              logic_objc_1.LogicObjC.objcClasses.push(className);
            }

            send("enumerate_objc_classes_match:::" + className);
          },
          onComplete: function onComplete() {
            send("enumerate_objc_classes_complete:::");
          }
        });
      } catch (e) {
        utils_1.Utils.logErr("enumerateObjCClasses", e);
        dwarf_1.Dwarf.loggedSend("enumerate_objc_classes_complete:::");
      }
    }
  }, {
    key: "enumerateObjCMethods",
    value: function enumerateObjCMethods(className) {
      if (ObjC.available) {
        dwarf_1.Dwarf.loggedSend("enumerate_objc_methods_start:::");
        var that = this;
        var clazz = ObjC.classes[className];
        var methods = clazz.$ownMethods;
        methods.forEach(function (method) {
          send("enumerate_objc_methods_match:::" + method);
        });
        dwarf_1.Dwarf.loggedSend("enumerate_objc_methods_complete:::");
      }
    }
  }, {
    key: "enumerateModules",
    value: function enumerateModules(fillInformation) {
      fillInformation = fillInformation || false;
      var modules = Process.enumerateModules();

      if (fillInformation) {
        for (var i = 0; i < modules.length; i++) {
          if (dwarf_1.Dwarf.modulesBlacklist.indexOf(modules[i].name) >= 0) {
            continue;
          }

          if (Process.platform === "windows") {
            if (modules[i].name === "ntdll.dll") {
              continue;
            }
          } else if (Process.platform === "linux") {
            if (logic_java_1.LogicJava !== null) {
              if (logic_java_1.LogicJava.sdk <= 23) {
                if (modules[i].name === "app_process") {
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
    value: function enumerateModuleInfo(fridaModule) {
      var _module = null;

      if (utils_1.Utils.isString(fridaModule)) {
        _module = Process.findModuleByName(fridaModule);
      } else {
        _module = fridaModule;
      }

      if (dwarf_1.Dwarf.modulesBlacklist.indexOf(_module.name) >= 0) {
        Api.log("Error: Module " + _module.name + " is blacklisted");
        return _module;
      }

      try {
        _module["imports"] = _module.enumerateImports();
        _module["exports"] = _module.enumerateExports();
        _module["symbols"] = _module.enumerateSymbols();
      } catch (e) {
        return _module;
      }

      _module["entry"] = null;

      var header = _module.base.readByteArray(4);

      if (header[0] !== 0x7f && header[1] !== 0x45 && header[2] !== 0x4c && header[3] !== 0x46) {
        _module["entry"] = _module.base.add(24).readPointer();
      }

      return _module;
    }
  }, {
    key: "enumerateRanges",
    value: function enumerateRanges() {
      return Process.enumerateRanges("---");
    }
  }, {
    key: "enumerateSymbols",
    value: function enumerateSymbols(module) {
      if ((0, _typeof2["default"])(module) !== "object") {
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
    value: function evaluate(jsCode) {
      var Thread = thread_wrapper_1.ThreadWrapper;

      try {
        return eval(jsCode);
      } catch (e) {
        Api.log(e.toString());
        return null;
      }
    }
  }, {
    key: "evaluateFunction",
    value: function evaluateFunction(jsFnc) {
      try {
        var fn = new Function("Thread", jsFnc);
        return fn.apply(this, [thread_wrapper_1.ThreadWrapper]);
      } catch (e) {
        Api.log(e.toString());
        return null;
      }
    }
  }, {
    key: "evaluatePtr",
    value: function evaluatePtr(pointer) {
      try {
        return ptr(eval(pointer));
      } catch (e) {
        return NULL;
      }
    }
  }, {
    key: "findExport",
    value: function findExport(name, module) {
      if (typeof module === "undefined") {
        module = null;
      }

      return Module.findExportByName(module, name);
    }
  }, {
    key: "findModule",
    value: function findModule(module) {
      var _module;

      if (utils_1.Utils.isString(module) && module.substring(0, 2) !== "0x") {
        _module = Process.findModuleByName(module);

        if (utils_1.Utils.isDefined(_module)) {
          return _module;
        } else {
          if (module.indexOf("*") !== -1) {
            var modules = Process.enumerateModules();
            var searchName = module.toLowerCase().split("*")[0];

            for (var i = 0; i < modules.length; i++) {
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
    value: function findSymbol(pattern) {
      return DebugSymbol.findFunctionsMatching(pattern);
    }
  }, {
    key: "getAddressTs",
    value: function getAddressTs(p) {
      var _ptr = ptr(p);

      var _range = Process.findRangeByAddress(_ptr);

      if (utils_1.Utils.isDefined(_range)) {
        if (_range.protection.indexOf("r") !== -1) {
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
    value: function getDebugSymbols(ptrs) {
      var symbols = [];

      if (utils_1.Utils.isDefined(ptrs)) {
        try {
          ptrs = JSON.parse(ptrs);
        } catch (e) {
          utils_1.Utils.logErr("getDebugSymbols", e);
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
    value: function getInstruction(address) {
      try {
        var instruction = Instruction.parse(ptr(address));
        return (0, _stringify["default"])({
          string: instruction.toString()
        });
      } catch (e) {
        utils_1.Utils.logErr("getInstruction", e);
      }

      return null;
    }
  }, {
    key: "getRange",
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
        utils_1.Utils.logErr("getRange", e);
        return null;
      }
    }
  }, {
    key: "getSymbolByAddress",
    value: function getSymbolByAddress(pt) {
      try {
        pt = ptr(pt);
        return DebugSymbol.fromAddress(pt);
      } catch (e) {
        utils_1.Utils.logErr("getSymbolByAddress", e);
        return null;
      }
    }
  }, {
    key: "hookAllJavaMethods",
    value: function hookAllJavaMethods(className, callback) {
      return logic_java_1.LogicJava.hookAllJavaMethods(className, callback);
    }
  }, {
    key: "hookClassLoaderClassInitialization",
    value: function hookClassLoaderClassInitialization(className, callback) {
      return logic_java_1.LogicJava.hookClassLoaderClassInitialization(className, callback);
    }
  }, {
    key: "hookJavaConstructor",
    value: function hookJavaConstructor(className, callback) {
      return logic_java_1.LogicJava.hook(className, "$init", callback);
    }
  }, {
    key: "hookJavaMethod",
    value: function hookJavaMethod(targetClassMethod, callback) {
      return logic_java_1.LogicJava.hookJavaMethod(targetClassMethod, callback);
    }
  }, {
    key: "hookModuleInitialization",
    value: function hookModuleInitialization(moduleName, callback) {
      return logic_initialization_1.LogicInitialization.hookModuleInitialization(moduleName, callback);
    }
  }, {
    key: "injectBlob",
    value: function injectBlob(name, blob) {
      var sys_num = 385;

      if (Process.arch === "ia32") {
        sys_num = 356;
      } else if (Process.arch === "x64") {
        sys_num = 319;
      }

      var syscall_ptr = Api.findExport("syscall");
      var write_ptr = Api.findExport("write");
      var dlopen_ptr = Api.findExport("dlopen");

      if (syscall_ptr !== null && !syscall_ptr.isNull()) {
        var syscall = new NativeFunction(syscall_ptr, "int", ["int", "pointer", "int"]);

        if (write_ptr !== null && !write_ptr.isNull()) {
          var write = new NativeFunction(write_ptr, "int", ["int", "pointer", "int"]);

          if (dlopen_ptr !== null && !dlopen_ptr.isNull()) {
            var dlopen = new NativeFunction(dlopen_ptr, "int", ["pointer", "int"]);
            var m = fs_1.FileSystem.allocateRw(128);
            m.writeUtf8String(name);
            var fd = syscall(sys_num, m, 0);

            if (fd > 0) {
              var hexArr = utils_1.Utils.hex2a(blob);
              var blob_space = Memory.alloc(hexArr.length);
              Memory.protect(blob_space, hexArr.length, "rwx");
              blob_space.writeByteArray(hexArr);
              write(fd, blob_space, hexArr.length);
              m.writeUtf8String("/proc/" + Process.id + "/fd/" + fd);
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
    value: function isAddressWatched(pt) {
      var watchpoint = logic_watchpoint_1.LogicWatchpoint.memoryWatchpoints[ptr(pt).toString()];
      return utils_1.Utils.isDefined(watchpoint);
    }
  }, {
    key: "isPrintable",
    value: function isPrintable(_char) {
      try {
        var isprint_ptr = Api.findExport("isprint");

        if (utils_1.Utils.isDefined(isprint_ptr)) {
          var isprint_fn = new NativeFunction(isprint_ptr, "int", ["int"]);

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
        utils_1.Utils.logErr("isPrintable", e);
        return false;
      }
    }
  }, {
    key: "javaBacktrace",
    value: function javaBacktrace() {
      return logic_java_1.LogicJava.backtrace();
    }
  }, {
    key: "jvmExplorer",
    value: function jvmExplorer(handle) {
      return logic_java_1.LogicJava.jvmExplorer(handle);
    }
  }, {
    key: "log",
    value: function log(message) {
      if (utils_1.Utils.isDefined(message)) {
        for (var _len = arguments.length, optionalParams = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
          optionalParams[_key - 1] = arguments[_key];
        }

        if (dwarf_1.Dwarf.UI) {
          if (optionalParams.length > 0) {
            optionalParams.forEach(function (param) {
              message += ' ' + param;
            });
          }

          dwarf_1.Dwarf.loggedSend("log:::" + message);
        } else {
          console.log(message, optionalParams);
        }
      }
    }
  }, {
    key: "memoryScan",
    value: function memoryScan(start, size, pattern) {
      var result = [];

      try {
        result = Api._internalMemoryScan(ptr(start), size, pattern);
      } catch (e) {
        utils_1.Utils.logErr("memoryScan", e);
      }

      dwarf_1.Dwarf.loggedSend("memoryscan_result:::" + (0, _stringify["default"])(result));
    }
  }, {
    key: "memoryScanList",
    value: function memoryScanList(ranges, pattern) {
      ranges = JSON.parse(ranges);
      var result = [];

      for (var i = 0; i < ranges.length; i++) {
        try {
          result = result.concat(Api._internalMemoryScan(ptr(ranges[i]["start"]), ranges[i]["size"], pattern));
        } catch (e) {
          utils_1.Utils.logErr("memoryScanList", e);
        }

        if (result.length >= 100) {
          break;
        }
      }

      dwarf_1.Dwarf.loggedSend("memoryscan_result:::" + (0, _stringify["default"])(result));
    }
  }, {
    key: "putBreakpoint",
    value: function putBreakpoint(address_or_class, condition) {
      return logic_breakpoint_1.LogicBreakpoint.putBreakpoint(address_or_class, condition);
    }
  }, {
    key: "putJavaClassInitializationBreakpoint",
    value: function putJavaClassInitializationBreakpoint(className) {
      return logic_java_1.LogicJava.putJavaClassInitializationBreakpoint(className);
    }
  }, {
    key: "putModuleInitializationBreakpoint",
    value: function putModuleInitializationBreakpoint(moduleName) {
      return logic_initialization_1.LogicInitialization.putModuleInitializationBreakpoint(moduleName);
    }
  }, {
    key: "putWatchpoint",
    value: function putWatchpoint(address, flags, callback) {
      var intFlags = 0;

      if (!utils_1.Utils.isDefined(flags)) {
        flags = "rw";
      }

      if (utils_1.Utils.isNumber(flags)) {
        intFlags = flags;
      } else if (utils_1.Utils.isString(flags)) {
        if (flags.indexOf("r") >= 0) {
          intFlags |= watchpoint_1.MEMORY_ACCESS_READ;
        }

        if (flags.indexOf("w") >= 0) {
          intFlags |= watchpoint_1.MEMORY_ACCESS_WRITE;
        }

        if (flags.indexOf("x") >= 0) {
          intFlags |= watchpoint_1.MEMORY_ACCESS_EXECUTE;
        }
      }

      if (!utils_1.Utils.isNumber(intFlags) || intFlags == 0) {
        return;
      }

      return logic_watchpoint_1.LogicWatchpoint.putWatchpoint(address, intFlags, callback);
    }
  }, {
    key: "readString",
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

        if (utils_1.Utils.isString(range.protection) && range.protection.indexOf("r") === -1) {
          return "";
        }

        var _np = new NativePointer(address);

        if (!utils_1.Utils.isDefined(_np)) {
          return "";
        }

        if (Process.platform === "windows") {
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
        utils_1.Utils.logErr("readString", e);
        return "";
      }
    }
  }, {
    key: "readBytes",
    value: function readBytes(address, length) {
      try {
        address = ptr(address);
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
            if (range.protection[0] !== "r") {
              Memory.protect(range.base, range.size, "r--");
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
        utils_1.Utils.logErr("readBytes", e);
        return [];
      }
    }
  }, {
    key: "readPointer",
    value: function readPointer(pt) {
      try {
        return ptr(pt).readPointer();
      } catch (e) {
        utils_1.Utils.logErr("readPointer", e);
        return NULL;
      }
    }
  }, {
    key: "releaseFromJs",
    value: function releaseFromJs(tid) {
      dwarf_1.Dwarf.loggedSend("release_js:::" + tid);
    }
  }, {
    key: "removeBreakpoint",
    value: function removeBreakpoint(address_or_class) {
      return logic_breakpoint_1.LogicBreakpoint.removeBreakpoint(address_or_class);
    }
  }, {
    key: "removeJavaClassInitializationBreakpoint",
    value: function removeJavaClassInitializationBreakpoint(moduleName) {
      var ret = logic_java_1.LogicJava.removeModuleInitializationBreakpoint(moduleName);

      if (ret) {
        dwarf_1.Dwarf.loggedSend("breakpoint_deleted:::java_class_initialization:::" + moduleName);
      }

      return ret;
    }
  }, {
    key: "removeModuleInitializationBreakpoint",
    value: function removeModuleInitializationBreakpoint(moduleName) {
      var ret = logic_initialization_1.LogicInitialization.removeModuleInitializationBreakpoint(moduleName);

      if (ret) {
        dwarf_1.Dwarf.loggedSend("breakpoint_deleted:::module_initialization:::" + moduleName);
      }

      return ret;
    }
  }, {
    key: "removeWatchpoint",
    value: function removeWatchpoint(address) {
      return logic_watchpoint_1.LogicWatchpoint.removeWatchpoint(address);
    }
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
      if (!dwarf_1.Dwarf.PROC_RESUMED) {
        dwarf_1.Dwarf.PROC_RESUMED = true;
        dwarf_1.Dwarf.loggedSend("resume:::0");
      } else {
        console.log("Error: Process already resumed");
      }
    }
  }, {
    key: "setBreakpointCondition",
    value: function setBreakpointCondition(address_or_class, condition) {
      return logic_breakpoint_1.LogicBreakpoint.setBreakpointCondition(address_or_class, condition);
    }
  }, {
    key: "setData",
    value: function setData(key, data) {
      if (typeof key !== "string" && key.length < 1) {
        return;
      }

      if (data.constructor.name === "ArrayBuffer") {
        dwarf_1.Dwarf.loggedSend("set_data:::" + key, data);
      } else {
        if ((0, _typeof2["default"])(data) === "object") {
          data = (0, _stringify["default"])(data, null, 4);
        }

        dwarf_1.Dwarf.loggedSend("set_data:::" + key + ":::" + data);
      }
    }
  }, {
    key: "startJavaTracer",
    value: function startJavaTracer(classes, callback) {
      return logic_java_1.LogicJava.startTrace(classes, callback);
    }
  }, {
    key: "startNativeTracer",
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
    value: function stopJavaTracer() {
      return logic_java_1.LogicJava.stopTrace();
    }
  }, {
    key: "strace",
    value: function strace(callback) {
      return logic_stalker_1.LogicStalker.strace(callback);
    }
  }, {
    key: "updateModules",
    value: function updateModules() {
      var modules = Api.enumerateModules();
      dwarf_1.Dwarf.loggedSend("update_modules:::" + Process.getCurrentThreadId() + ":::" + (0, _stringify["default"])(modules));
    }
  }, {
    key: "updateRanges",
    value: function updateRanges() {
      try {
        dwarf_1.Dwarf.loggedSend("update_ranges:::" + Process.getCurrentThreadId() + ":::" + (0, _stringify["default"])(Process.enumerateRanges("---")));
      } catch (e) {
        utils_1.Utils.logErr("updateRanges", e);
      }
    }
  }, {
    key: "updateSearchableRanges",
    value: function updateSearchableRanges() {
      try {
        dwarf_1.Dwarf.loggedSend("update_searchable_ranges:::" + Process.getCurrentThreadId() + ":::" + (0, _stringify["default"])(Process.enumerateRanges("r--")));
      } catch (e) {
        utils_1.Utils.logErr("updateSearchableRanges", e);
      }
    }
  }, {
    key: "writeBytes",
    value: function writeBytes(address, what) {
      try {
        address = ptr(address);

        if (typeof what === "string") {
          Api.writeUtf8(address, utils_1.Utils.hex2a(what));
        } else {
          address.writeByteArray(what);
        }

        return true;
      } catch (e) {
        utils_1.Utils.logErr("writeBytes", e);
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
        utils_1.Utils.logErr("writeUtf8", e);
        return false;
      }
    }
  }]);
  return Api;
}();

exports.Api = Api;

},{"./dwarf":103,"./fs":104,"./logic_breakpoint":107,"./logic_initialization":108,"./logic_java":109,"./logic_objc":110,"./logic_stalker":111,"./logic_watchpoint":112,"./thread_wrapper":116,"./utils":117,"./watchpoint":118,"@babel/runtime-corejs2/core-js/json/stringify":3,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/core-js/parse-int":8,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/createClass":12,"@babel/runtime-corejs2/helpers/interopRequireDefault":13,"@babel/runtime-corejs2/helpers/typeof":14}],102:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.Breakpoint = void 0;

var Breakpoint = function Breakpoint(target) {
  (0, _classCallCheck2["default"])(this, Breakpoint);
  this.target = target;
};

exports.Breakpoint = Breakpoint;

},{"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],103:[function(require,module,exports){
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
exports.Dwarf = void 0;

var api_1 = require("./api");

var logic_breakpoint_1 = require("./logic_breakpoint");

var interceptor_1 = require("./interceptor");

var logic_java_1 = require("./logic_java");

var logic_initialization_1 = require("./logic_initialization");

var logic_watchpoint_1 = require("./logic_watchpoint");

var utils_1 = require("./utils");

var Dwarf = function () {
  var Dwarf = /*#__PURE__*/function () {
    function Dwarf() {
      (0, _classCallCheck2["default"])(this, Dwarf);
    }

    (0, _createClass2["default"])(Dwarf, null, [{
      key: "init",
      value: function init(breakStart, debug, spawned, isUi) {
        Dwarf.BREAK_START = breakStart;
        Dwarf.DEBUG = debug;
        Dwarf.SPAWNED = spawned;
        Dwarf.UI = isUi;

        if (logic_java_1.LogicJava.available) {
          logic_java_1.LogicJava.init();
        }

        logic_initialization_1.LogicInitialization.init();
        interceptor_1.DwarfInterceptor.init();
        var exclusions = ['constructor', 'length', 'name', 'prototype'];
        (0, _getOwnPropertyNames["default"])(api_1.Api).forEach(function (prop) {
          if (exclusions.indexOf(prop) < 0) {
            global[prop] = api_1.Api[prop];
          }
        });

        if (Process.platform === 'windows') {
          this.modulesBlacklist.push('ntdll.dll');

          if (Process.arch === 'x64') {
            this.modulesBlacklist.push('win32u.dll');
          }
        } else if (Process.platform === 'linux') {
          if (utils_1.Utils.isDefined(logic_java_1.LogicJava) && logic_java_1.LogicJava.sdk <= 23) {
            this.modulesBlacklist.push('app_process');
          }
        }

        Process.setExceptionHandler(Dwarf.handleException);

        if (Process.platform === 'windows') {
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
  return Dwarf;
}();

exports.Dwarf = Dwarf;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./api":101,"./interceptor":106,"./logic_breakpoint":107,"./logic_initialization":108,"./logic_java":109,"./logic_watchpoint":112,"./utils":117,"@babel/runtime-corejs2/core-js/json/stringify":3,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/core-js/object/get-own-property-names":6,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/createClass":12,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],104:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.FileSystem = void 0;

var api_1 = require("./api");

var FileSystem = /*#__PURE__*/function () {
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
  }, {
    key: "allocateRw",
    value: function allocateRw(size) {
      var pt = Memory.alloc(size);
      Memory.protect(pt, size, 'rw-');
      return pt;
    }
  }, {
    key: "allocateString",
    value: function allocateString(what) {
      return Memory.allocUtf8String(what);
    }
  }, {
    key: "fopen",
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
    value: function writeStringToFile(filePath, content, append) {
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

},{"./api":101,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/createClass":12,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],105:[function(require,module,exports){
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
  init: function init(breakStart, debug, spawned, isUi) {
    if (!utils_1.Utils.isDefined(isUi)) {
      isUi = false;
    }

    dwarf_1.Dwarf.init(breakStart, debug, spawned, isUi);
  },
  keywords: function keywords() {
    var map = [];
    (0, _getOwnPropertyNames["default"])(global).forEach(function (name) {
      map.push(name);

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
},{"./api":101,"./dwarf":103,"./thread_api":114,"./utils":117,"@babel/runtime-corejs2/core-js/date/now":1,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/core-js/object/get-own-property-names":6,"@babel/runtime-corejs2/core-js/object/keys":7,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],106:[function(require,module,exports){
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
exports.DwarfInterceptor = void 0;

var utils_1 = require("./utils");

var dwarf_1 = require("./dwarf");

var thread_context_1 = require("./thread_context");

var DwarfInterceptor = /*#__PURE__*/function () {
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

      clone.attach = function attach(target, callbacksOrProbe, data) {
        if (target.hasOwnProperty('handle')) {
          target.handle.readU8();
        } else {
          target.readU8();
        }

        var replacement;

        if (typeof callbacksOrProbe === 'function') {
          replacement = function replacement() {
            DwarfInterceptor.onAttach(this.context);
            var ret = callbacksOrProbe.apply(this, arguments);
            DwarfInterceptor.onDetach();
            return ret;
          };
        } else if ((0, _typeof2["default"])(callbacksOrProbe) === 'object') {
          if (utils_1.Utils.isDefined(callbacksOrProbe['onEnter'])) {
            replacement = {
              onEnter: function onEnter() {
                DwarfInterceptor.onAttach(this.context);
                var ret = callbacksOrProbe['onEnter'].apply(this, arguments);
                DwarfInterceptor.onDetach();
                return ret;
              }
            };

            if (utils_1.Utils.isDefined(callbacksOrProbe['onLeave'])) {
              replacement['onLeave'] = callbacksOrProbe['onLeave'];
            }
          } else {
            replacement = callbacksOrProbe;
          }
        }

        return Interceptor['_attach'](target, replacement, data);
      };

      global['Interceptor'] = clone;
    }
  }]);
  return DwarfInterceptor;
}();

exports.DwarfInterceptor = DwarfInterceptor;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./dwarf":103,"./thread_context":115,"./utils":117,"@babel/runtime-corejs2/core-js/object/assign":4,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/createClass":12,"@babel/runtime-corejs2/helpers/interopRequireDefault":13,"@babel/runtime-corejs2/helpers/typeof":14}],107:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.LogicBreakpoint = void 0;

var api_1 = require("./api");

var breakpoint_1 = require("./breakpoint");

var dwarf_1 = require("./dwarf");

var logic_java_1 = require("./logic_java");

var logic_objc_1 = require("./logic_objc");

var logic_stalker_1 = require("./logic_stalker");

var thread_context_1 = require("./thread_context");

var utils_1 = require("./utils");

var LogicBreakpoint = function () {
  var LogicBreakpoint = /*#__PURE__*/function () {
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
            var stalkerInfo = logic_stalker_1.LogicStalker.stalkerInfoMap[tid];

            if (threadApi.apiFunction === '_step') {
              if (!utils_1.Utils.isDefined(stalkerInfo)) {
                logic_stalker_1.LogicStalker.stalk(tid);
              }

              release = true;
              break;
            } else if (threadApi.apiFunction === 'release') {
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
  return LogicBreakpoint;
}();

exports.LogicBreakpoint = LogicBreakpoint;

},{"./api":101,"./breakpoint":102,"./dwarf":103,"./logic_java":109,"./logic_objc":110,"./logic_stalker":111,"./thread_context":115,"./utils":117,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/createClass":12,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],108:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _getIterator2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/get-iterator"));

var _keys = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/keys"));

var _stringify = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/json/stringify"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.LogicInitialization = void 0;

var api_1 = require("./api");

var dwarf_1 = require("./dwarf");

var logic_breakpoint_1 = require("./logic_breakpoint");

var logic_java_1 = require("./logic_java");

var utils_1 = require("./utils");

var LogicInitialization = function () {
  var LogicInitialization = /*#__PURE__*/function () {
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
            userCallback.call(this);
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
          var dvmModule = Process.findModuleByName("libdvm.so");

          if (dvmModule) {
            var artModule = Process.findModuleByName("libart.so");

            if (artModule) {
              var _iteratorNormalCompletion = true;
              var _didIteratorError = false;
              var _iteratorError = undefined;

              try {
                for (var _iterator = (0, _getIterator2["default"])(artModule.enumerateExports()), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
                  var moduleExportDetail = _step.value;

                  if (moduleExportDetail.name.indexOf("LoadNativeLibrary") != -1) {
                    (function () {
                      console.log('hook loadnative');
                      var argNum = logic_java_1.LogicJava.sdk <= 22 ? 1 : 2;
                      Interceptor.attach(moduleExportDetail.address, {
                        onEnter: function onEnter(args) {
                          var moduleName = utils_1.Utils.readStdString(args[argNum]);
                          LogicInitialization.hitModuleLoading.apply(this, [moduleName]);
                        }
                      });
                    })();
                  }
                }
              } catch (err) {
                _didIteratorError = true;
                _iteratorError = err;
              } finally {
                try {
                  if (!_iteratorNormalCompletion && _iterator["return"] != null) {
                    _iterator["return"]();
                  }
                } finally {
                  if (_didIteratorError) {
                    throw _iteratorError;
                  }
                }
              }
            }

            var _iteratorNormalCompletion2 = true;
            var _didIteratorError2 = false;
            var _iteratorError2 = undefined;

            try {
              for (var _iterator2 = (0, _getIterator2["default"])(dvmModule.enumerateExports()), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
                var _moduleExportDetail = _step2.value;

                if (_moduleExportDetail.name.indexOf("dvmLoadNativeCode") != -1) {
                  console.log('hook dvmLoadNativeCode');
                  Interceptor.attach(_moduleExportDetail.address, {
                    onEnter: function onEnter(args) {
                      var moduleName = args[0].readUtf8String();
                      LogicInitialization.hitModuleLoading.apply(this, [moduleName]);
                    }
                  });
                }
              }
            } catch (err) {
              _didIteratorError2 = true;
              _iteratorError2 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion2 && _iterator2["return"] != null) {
                  _iterator2["return"]();
                }
              } finally {
                if (_didIteratorError2) {
                  throw _iteratorError2;
                }
              }
            }
          } else {
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
  return LogicInitialization;
}();

exports.LogicInitialization = LogicInitialization;

},{"./api":101,"./dwarf":103,"./logic_breakpoint":107,"./logic_java":109,"./utils":117,"@babel/runtime-corejs2/core-js/get-iterator":2,"@babel/runtime-corejs2/core-js/json/stringify":3,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/core-js/object/keys":7,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/createClass":12,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],109:[function(require,module,exports){
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
exports.LogicJava = void 0;

var breakpoint_1 = require("./breakpoint");

var dwarf_1 = require("./dwarf");

var logic_breakpoint_1 = require("./logic_breakpoint");

var utils_1 = require("./utils");

var isDefined = utils_1.Utils.isDefined;

var LogicJava = function () {
  var LogicJava = /*#__PURE__*/function () {
    function LogicJava() {
      (0, _classCallCheck2["default"])(this, LogicJava);
    }

    (0, _createClass2["default"])(LogicJava, null, [{
      key: "applyTracerImplementationAtClass",
      value: function applyTracerImplementationAtClass(className, attach, callback) {
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
          if (e.toString().indexOf('ClassNotFoundException') >= 0) {
            LogicJava.hookClassLoaderClassInitialization(className, function (clazz) {
              LogicJava.applyTracerImplementationAtClass(clazz, attach, callback);
            });
          } else if (e.toString().indexOf('no supported overloads') < 0) {
            utils_1.Utils.logErr('LogicJava.startTrace', e);
          }
        }
      }
    }, {
      key: "applyTracerImplementation",
      value: function applyTracerImplementation(attach, callback) {
        Java.performNow(function () {
          LogicJava.tracedClasses.forEach(function (className) {
            LogicJava.applyTracerImplementationAtClass(className, attach, callback);
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

        var result = false;
        Java.performNow(function () {
          result = LogicJava.hookInJVM(className, method, implementation);
        });
        return result;
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
          } catch (err) {
            return false;
          }

          utils_1.Utils.logErr('LogicJava.hook', err);

          if (handler === null) {
            return false;
          }
        }

        try {
          if (handler == null || typeof handler[method] === 'undefined') {
            return false;
          }
        } catch (e) {
          utils_1.Utils.logErr('LogicJava.hook', e);
          return false;
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
          return LogicJava.hook(targetClass, targetMethod, implementation);
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
              LogicJava.hookInJVM('com.android.internal.os.RuntimeInit', 'commonInit', function () {
                LogicJava.jvmBreakpoint.call(this, 'com.android.internal.os.RuntimeInit', 'commonInit', arguments, this.overload.argumentTypes);
              });
            } else {
              LogicJava.hookInJVM('android.app.Application', 'onCreate', function () {
                LogicJava.jvmBreakpoint.call(this, 'android.app.Application', 'onCreate', arguments, this.overload.argumentTypes);
              });
            }
          }

          var handler = Java.use('java.lang.ClassLoader');
          var overload = handler.loadClass.overload('java.lang.String', 'boolean');

          overload.implementation = function (clazz, resolve) {
            if (LogicJava.javaClasses.indexOf(clazz) === -1) {
              LogicJava.javaClasses.push(clazz);
              dwarf_1.Dwarf.loggedSend('class_loader_loading_class:::' + Process.getCurrentThreadId() + ':::' + clazz);
              var userCallback = LogicJava.javaClassLoaderCallbacks[clazz];

              if (typeof userCallback !== 'undefined') {
                if (userCallback !== null) {
                  userCallback.call(this, clazz);
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
                if (typeof handle[name] !== 'undefined') {
                  sub_handle_class = handle[name]['$className'];
                }
              }

              if (typeof handle[name] !== 'undefined' && typeof handle[name]['$handle'] !== 'undefined' && handle[name]['$handle'] !== null) {
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
        var result = false;

        if (target.endsWith('.$init')) {
          result = LogicJava.hook(target, '$init', function () {
            LogicJava.jvmBreakpoint(this.className, this.method, arguments, this.overload.argumentTypes, condition);
          });
        } else {
          result = LogicJava.hookJavaMethod(target, function () {
            LogicJava.jvmBreakpoint(this.className, this.method, arguments, this.overload.argumentTypes, condition);
          });
        }

        return result;
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
        LogicJava.tracerDepth = 1;
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
        LogicJava.tracerDepth = 1;
        LogicJava.applyTracerImplementation(true);
        return true;
      }
    }, {
      key: "traceImplementation",
      value: function traceImplementation(callback, className, method) {
        return function () {
          var uiCallback = !utils_1.Utils.isDefined(callback);
          var classMethod = className + '.' + method;
          var thatObject = {
            $className: className,
            method: method,
            depth: LogicJava.tracerDepth
          };

          if (uiCallback) {
            dwarf_1.Dwarf.loggedSend('java_trace:::enter:::' + classMethod + ':::' + (0, _stringify["default"])(arguments));
          } else {
            if (utils_1.Utils.isDefined(callback['onEnter'])) {
              callback['onEnter'].apply(thatObject, arguments);
            } else if (typeof callback === 'function') {
              callback.apply(thatObject, arguments);
            }
          }

          LogicJava.tracerDepth += 1;
          var ret = this[method].apply(this, arguments);
          LogicJava.tracerDepth -= 1;

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
              var tempRet = callback['onLeave'].apply(thatObject, ret);

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
  LogicJava.tracerDepth = 1;
  LogicJava.sdk = 0;
  return LogicJava;
}();

exports.LogicJava = LogicJava;

},{"./breakpoint":102,"./dwarf":103,"./logic_breakpoint":107,"./utils":117,"@babel/runtime-corejs2/core-js/json/stringify":3,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/core-js/object/get-own-property-names":6,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/createClass":12,"@babel/runtime-corejs2/helpers/interopRequireDefault":13,"@babel/runtime-corejs2/helpers/typeof":14}],110:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.LogicObjC = void 0;

var breakpoint_1 = require("./breakpoint");

var dwarf_1 = require("./dwarf");

var logic_breakpoint_1 = require("./logic_breakpoint");

var utils_1 = require("./utils");

var LogicObjC = function () {
  var LogicObjC = /*#__PURE__*/function () {
    function LogicObjC() {
      (0, _classCallCheck2["default"])(this, LogicObjC);
    }

    (0, _createClass2["default"])(LogicObjC, null, [{
      key: "applyTracerImplementation",
      value: function applyTracerImplementation(attach, callback) {
        dwarf_1.Dwarf.loggedSend('Not implemented');
      }
    }, {
      key: "backtrace",
      value: function backtrace() {
        dwarf_1.Dwarf.loggedSend('Not implemented');
      }
    }, {
      key: "getApplicationContext",
      value: function getApplicationContext() {
        dwarf_1.Dwarf.loggedSend('Not implemented');
      }
    }, {
      key: "hookAllObjCMethods",
      value: function hookAllObjCMethods(className, implementation) {
        dwarf_1.Dwarf.loggedSend('Not implemented');
        return false;
      }
    }, {
      key: "hookClassLoaderClassInitialization",
      value: function hookClassLoaderClassInitialization(clazz, callback) {
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
        dwarf_1.Dwarf.loggedSend('Not implemented');
      }
    }, {
      key: "jvmBreakpoint",
      value: function jvmBreakpoint(className, method, args, types, condition) {
        dwarf_1.Dwarf.loggedSend('Not implemented');
      }
    }, {
      key: "jvmExplorer",
      value: function jvmExplorer(what) {
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
          delete LogicObjC.breakpoints[target.toString()];
          return true;
        }

        return false;
      }
    }, {
      key: "removeModuleInitializationBreakpoint",
      value: function removeModuleInitializationBreakpoint(clazz) {
        dwarf_1.Dwarf.loggedSend('Not implemented');
      }
    }, {
      key: "restartApplication",
      value: function restartApplication() {
        dwarf_1.Dwarf.loggedSend('Not implemented');
        return false;
      }
    }, {
      key: "startTrace",
      value: function startTrace(classes, callback) {
        dwarf_1.Dwarf.loggedSend('Not implemented');
        return false;
      }
    }, {
      key: "stopTrace",
      value: function stopTrace() {
        dwarf_1.Dwarf.loggedSend('Not implemented');
        return false;
      }
    }, {
      key: "traceImplementation",
      value: function traceImplementation(callback, className, method) {
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
  return LogicObjC;
}();

exports.LogicObjC = LogicObjC;

},{"./breakpoint":102,"./dwarf":103,"./logic_breakpoint":107,"./utils":117,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/createClass":12,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],111:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _parseInt2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/parse-int"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.LogicStalker = void 0;

var dwarf_1 = require("./dwarf");

var logic_breakpoint_1 = require("./logic_breakpoint");

var stalker_info_1 = require("./stalker_info");

var utils_1 = require("./utils");

var LogicStalker = function () {
  var LogicStalker = /*#__PURE__*/function () {
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
          var initialContextAddress = ptr((0, _parseInt2["default"])(context.context.pc));
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
        var putCallout = true;

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
            }

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
  return LogicStalker;
}();

exports.LogicStalker = LogicStalker;

},{"./dwarf":103,"./logic_breakpoint":107,"./stalker_info":113,"./utils":117,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/core-js/parse-int":8,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/createClass":12,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],112:[function(require,module,exports){
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
exports.LogicWatchpoint = void 0;

var dwarf_1 = require("./dwarf");

var watchpoint_1 = require("./watchpoint");

var utils_1 = require("./utils");

var logic_breakpoint_1 = require("./logic_breakpoint");

var isDefined = utils_1.Utils.isDefined;

var LogicWatchpoint = function () {
  var LogicWatchpoint = /*#__PURE__*/function () {
    function LogicWatchpoint() {
      (0, _classCallCheck2["default"])(this, LogicWatchpoint);
    }

    (0, _createClass2["default"])(LogicWatchpoint, null, [{
      key: "attachMemoryAccessMonitor",
      value: function attachMemoryAccessMonitor() {
        var monitorAddresses = new Array();
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
          if (exception.type === 'access-violation') {
            watchpoint = LogicWatchpoint.memoryWatchpoints[exception.memory.address.toString()];

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
          var invocationListener = Interceptor.attach(exception.address, function (args) {
            invocationListener.detach();
            Interceptor['flush']();

            if (watchpoint.callback !== null) {
              watchpoint.callback.call(this, args);
            } else {
              logic_breakpoint_1.LogicBreakpoint.breakpoint(logic_breakpoint_1.LogicBreakpoint.REASON_WATCHPOINT, this.context.pc, this.context);
            }

            if (isDefined(LogicWatchpoint.memoryWatchpoints[exception.memory.address.toString()]) && !(watchpoint.flags & watchpoint_1.MEMORY_WATCH_SINGLE_SHOT)) {
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
        var operation = details.operation;
        var fromPtr = details.from;
        var address = details.address;
        var watchpoint = null;

        if ((0, _keys["default"])(LogicWatchpoint.memoryWatchpoints).length > 0) {
          watchpoint = LogicWatchpoint.memoryWatchpoints[address.toString()];

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
          var invocationListener = Interceptor.attach(fromPtr, function (args) {
            invocationListener.detach();
            Interceptor['flush']();

            if (watchpoint.callback !== null) {
              watchpoint.callback.call(this, args);
            } else {
              logic_breakpoint_1.LogicBreakpoint.breakpoint(logic_breakpoint_1.LogicBreakpoint.REASON_WATCHPOINT, this.context.pc, this.context);
            }

            if (isDefined(LogicWatchpoint.memoryWatchpoints[address.toString()]) && !(watchpoint.flags & watchpoint_1.MEMORY_WATCH_SINGLE_SHOT)) {
              LogicWatchpoint.attachMemoryAccessMonitor();
            }
          });
        }

        return watchpoint !== null;
      }
    }, {
      key: "putWatchpoint",
      value: function putWatchpoint(address) {
        var flags = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : watchpoint_1.MEMORY_ACCESS_READ | watchpoint_1.MEMORY_ACCESS_WRITE;
        var callback = arguments.length > 2 ? arguments[2] : undefined;
        var memPtr;

        if (typeof address === 'string') {
          memPtr = ptr(address);
        } else {
          memPtr = address;
        }

        if (memPtr.isNull()) {
          throw new Error('putWatchpoint: Invalid PointerValue!');
        }

        var watchpoint = null;

        if (typeof callback === 'undefined') {
          callback = null;
        }

        if (!LogicWatchpoint.memoryWatchpoints.hasOwnProperty(memPtr.toString())) {
          var rangeDetails = Process.findRangeByAddress(memPtr);

          if (rangeDetails === null) {
            console.log('failed to find memory range for ' + memPtr.toString());
            return null;
          }

          watchpoint = new watchpoint_1.Watchpoint(memPtr, flags, rangeDetails.protection, callback);
          LogicWatchpoint.memoryWatchpoints[memPtr.toString()] = watchpoint;
          dwarf_1.Dwarf.loggedSend('watchpoint_added:::' + memPtr.toString() + ':::' + flags + ':::' + (0, _stringify["default"])(watchpoint.debugSymbol));

          if (Process.platform === 'windows') {
            LogicWatchpoint.attachMemoryAccessMonitor();
          } else {
            if (watchpoint) {
              watchpoint.watch();
            }
          }

          return watchpoint;
        } else {
          console.log(memPtr.toString() + ' is already watched');
          return null;
        }
      }
    }, {
      key: "removeWatchpoint",
      value: function removeWatchpoint(address) {
        var memPtr;

        if (typeof address === 'string') {
          memPtr = ptr(address);
        } else {
          memPtr = address;
        }

        if (memPtr.isNull()) {
          throw new Error('removeWatchpoint: Invalid PointerValue!');
        }

        if (!LogicWatchpoint.memoryWatchpoints.hasOwnProperty(memPtr.toString())) {
          throw new Error('removeWatchpoint: No Watchpoint for given address!');
        }

        var watchpoint = LogicWatchpoint.memoryWatchpoints[memPtr.toString()];

        if (Process.platform === 'windows') {
          MemoryAccessMonitor.disable();
        }

        watchpoint.restore();
        delete LogicWatchpoint.memoryWatchpoints[memPtr.toString()];

        if (Process.platform === 'windows') {
          LogicWatchpoint.attachMemoryAccessMonitor();
        }

        dwarf_1.Dwarf.loggedSend('watchpoint_removed:::' + memPtr.toString());
        return true;
      }
    }]);
    return LogicWatchpoint;
  }();

  LogicWatchpoint.memoryWatchpoints = {};
  return LogicWatchpoint;
}();

exports.LogicWatchpoint = LogicWatchpoint;

},{"./dwarf":103,"./logic_breakpoint":107,"./utils":117,"./watchpoint":118,"@babel/runtime-corejs2/core-js/json/stringify":3,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/core-js/object/keys":7,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/createClass":12,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],113:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.StalkerInfo = void 0;

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

},{"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],114:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.ThreadApi = void 0;

var ThreadApi = function ThreadApi(apiFunction, apiArguments) {
  (0, _classCallCheck2["default"])(this, ThreadApi);
  this.result = null;
  this.consumed = false;
  this.apiFunction = apiFunction;
  this.apiArguments = apiArguments;
};

exports.ThreadApi = ThreadApi;

},{"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],115:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.ThreadContext = void 0;

var ThreadContext = function ThreadContext(tid) {
  (0, _classCallCheck2["default"])(this, ThreadContext);
  this.context = null;
  this.javaHandle = null;
  this.apiQueue = [];
  this.preventSleep = false;
  this.tid = tid;
};

exports.ThreadContext = ThreadContext;

},{"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],116:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.ThreadWrapper = void 0;

var dwarf_1 = require("./dwarf");

var ThreadWrapper = function () {
  var ThreadWrapper = /*#__PURE__*/function () {
    function ThreadWrapper() {
      (0, _classCallCheck2["default"])(this, ThreadWrapper);
    }

    (0, _createClass2["default"])(ThreadWrapper, null, [{
      key: "init",
      value: function init() {
        ThreadWrapper.pthreadCreateAddress = Module.findExportByName(null, 'pthread_create');

        if (ThreadWrapper.pthreadCreateAddress != null && !ThreadWrapper.pthreadCreateAddress.isNull()) {
          ThreadWrapper.pthreadCreateImplementation = new NativeFunction(ThreadWrapper.pthreadCreateAddress, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
          ThreadWrapper.handler = Memory.alloc(Process.pointerSize);
          Memory.protect(ThreadWrapper.handler, Process.pointerSize, 'rwx');

          if (Process.arch === 'arm64') {
            ThreadWrapper.handler.writeByteArray([0xE1, 0x03, 0x01, 0xAA, 0xC0, 0x03, 0x5F, 0xD6]);
          }

          Interceptor.replace(ThreadWrapper.handler, new NativeCallback(function () {
            if (ThreadWrapper.handlerFunction !== null) {
              var ret = ThreadWrapper.handlerFunction.apply(this);
              ThreadWrapper.handlerFunction = null;
              return ret;
            }

            return 0;
          }, 'int', []));
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
        if (ThreadWrapper.pthreadCreateAddress !== null) {
          return 1;
        }

        if (typeof fn !== 'function') {
          return 2;
        }

        var pthread_t = Memory.alloc(Process.pointerSize);
        Memory.protect(pthread_t, Process.pointerSize, 'rwx');
        ThreadWrapper.handlerFunction = fn;
        return ThreadWrapper.pthreadCreateImplementation(pthread_t, ptr(0), ThreadWrapper.handler, ptr(0));
      }
    }, {
      key: "sleep",
      value: function sleep(delay) {
        Thread.sleep(delay);
      }
    }, {
      key: "onCreate",
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
  return ThreadWrapper;
}();

exports.ThreadWrapper = ThreadWrapper;

},{"./dwarf":103,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/createClass":12,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],117:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _keys = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/keys"));

var _stringify = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/json/stringify"));

var _parseInt2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/parse-int"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.Utils = void 0;
var Utils;

(function (Utils) {
  function isDefined(value) {
    return value !== undefined && value !== null && typeof value !== "undefined";
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
      return "";
    }

    var hexStr = "";

    for (var i = 0; i < uint8arr.length; i++) {
      var hex = (uint8arr[i] & 0xff).toString(16);
      hex = hex.length === 1 ? "0" + hex : hex;
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
    if (Process.arch.indexOf("arm") !== -1) {
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
    var now = date["getHourMinuteSecond"]();
    var to_log = "";
    (0, _keys["default"])(data).forEach(function (argN) {
      var what = data[argN];

      if (what instanceof ArrayBuffer) {
        console.log(hexdump(what));
      } else if (what instanceof Object) {
        what = (0, _stringify["default"])(what, null, 2);
      }

      if (to_log !== "") {
        to_log += "\t";
      }

      to_log += what;
    });

    if (to_log !== "") {
      console.log(now, to_log);
    }
  }

  Utils.logDebug = logDebug;

  function logErr(tag, err) {
    logDebug("[ERROR-" + tag + "] " + err);
  }

  Utils.logErr = logErr;

  function readStdString(arg) {
    var isTiny = (arg.readU8() & 1) === 0;

    if (isTiny) {
      return arg.add(1).readUtf8String();
    }

    return arg.add(2 * Process.pointerSize).readPointer().readUtf8String();
  }

  Utils.readStdString = readStdString;
})(Utils = exports.Utils || (exports.Utils = {}));

},{"@babel/runtime-corejs2/core-js/json/stringify":3,"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/core-js/object/keys":7,"@babel/runtime-corejs2/core-js/parse-int":8,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}],118:[function(require,module,exports){
"use strict";

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

(0, _defineProperty["default"])(exports, "__esModule", {
  value: true
});
exports.Watchpoint = exports.MEMORY_WATCH_SINGLE_SHOT = exports.MEMORY_ACCESS_EXECUTE = exports.MEMORY_ACCESS_WRITE = exports.MEMORY_ACCESS_READ = void 0;
exports.MEMORY_ACCESS_READ = 1;
exports.MEMORY_ACCESS_WRITE = 2;
exports.MEMORY_ACCESS_EXECUTE = 4;
exports.MEMORY_WATCH_SINGLE_SHOT = 8;

var Watchpoint = /*#__PURE__*/function () {
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

},{"@babel/runtime-corejs2/core-js/object/define-property":5,"@babel/runtime-corejs2/helpers/classCallCheck":11,"@babel/runtime-corejs2/helpers/createClass":12,"@babel/runtime-corejs2/helpers/interopRequireDefault":13}]},{},[105]);
