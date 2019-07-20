Combining dwarf Android native onload with r2 js api to automate the reaching of initialization functions.

the most recent version of onload hooks in Android exists in Dwarf by attaching **soinfo::call_constructor()**

the register argument 0 holds the pointer of the current **soinfo_struct**

I did the parse of the struct until relevant things.

```javascript
const soinfo_struct = 'ppppppppppppppppppppppppp phdr phnum base size dynamic ' +
	'next strtab symtab nbucket nchain bucket chain plt_got plt_rel plt_rel_count rel rel_count,' +
	' preinit_array preinit_array_count init_array init_array_count fini_array fini_array_count init_func fini_func';

api.hookNativeOnLoad('libtarget.so', function () {
	var soinfo = this.context.x0;
	r2('s ' + soinfo);
	console.log(r2('pf ' + soinfo_struct));
	var p = JSON.parse(r2('pfj ' + soinfo_struct));

	var initArray = null;
	var initArraySize = 0;

	p.forEach(function (field) {
		if (field.name === 'init_array') {
			initArray = ptr(field.value);
		} else if (field.name === 'init_array_count') {
			initArraySize = field.value;
		}
	});

	if (initArray !== null) {
		console.log('\n\ninit array at: ' + initArray + '\nsize: ' + initArraySize);
		var functions = [];
		for (var i=0;i<initArraySize;i++) {
			functions.push(initArray.add(Process.pointerSize * i).readPointer());
		}
		console.log(functions);
	}
});
```

![DWARF](https://i.ibb.co/tJ49x6V/Screenshot-from-2019-07-20-20-50-16.png)
