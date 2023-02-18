
//console.log("Hello from JS");
//
//var counter = Memory.alloc(0x10);
//var bump = null;
//cs.counter = counter;
//rpc.exports.init = () => {
//  bump = new NativeFunction(cm.bump,'void',['int']);
//}
//
//demo()


hook('libttmplayer.so',0xF6978) //x1 +8 寄存器有字符串

function hook(so, addr) {
	let lib = Module.findBaseAddress(so);
	while (lib == null) {
		lib = Module.findBaseAddress(so);
	}
  send(lib)

 var  openImpl = lib.add(addr)

Interceptor.attach(openImpl, new CModule(`
  #include <gum/guminterceptor.h>

  extern void onMessage (const gchar * message);

  static void log (const gchar * format, ...);

  void
  onEnter (GumInvocationContext * ic)
  {
    log ("open() path=\\"%s\\"", "path");
  }

  void
  onLeave (GumInvocationContext * ic)
  {
    int fd = 1;
    log ("=> fd=%d", fd);
  }

  static void
  log (const gchar * format,
       ...)
  {
    gchar * message;
    va_list args;

    va_start (args, format);
    message = g_strdup_vprintf (format, args);
    va_end (args);

    onMessage (message);

    g_free (message);
  }
`, {
  onMessage: new NativeCallback(messagePtr => {
    const message = messagePtr.readUtf8String();
    send(message)
  }, 'void', ['pointer'])
}));
}





function demo() {
  //  const openImpl = Module.getExportByName("libc.so", 'open');

  Process.setExceptionHandler((details)=>{

    console.log(details);

  })

  rpc.exports.c = (openImpl) => {
    openImpl = new NativePointer(openImpl);
    console.log("c->"+openImpl);
  Interceptor.attach(openImpl, new CModule(`
    #include <gum/guminterceptor.h>
    #include <stdio.h>

    void
    onEnter (GumInvocationContext * ic)
    {
    //  const char * path;

     // path = gum_invocation_context_get_nth_argument (ic, 0);

      //printf ("open() path=\\"%s\\"\\n", path);
      printf("enter -> cc");
	frida_log("Hello from C");
    }

    void
    onLeave (GumInvocationContext * ic)
    {
      unsigned int fd;

  //    fd = (int) gum_invocation_context_get_return_value (ic);
   //   fd = (uintptr_t) gum_invocation_context_get_return_value (ic);

      //printf ("=> fd=%d\\n", fd);
      printf ("=> fd=");
    }
  `));
  }
}
