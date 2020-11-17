# pyminhook

Minimal python library for hooking.
A python wrapper for the [Minhook](https://github.com/TsudaKageyu/minhook) dll.

Tested locally with python 2.7.15 (32 and 64 bit) and python 3.7.2 (32 bit), python 3.7.9 (64 bit)

### Example
A small example exists in the examples directory
    
    # add function definitions - required for wrapper callback
    class my_func_defs:
	    functions = ["MessageBoxA", "send"]
	    MessageBoxAPrototype = ctypes.WINFUNCTYPE(DWORD, LPVOID, LPSTR, LPSTR, LPVOID)
	    sendPrototype = ctypes.WINFUNCTYPE(ctypes.c_uint, LPVOID, LPSTR, ctypes.c_uint, ctypes.c_uint)
	    
	pyminhook.add_function_definitions(my_func_defs)
	
	# define the callback function
	@pyminhook.MessageBoxACallback
    def msgbox_hook(a, content, title, c, real_function):
	    k = real_function(0, b"lol", b"lol", 1)
	    return k
	    
	# hook it
	pyminhook.MH_Initialize()
	hook_entry = pyminhook.hook_entry.from_dll_name_and_apiname(b"user32", b"MessageBoxA", msgbox_hook)
	hook_entry.enable()
	
    # test it
    ctypes.windll.user32.MessageBoxA(0, b"hi", b"hi", 0)
    
    