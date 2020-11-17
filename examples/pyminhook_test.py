import ctypes
import pyminhook
from ctypes.wintypes import *
import urllib
try:
	import urllib.request as urllib
except Exception as e:
	pass


class my_func_defs:
	functions = ["MessageBoxA", "send"]
	
	MessageBoxAPrototype = ctypes.WINFUNCTYPE(DWORD, LPVOID, LPSTR, LPSTR, LPVOID)
	sendPrototype = ctypes.WINFUNCTYPE(ctypes.c_uint, LPVOID, LPSTR, ctypes.c_uint, ctypes.c_uint)


pyminhook.add_function_definitions(my_func_defs)

@pyminhook.MessageBoxACallback
def msgbox_hook(a, content, title, c, real_function):
	k = real_function(0, b"lol", b"lol", 1)
	return k

@pyminhook.sendCallback
def send_hook(*args, **kwargs):
	s, buf, len, flags = args
	
	real_value = kwargs['real_function']()
	
	print ("SOCK SEND:", buf.value)
	
	return real_value


def test_networking():
	hook_entry_2 = pyminhook.hook_entry.from_dll_name_and_apiname(b"ws2_32", b"send", send_hook)
	hook_entry_2.enable()
	
	print ("networking enabled hook")
	bla = urllib.urlopen("http://google.com")
	
	
	hook_entry_2.disable()
	print ("networking disabled hook")
	bla = urllib.urlopen("http://google.com")
	
	
	
def test_messagebox():
	print ("before enable msgbox hook")
	ctypes.windll.user32.MessageBoxA(0, b"hi", b"hi", 0)
	# import pdb;pdb.set_trace()
	hook_entry = pyminhook.hook_entry.from_dll_name_and_apiname(b"user32", b"MessageBoxA", msgbox_hook)
	hook_entry.enable()
	print ("after enable msgbox hook")
	ctypes.windll.user32.MessageBoxA(0, b"hi", b"hi", 0)
	
	

def main():
	pyminhook.MH_Initialize()
	
	test_messagebox()
	test_networking()
	
	pyminhook.MH_Uninitialize()
	

if __name__ == "__main__":
	main()
	