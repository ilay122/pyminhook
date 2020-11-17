import sys, os
from ctypes import *
from ctypes.wintypes import *
import functools
import ctypes

# should functions return an error code or just throw an exception?
THROW_EXCEPTIONS = True

# Path stuff related
x86 = "x86"
x64 = "x64"
dll_name_without_bitness = "MinHook.{}.dll"

minhook_dll_name = dll_name_without_bitness.format(x86)
if sys.maxsize > 2**32:
	# 64 bit setup running
	minhook_dll_name = dll_name_without_bitness.format(x64)

_minhook_path = os.path.split(__file__)[0]
minhook_full_file_path = os.path.join(_minhook_path, minhook_dll_name)

# Consts and function definitions

ctypes.windll.kernel32.GetModuleHandleA.argtypes = [LPSTR]
ctypes.windll.kernel32.GetModuleHandleA.restype = LPVOID

ctypes.windll.kernel32.GetProcAddress.argtypes = [LPVOID, LPSTR]
ctypes.windll.kernel32.GetProcAddress.restype = LPVOID

# ctypes.windll.kernel32.GetCurrentThreadId
sys.threads_in_callback = set()

minhook_error_values_map = {
	-1 : 'MH_UNKNOWN',
	0  : 'MH_OK',
	1  : 'MH_ERROR_ALREADY_INITIALIZED',
	2  : 'MH_ERROR_NOT_INITIALIZED',
	3  : 'MH_ERROR_ALREADY_CREATED',
	4  : 'MH_ERROR_NOT_CREATED',
	5  : 'MH_ERROR_ENABLED',
	6  : 'MH_ERROR_DISABLED',
	7  : 'MH_ERROR_NOT_EXECUTABLE',
	8  : 'MH_ERROR_UNSUPPORTED_FUNCTION',
	9  : 'MH_ERROR_MEMORY_ALLOC',
	10 : 'MH_ERROR_MEMORY_PROTECT',
	11 : 'MH_ERROR_MODULE_NOT_FOUND',
	12 : 'MH_ERROR_FUNCTION_NOT_FOUND',
}
MH_ALL_HOOKS = 0
MH_UNKNOWN = -1
MH_OK = 0
MH_ERROR_ALREADY_INITIALIZED = 1
MH_ERROR_NOT_INITIALIZED = 2
MH_ERROR_ALREADY_CREATED = 3
MH_ERROR_NOT_CREATED = 4
MH_ERROR_ENABLED = 5
MH_ERROR_DISABLED = 6
MH_ERROR_NOT_EXECUTABLE = 7
MH_ERROR_UNSUPPORTED_FUNCTION = 8
MH_ERROR_MEMORY_ALLOC = 9
MH_ERROR_MEMORY_PROTECT = 10
MH_ERROR_MODULE_NOT_FOUND = 11
MH_ERROR_FUNCTION_NOT_FOUND = 12

MH_STATUS = DWORD

class MinHookException(RuntimeError):
	def __new__(self, func_name, error_value):
		# self.minhook_error_value = error_value
		# self.func_name = func_name
		error = super(MinHookException, self).__new__(self)
		error.func_name = func_name
		error.minhook_error_value = error_value
		return error
		
	def __repr__(self):
		return "{0}: did not return MH_OK: {1} was returned".format(self.func_name, minhook_error_values_map[self.minhook_error_value]).__repr__()

	def __str__(self):
		return "{0}: did not return MH_OK: {1} was returned".format(self.func_name, minhook_error_values_map[self.minhook_error_value]).__repr__()

class PyMinHookException(Exception):
	pass

def minhook_errorcheck_function(func_name, res_value, arguments, param4):
	# raise MinHookException(func_name, 0)
	if arguments.restype == MH_STATUS:
		if res_value != MH_OK:
			if THROW_EXCEPTIONS:
				raise MinHookException(func_name, res_value)
			else:
				return res_value
	return res_value

minhook_dll = cdll.LoadLibrary(minhook_full_file_path)

class TransparentMinHookProxy(object):
	def __init__(self, target_func):
		self.target_func = target_func
		self._ctypes_function = None
		self.dummy_tuple = (0, "")
		self.prototype = getattr(minhook_functions_definitions, target_func + "Prototype")
		
	def __call__(self, *args, **kwargs):
		if self._ctypes_function is None:
			self.force_resolution()
		return self._ctypes_function(*args, **kwargs)

	def force_resolution(self):
		try:
			c_prototyped = self.prototype((self.target_func, minhook_dll), (self.dummy_tuple, ) * len(self.prototype._argtypes_))
		except AttributeError:
			raise ExportNotFound(self.target_func, self.target_dll)
		c_prototyped.errcheck = functools.wraps(minhook_errorcheck_function)(functools.partial(minhook_errorcheck_function, self.target_func))
		self._ctypes_function = c_prototyped


class minhook_functions_definitions:
	MH_StatusToStringPrototype = WINFUNCTYPE(LPSTR, MH_STATUS)
	
	MH_InitializePrototype = WINFUNCTYPE(MH_STATUS)
	
	MH_UninitializePrototype = WINFUNCTYPE(MH_STATUS)
	
	MH_CreateHookApiPrototype = WINFUNCTYPE(MH_STATUS, LPCWSTR, LPCSTR, LPVOID, POINTER(LPVOID))
	
	MH_EnableHookPrototype = WINFUNCTYPE(MH_STATUS, LPVOID)
	
	MH_CreateHookPrototype = WINFUNCTYPE(MH_STATUS, LPVOID, LPVOID, POINTER(LPVOID))
	
	MH_DisableHookPrototype = WINFUNCTYPE(MH_STATUS, LPVOID)
	
	MH_RemoveHookPrototype = WINFUNCTYPE(MH_STATUS, LPVOID)

# use constant map defined above ^ 
MH_StatusToString			= TransparentMinHookProxy("MH_StatusToString")

MH_Initialize				= TransparentMinHookProxy("MH_Initialize")
MH_Uninitialize				= TransparentMinHookProxy("MH_Uninitialize")
MH_CreateHookApi	        = TransparentMinHookProxy("MH_CreateHookApi")
MH_EnableHook				= TransparentMinHookProxy("MH_EnableHook")
MH_CreateHook               = TransparentMinHookProxy("MH_CreateHook")
MH_DisableHook	            = TransparentMinHookProxy("MH_DisableHook")
MH_RemoveHook               = TransparentMinHookProxy("MH_RemoveHook")


class KnownCallback(object):
	types = ()

	def __call__(self, func):
		func._types_info = self.types
		return func


def add_callback_to_module(callback):
	setattr(sys.modules[__name__], type(callback).__name__, callback)

def add_function_definitions(class_name):
	for func in class_name.functions:
		prototype = getattr(class_name, func + "Prototype")
		callback_name = func + "Callback"

		class CallBackDeclaration(KnownCallback):
			types = (prototype._restype_,) + prototype._argtypes_

		CallBackDeclaration.__name__ = callback_name
		add_callback_to_module(CallBackDeclaration())

class hook_entry:
	"""
	hook entry for inline hooks
	based on PythonForWindows
	"""
	def __init__(self, hook_addr=None, callback=None):
		if callback == None:
			raise PyMinHookException("Callback cannot be None!")
		if not hasattr(callback, "_types_info"):
			raise ValueError("Callback must have have been definied in `add_function_definitions`")
		
		types = callback._types_info
		
		# types = (callback.restype,) + callback.argtypes
		
		self.original_types = types
		self.callback_types = self.transform_arguments(self.original_types)
		
		self.original = LPVOID(0)
		self.stub = ctypes.WINFUNCTYPE(*self.callback_types)(self.hook_callback)
		self.stub_addr = ctypes.cast(self.stub, LPVOID).value
		self.callback = callback
		self.target = hook_addr
		
		status = MH_CreateHook(hook_addr, self.stub_addr, ctypes.byref(self.original))
		self.realfunction = ctypes.WINFUNCTYPE(*types)(self.original.value)
		self.enabled = False
		
	@classmethod
	def from_dll_name_and_apiname(cls, dll_name, api_name, callback):
		dll_hmodule = ctypes.windll.kernel32.GetModuleHandleA(dll_name)
		if dll_hmodule == 0:
			return None
		func_addr = ctypes.windll.kernel32.GetProcAddress(dll_hmodule, api_name)
		if func_addr == 0:
			return None
		
		return cls(hook_addr=func_addr, callback=callback)
	
	def transform_arguments(self, types):
		res = []
		for type in types:
			if type in (ctypes.c_wchar_p, ctypes.c_char_p):
				res.append(ctypes.c_void_p)
			else:
				res.append(type)
		return res
	
	def enable(self):
		MH_EnableHook(self.target)
		self.enabled = True
	
	def disable(self):
		MH_DisableHook(self.target)
		self.enabled = False
	
	def __del__(self):
		if self.enabled:
			self.disable()
		try:
			MH_RemoveHook(self.target)
		except MinHookException as e:
			if e.minhook_error_value != MH_ERROR_NOT_INITIALIZED:
				raise(e)
	
	def hook_callback(self, *args):
		cur_tid = ctypes.windll.kernel32.GetCurrentThreadId()
		if cur_tid in sys.threads_in_callback:
			return self.realfunction(*args)
		sys.threads_in_callback.add(cur_tid)
		
		adapted_args = []
		for value, type in zip(args, self.original_types[1:]):
			try:
				if type == ctypes.c_wchar_p:
					adapted_args.append(ctypes.c_wchar_p(value))
				elif type == ctypes.c_char_p:
					adapted_args.append(ctypes.c_char_p((value)))
				else:
					adapted_args.append(value)
			except:
				adapted_args.append(value)

		def real_function(*args):
			if args == ():
				args = adapted_args
			return self.realfunction(*args)
		
		return_value = self.callback(*adapted_args, real_function=real_function)
		sys.threads_in_callback.remove(cur_tid)
		return return_value
