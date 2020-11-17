import os, sys
from distutils.core import setup


x86 = "x86"
x64 = "x64"
dll_name_without_bitness = "MinHook.{}.dll"

minhook_dll_name = dll_name_without_bitness.format(x86)
if sys.maxsize > 2**32:
	# 64 bit setup running
	minhook_dll_name = dll_name_without_bitness.format(x64)


setup(
    name='pyminhook',
    version='0.1',
    packages=['pyminhook',],
    long_description="long description thing",
	data_files=[("lib\\site-packages\\pyminhook", [os.path.join("dlls", minhook_dll_name)])]
)