import ctypes

req = ctypes.CDLL(".output/libbpf.so")
fun = ctypes.CDLL(".output/libtcpretranslib.so")
ret = fun.run()
print(ret)
