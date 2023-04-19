# -*- coding: utf-8 -*-
"""
    Brief: Helper functions to retrieve Vdex Files
"""

# -- Import --#
import artParse as art
import artClass as cls
import artField as fld
import artDex as dx
import artJVM as jvm
import artHeap as heap
from utils import *
# -- End Import --#

def retrieveVdexFile(proj_path, memList, mapList, listing, lstList, nPath, rAddr):
	global proj_path_global

	instance = art.getRuntime(proj_path)
	[address] = art.getBss(lstList, proj_path, instance)
	print "addr test " + str(address)

	proj_path_global = proj_path

	heap_obj = heap.android_heap()

	# Get beginning address of the heap.
	heap_addr = getHeapAddr(heap_obj, nPath, rAddr)

	boot_image_offset = get_index('Heap', 'boot_image_spaces_')
	boot_image_space_begin_addr = hex(int(heap_addr, 16) + boot_image_offset)

	[ptr, nPath, rAddr] = runtimeObj(boot_image_space_begin_addr, memList)
	print "ptr " + str(ptr)

	image_space_addr = heap_obj.readPointer(nPath, rAddr, 0)
	print "image space addr " + str(image_space_addr)

	ofno_addr = hex(int(image_space_addr, 16) + 44)

	[ptr, nPath, rAddr] = runtimeObj(ofno_addr, memList)
	print "ptr " + str(ptr)

	vdex_addr = heap_obj.readPointer(nPath, rAddr, 16)
	print "vdex " + str(vdex_addr)

def runtimeObj(address, memList):
	[rPath, rAddr] = getOffset(address, memList)
	with open(rPath, 'rb') as g:
		g.seek(rAddr)
		runtime = hex(unpack_addr(g))
		[nPath, nAddr] = getOffset(runtime, memList)
		g.close()
		return [runtime, nPath, nAddr]

def getOffset(addr, alist):
	start, key = findAddr(addr, alist)
	if (start != 0):
		offset = int(addr, 16) - int(start, 16)
		aPath = proj_path_global + "/" + key
	else:
		offset = 0
		aPath = None
	return [aPath, offset]

def findAddr(addr, lst):
	addrInt = int(addr, 16)
	start = 0
	end = 0
	for key, value in lst.items():
		v1 = int(value[1], 16)
		v0 = int(value[0], 16)
		if v0 <= addrInt < v1:
			start = value[0]
			end = value[1]
			break
	return start, key

"""
    Gets the pointer to the beginning of the Heap to start traversal 
    towards Vdex Files. 
"""

def getHeapAddr(heap_obj, nPath, rAddr):
	# Get index of Heap in Runtime.
	heap_index = get_index('Runtime', 'heap_')

	# Get beginning address of Heap.
	heap_addr = heap_obj.readPointer(nPath, rAddr, heap_index)

	# Test print
	print "Heap Offset " + heap_addr

	return heap_addr


def getImageSpacePtrs(self, nPath, rAddr):
	heap_addr = getHeapAddr(self, nPath, rAddr)
	#
	# boot_image_space_begin_ptr = hex(int(heap_addr, 16) + 880)
	#
	# boot_image_space_addr = self.readPointer(nPath, rAddr, boot_image_space_begin_ptr)
	#
	# print "Boot Image Space Addr  " + boot_image_space_addr
	#
	# boot_image_space_end_ptr = hex(int(boot_image_space_begin_ptr, 16) + 4)
	#
	# print "Boot Image Space Addr End  " + boot_image_space_end_ptr

	boot_img_spaces_index = get_index('Heap', 'boot_image_spaces_')

	boot_image_space_begin_addr = self.readPointer(nPath, rAddr, boot_img_spaces_index)

	print "Boot Image Space addr " + str(boot_image_space_begin_addr)
