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
import os
# -- End Import --#

def retrieveVdexFiles(proj_path, memList, mapList, nPath, rAddr, dump_dir):
	global proj_path_global

	# Assign global project path and create an Android Heap object for traversal.
	proj_path_global = proj_path
	heap_obj = heap.android_heap()

	# Get beginning address of the heap.
	heap_addr = getHeapAddr(heap_obj, nPath, rAddr)

	# Get pointer to the beginning of the vector for the boot image spaces.
	boot_image_offset = get_index('Heap', 'boot_image_spaces_')
	boot_image_space_begin_ptr = hex(int(heap_addr, 16) + boot_image_offset)

	# Get pointer to first ImageSpace
	[first_img_spc_ptr, nPath, rAddr] = runtimeObj(boot_image_space_begin_ptr, memList)
	print "Pointer to first ImageSpace: " + str(first_img_spc_ptr)

	# Get pointer to last ImageSpace
	boot_image_space_end_ptr = hex(int(heap_addr, 16) + boot_image_offset + 4)
	[last_img_spc_ptr, nPath2, rAddr2] = runtimeObj(boot_image_space_end_ptr, memList)
	print "Pointer to last ImageSpace: " + str(last_img_spc_ptr)

	# Get number of ImageSpaces
	num_spaces = (int(last_img_spc_ptr, 16) - int(first_img_spc_ptr, 16)) / 4
	print "num spaces " + str(num_spaces)

	# Start loop here

	# Read the pointer to get the address of the first ImageSpace.
	image_space_addr = heap_obj.readPointer(nPath, rAddr, 0) # Increment by 4 to grab next addr based on index.
	print "ImageSpace address: " + str(image_space_addr)

	# Find the pointer to the OatFile non-owned within the ImageSpace.
	ofno_offset = get_index('ImageSpace', 'oat_file_non_owned_')
	ofno_ptr = hex(int(image_space_addr, 16) + ofno_offset)

	# Get address of the acquired OatFile non-owned.
	[ofno_addr, nPath, rAddr] = runtimeObj(ofno_ptr, memList)
	print "Address of OFNO: " + str(ofno_addr)

	# Find pointer to VDEX within the OatFile non-owned.
	vdex_offset = get_index('OatFile', 'vdex_')
	vdex_ptr = heap_obj.readPointer(nPath, rAddr, vdex_offset)
	print "Pointer to VDEX: " + str(vdex_ptr)

	# Get the address of the associated MemMap within the VDEX.
	[mem_map_addr, nPath, rAddr] = runtimeObj(vdex_ptr, memList)
	print "Address of MemMap: " + mem_map_addr

	# Find pointer to the beginning of the VDEX file.
	begin_offset = get_index('MemMap', 'begin_')
	vdex_begin_ptr = heap_obj.readPointer(nPath, rAddr, begin_offset)
	print "Pointer to beginning of VDEX file: " + vdex_begin_ptr

	# Find the VDEX file where raw data is stored.
	[vdex_path, rAddr] = getOffset(vdex_begin_ptr, mapList)
	print "File path of VDEX: " + str(vdex_path)

	# Open VDEX file to dump DEX and verify proper VDEX format.
	with open(vdex_path, "r") as vdex_file:

		# Check that first 8 bytes of file are vdex006\0 since
		# this is a valid signature for a VDEX file.
		first_line = vdex_file.readline()

		vdex_verify = first_line[0:8]
		# print vdex_verify

		# If file is VDEX, dump DEX into specified directory in params.
		if (vdex_verify == "vdex006\0"):
			# Get number of DEX files. Since unpack can only do 2 bytes,
			# have to do in 2 byte blocks and add together to get total number.
			num_dex_1 = struct.unpack("h", first_line[8:10])[0]
			num_dex_2 = struct.unpack("h", first_line[10:12])[0]

			total_num_dex = num_dex_1 + num_dex_2
			print "num dex " + str(total_num_dex)

			index = 0
			complete_path = os.path.join(dump_dir, "test_dump_" + str(index) + ".txt")
			print(complete_path)

			# Go back to start of file and read starting after VDEX header.
			vdex_file.seek(0, 0)
			read_file = vdex_file.read()

			print read_file[24+32:24+32+4]
			size_dex_1 = struct.unpack("h", read_file[24+32:24+32+2])[0]
			size_dex_2 = struct.unpack("h", read_file[24+32+2:24+32+4])[0]
			print size_dex_2
			print size_dex_1

			print struct.unpack("h", "ff")[0]

			with open(complete_path, "wt") as out_file:
				out_file.write(read_file[24:])

			print "Dumped DEX files."

		else:
			print "File is not a valid VDEX file."
			return

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
		aPath = proj_path_global + "/" + key
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
