# -*- coding: utf-8 -*-
"""
    Brief: Helper functions to retrieve Vdex Files
"""

#-- Import --#
import artParse as art
import artClass as cls
import artField as fld
import artDex as dx
import artJVM as jvm
import artHeap as heap
from utils import *
#-- End Import --#

def retrieveVdexFile(self, nPath, rAddr):

    getImageSpacePtrs(self, nPath, rAddr)

"""
    Gets the pointer to the beginning of the Heap to start traversal 
    towards Vdex Files. 
"""
def getHeapAddr(self, nPath, rAddr):

    # Get index of Heap in Runtime.
    heap_index = get_index('Runtime', 'heap_')

    # Get beginning address of Heap.
    heap_addr = self.readPointer(nPath, rAddr, heap_index)

    # Test print
    print "Heap Offset " + heap_addr

    return heap_addr

def getImageSpacePtrs(self, nPath, rAddr):

    heap_addr = getHeapAddr(self, nPath, rAddr)

    boot_image_space_begin_ptr = hex(heap_addr)

    print "boot_image_space_begin_ptr " + boot_image_space_begin_ptr


# def getHeap(self, nPath, rAddr, memList):
#     index = get_index('Runtime', 'heap_')
#     heapAddr = self.readPointer(nPath, rAddr, index)
#     print "Heap Offset " + heapAddr
#     [heapPath, offset] = art.getOffset(heapAddr, memList)
#     return [heapPath, offset]