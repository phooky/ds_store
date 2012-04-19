#!/usr/bin/python
import struct
import sys

# The DS_Store format was reverse engineered by Mark Mentovai. I am using
# the documentation compiled by Wim Lewis for his Perl module.
# http://search.cpan.org/~wiml/Mac-Finder-DSStore/DSStoreFormat.pod

class DsStore:
    def __init__(self):
        self.records=[]

    def read(self,f):
        # find data start
        f.seek(0x14)
        (self.record_start,) = struct.unpack(">I",f.read(4))
        start = self.record_start
        while 1:
            r = Record()
            r.read(f,start)
            self.records.append(r)
            start = 0
        
class Record:
    def __init__(self):
        pass

    def read(self,f,seek_to=0):
        if seek_to != 0:
            f.seek(seek_to)
        (fn_len,) = struct.unpack(">I", f.read(4))
        self.filename = f.read(fn_len*2)
        self.struct_type = f.read(4)
        self.data_type = f.read(4)
        if self.data_type == 'blob':
            (blob_len,) = struct.unpack(">I", f.read(4))
            self.data = f.read(blob_len)
        elif self.data_type == 'long' or self.data_type == 'shor':
            (self.data,) = struct.unpack(">I", f.read(4))
        elif self.data_type == 'bool':
            self.data = ord(f.read(1)[0]) != 0
        else:
            print "UNKNOWN RECORD TYPE" + str( self.data_type ) + " hex " + "(" + " ".join(map(hex,map(ord,self.data_type))) + ")"
            print "read: ", self.filename, self.struct_type, self.data_type
            sys.exit(1)
        print "read: ", self.filename, self.struct_type, self.data_type, self.display()

    def display(self,limit=20):
        if self.data_type == 'blob':
            return " ".join(map(hex,map(ord,self.data[:limit])))
        elif self.data_type == 'long' or self.data_type == 'shor':
            return str(self.data)
        elif self.data_type == 'bool':
            return str(self.data)


ds = DsStore()
f=open("sample")
ds.read(f)
