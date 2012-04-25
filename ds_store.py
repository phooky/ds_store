#!/usr/bin/python
import struct
import sys

# The DS_Store format was reverse engineered by Mark Mentovai. I am using
# the documentation compiled by Wim Lewis for his Perl module.
# http://search.cpan.org/~wiml/Mac-Finder-DSStore/DSStoreFormat.pod

class DsStore:
    def __init__(self):
        self.records=[]

    def readBlock(self,f):
        block_records=[]
        (node_type,record_count) = struct.unpack(">II",f.read(8))
        for i in range(record_count):
            r = Record()
            r.read(f)
            block_records.append(r)
        return block_records

    def read(self,f):
        # find data start
        f.seek(0x14)
        (self.record_start,) = struct.unpack(">I",f.read(4))
        f.seek( (self.record_start & 0xff80) + 4 )
        self.records = self.records + self.readBlock(f)
        
class Record:
    def __init__(self):
        pass

    def read(self,f):
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


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No store file specified; looking for .DS_Store")
        path = '.DS_Store'
    else:
        path = sys.argv[1]

    ds = DsStore()
    f=open(path)
    ds.read(f)
