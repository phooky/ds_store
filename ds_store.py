#!/usr/bin/python3.2
import struct
import sys
#import binplist

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
        if self.data_type == b'blob':
            (blob_len,) = struct.unpack(">I", f.read(4))
            self.data = f.read(blob_len)
        elif self.data_type == b'long' or self.data_type == b'shor':
            (self.data,) = struct.unpack(">I", f.read(4))
        elif self.data_type == b'bool':
            self.data = ord(f.read(1)[0]) != 0
        else:
            print("UNKNOWN RECORD TYPE", str( self.data_type ), "hex", " ".join(map(hex,self.data_type)))
            sys.exit(1)
        print("----------------------")
        self.display()

    def display(self,limit=10):
        print("Entry struct ",self.struct_type,"data",self.data_type)
        if self.filename and self.filename != ".".encode("utf-16-be"):
            print("Filename", self.filename.decode('utf-16-be'))
        if self.data_type == b'blob':
            if len(self.data) >= 6 and self.data[0:6] == b'bplist':
                print("plist")
                #root = binplist.decodeBinPlist(self.data)
                #print(root)
            else:
                print("size",str(len(self.data)),"data"," ".join(map(hex,self.data[:limit])))
        elif self.data_type == b'long' or self.data_type == b'shor':
            print(str(self.data))
        elif self.data_type == b'bool': 
            print(str(self.data))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No store file specified; looking for .DS_Store")
        path = '.DS_Store'
    else:
        path = sys.argv[1]

    ds = DsStore()
    f=open(path,'br')
    ds.read(f)
