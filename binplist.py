#!/usr/bin/python
import struct

tfmt = ">BBBQQQ"

def decodeVarInt(data,length):
    val = 0
    for i in range(0,length):
        val = val << 8
        val = val + data[i]
    return val

def decodeObj(data,offset):
    code = data[offset]
    offset = offset + 1
    if code == 0x00:
        return None
    elif code == 0x08:
        return False
    elif code == 0x09:
        return True
    elif code == 0x0f:
        return None # fill byte
    elif code == 0x33:
        # parse date
        return "date"
    elif (code & 0xf0) == 0x10:
        # parse int
        sz = code & 0x0f
        val = 0
        for b in data[offset:offset+2**sz]:
            val = val << 8
            val = val + b
        return val
    elif (code & 0xf0) == 0x20:
        # parse real
        sz = code & 0x0f
        if sz == 2:
            return struct.unpack(">f",data[offset:offset+4])[0]
        elif sz == 3:
            return struct.unpack(">d",data[offset:offset+8])[0]
        else:
            raise "Bad float size "+str(2**sz)
    elif (code & 0xf0) == 0x50:
        sz = code & 0x0f
        if sz == 0x0f:
            intsz = 2**(data[offset] & 0x0f)
            offset = offset+1
            sz = decodeVarInt(data[offset:offset+intsz],intsz)
            offset = offset+intsz
        return str(data[offset:offset+sz],"ascii")
    else:
        return "Not yet handled type "+hex(code)

def decodeBinPlist(data):
    print("size",len(data))
    if data[0:8] != b'bplist00':
        raise "Magic number incorrect"
    (sortVer, offIntSize, offRefSize, numObj, topObj, offTabOff) = \
        struct.unpack(tfmt,data[-struct.calcsize(tfmt):])
    print("sortVer",sortVer)
    print("off int sz",offIntSize)
    print("off ref sz",offRefSize)
    print("num obj",numObj)
    print("top obj",topObj)
    print("offset table off",offTabOff)
    offStart = offTabOff
    objects=[]
    for off in range(offTabOff,offTabOff+(offIntSize*numObj),offIntSize):
        val = 0
        for b in data[off:off+offIntSize]:
            val = val << 8
            val = val + b
        o = decodeObj(data,val)
        objects.append(o)
    return objects
        

# Typedef struct {
#     uint8_t	_unused[5];
#     uint8_t     _sortVersion;
#     uint8_t	_offsetIntSize;
#     uint8_t	_objectRefSize;
#     uint64_t	_numObjects;
#     uint64_t	_topObject;
#     uint64_t	_offsetTableOffset;
# } CFBinaryPlistTrailer;
