"""
Copyright 2020, CCL Forensics

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import sys
import struct
import datetime
import types
import typing
import re

__version__ = "0.1"
__description__ = "Partial reimplementation of the V8 Javascript Object Serialization"
__contact__ = "Alex Caithness"






__DEBUG = False


def log(msg, debug_only=True):
    if not debug_only or __DEBUG:
        caller_name = sys._getframe(1).f_code.co_name
        caller_line = sys._getframe(1).f_code.co_firstlineno
        print(f"{caller_name} ({caller_line}):\t{msg}")


def read_le_varint(stream: typing.BinaryIO) -> typing.Optional[typing.Tuple[int, bytes]]:
    
    i = 0
    result = 0
    underlying_bytes = []
    while i < 10:  
        raw = stream.read(1)
        if len(raw) < 1:
            return None
        tmp, = raw
        underlying_bytes.append(tmp)
        result |= ((tmp & 0x7f) << (i * 7))
        if (tmp & 0x80) == 0:
            break
        i += 1
    return result, bytes(underlying_bytes)


class _Undefined:
    def __bool__(self):
        return False

    def __eq__(self, other):
        if isinstance(other, _Undefined):
            return True
        return False


class Constants:
    
    kLatestVersion = 13

    
    token_kVersion = b"\xFF"
    
    token_kPadding = b"\0"
    
    token_kVerifyObjectCount = b"?"
    
    token_kTheHole = b"-"
    token_kUndefined = b"_"
    token_kNull = b"0"
    token_kTrue = b"T"
    token_kFalse = b"F"
    
    
    token_kInt32 = b"I"
    
    
    token_kUint32 = b"U"
    
    
    token_kDouble = b"N"
    
    token_kBigInt = b"Z"
    
    token_kUtf8String = b"S"
    token_kOneByteString = b"\""
    token_kTwoByteString = b"c"
    
    token_kObjectReference = b"^"
    
    token_kBeginJSObject = b"o"
    
    token_kEndJSObject = b"{"
    
    
    token_kBeginSparseJSArray = b"a"
    
    token_kEndSparseJSArray = b"@"
    
    
    token_kBeginDenseJSArray = b"A"
    
    token_kEndDenseJSArray = b"$"
    
    token_kDate = b"D"
    
    token_kTrueObject = b"y"
    token_kFalseObject = b"x"
    
    token_kNumberObject = b"n"
    
    token_kBigIntObject = b"z"
    
    token_kStringObject = b"s"
    
    
    token_kRegExp = b"R"
    
    token_kBeginJSMap = b";"
    
    token_kEndJSMap = b":"
    
    token_kBeginJSSet = b"'"
    
    token_kEndJSSet = b","
    
    token_kArrayBuffer = b"B"
    
    token_kArrayBufferTransfer = b"t"
    
    
    
    
    
    
    
    token_kArrayBufferView = b"V"
    
    token_kSharedArrayBuffer = b"u"
    
    token_kWasmModuleTransfer = b"w"
    
    
    token_kHostObject = b"\\"
    
    
    token_kWasmMemoryTransfer = b"m"
    
    
    token_kError = b"r"

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    token_kLegacyReservedMessagePort = b"M"
    token_kLegacyReservedBlob = b"b"
    token_kLegacyReservedBlobIndex = b"i"
    token_kLegacyReservedFile = b"f"
    token_kLegacyReservedFileIndex = b"e"
    token_kLegacyReservedDOMFileSystem = b"d"
    token_kLegacyReservedFileList = b"l"
    token_kLegacyReservedFileListIndex = b"L"
    token_kLegacyReservedImageData = b"
    token_kLegacyReservedImageBitmap = b"g"
    token_kLegacyReservedImageBitmapTransfer = b"G"
    token_kLegacyReservedOffscreenCanvas = b"H"
    token_kLegacyReservedCryptoKey = b"token_k"
    token_kLegacyReservedRTCCertificate = b"token_k"


class ArrayBufferViewTag:
    tag_kInt8Array = "b"
    tag_kUint8Array = "B"
    tag_kUint8ClampedArray = "C"
    tag_kInt16Array = "w"
    tag_kUint16Array = "W"
    tag_kInt32Array = "d"
    tag_kUint32Array = "D"
    tag_kFloat32Array = "f"
    tag_kFloat64Array = "F"
    tag_kBigInt64Array = "q"
    tag_kBigUint64Array = "Q"
    tag_kDataView = "?"

    STRUCT_LOOKUP = types.MappingProxyType({
        tag_kInt8Array: "b",
        tag_kUint8Array: "B",
        tag_kUint8ClampedArray: "B",
        tag_kInt16Array: "h",
        tag_kUint16Array: "H",
        tag_kInt32Array: "i",
        tag_kUint32Array: "I",
        tag_kFloat32Array: "f",
        tag_kFloat64Array: "d",
        tag_kBigInt64Array: "q",
        tag_kBigUint64Array: "Q",
        tag_kDataView: "c"
    })


class Deserializer:
    Undefined = _Undefined()

    __ODDBALLS = {
        Constants.token_kUndefined: Undefined,
        Constants.token_kTheHole: Undefined,
        Constants.token_kNull: None,
        Constants.token_kTrue: True,
        Constants.token_kFalse: False,
    }

    __WRAPPED_PRIMITIVES = {
        Constants.token_kTrueObject,
        Constants.token_kFalseObject,
        Constants.token_kNumberObject,
        Constants.token_kBigIntObject,
        Constants.token_kStringObject
    }

    def __init__(self, stream: typing.BinaryIO, host_object_delegate: typing.Callable,
                 *, is_little_endian=True, is_64bit=True):
        self._f = stream
        self._host_object_delegate = host_object_delegate
        self._endian = "<" if is_little_endian else ">"
        self._pointer_size = 8 if is_64bit else 4
        self._next_id = 0
        self._objects = []
        self.version = self._read_header()

    def _read_raw(self, length: int) -> bytes:
        start = self._f.tell()
        raw = self._f.read(length)
        if len(raw) != length:
            raise ValueError(f"Could not read all data at offset {start}; wanted {length}; got {len(raw)}")

        return raw

    def _read_le_varint(self) -> typing.Optional[typing.Tuple[int, bytes]]:
        return read_le_varint(self._f)

    def _read_zigzag(self) -> int:
        unsigned = self._read_le_varint()[0]
        if unsigned & 1:
            return -(unsigned >> 1)
        else:
            return unsigned >> 1

    def _read_double(self) -> float:
        return struct.unpack(f"{self._endian}d", self._read_raw(8))[0]

    
    

    
    

    def _read_bigint(self) -> int:
        size_flag = self._read_le_varint()[0]
        is_neg = size_flag & 0x01
        size = size_flag >> 4
        raw = self._read_raw(size * self._pointer_size)

        value = int.from_bytes(raw, "big" if self._endian == ">" else "little", signed=False)
        if is_neg:
            value = -value

        return value

    def _read_utf8_string(self) -> str:
        length = self._read_le_varint()[0]
        return self._read_raw(length).decode("utf8")

    def _read_one_byte_string(self) -> typing.AnyStr:
        length = self._read_le_varint()[0]
        
        raw = self._read_raw(length)  
        try:
            result = raw.decode("ascii")
        except UnicodeDecodeError:
            result = raw
        return result

    def _read_two_byte_string(self) -> str:
        length = self._read_le_varint()[0]
        return self._read_raw(length).decode("utf-16-le")  

    def _read_string(self) -> str:
        if self.version < 12:
            return self._read_utf8_string()

        value = self._read_object()
        assert isinstance(value, str)

        return value

    def _read_object_by_reference(self) -> typing.Any:
        ref_id = self._read_le_varint()[0]
        return self._objects[ref_id]

    def _read_tag(self) -> bytes:
        while True:
            t = self._f.read(1)
            if t != Constants.token_kPadding:
                return t

    def _peek_tag(self) -> bytes:
        start = self._f.tell()
        tag = self._read_tag()
        self._f.seek(start, 0)
        return tag

    def _read_date(self) -> datetime.datetime:
        x = self._read_double()
        result = datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=x)
        self._objects.append(result)
        return result

    def _read_js_regex(self) -> typing.Pattern:
        log(f"Reading js regex properties at {self._f.tell()}")
        pattern = self._read_string()
        flags = self._read_le_varint()

        
        regex = re.compile(pattern)
        self._objects.append(regex)
        return regex

    def _read_js_object_properties(self, end_tag) -> typing.Iterable[typing.Tuple[typing.Any, typing.Any]]:
        log(f"Reading object properties at {self._f.tell()} with end tag: {end_tag}")
        while True:
            if self._peek_tag() == end_tag:
                log(f"Object end at offset {self._f.tell()}")
                break
            key = self._read_object()
            value = self._read_object()

            yield key, value

        assert self._read_tag() == end_tag

    def _read_js_object(self) -> dict:
        log(f"Reading js object properties at {self._f.tell()}")
        result = {}
        self._objects.append(result)
        for key, value in self._read_js_object_properties(Constants.token_kEndJSObject):
            result[key] = value
        
        
        
        
        
        
        
        
        
        property_count = self._read_le_varint()[0]
        log(f"Actual property count: {len(result)}; stated property count: {property_count}")
        if len(result) != property_count:
            raise ValueError("Property count mismatch")

        return result

    def _read_js_sparse_array(self) -> list:
        log(f"Reading js sparse array properties at {self._f.tell()}")
        
        length = self._read_le_varint()[0]
        result = [None for _ in range(length)]
        self._objects.append(result)

        sparse_object = self._read_js_object_properties(Constants.token_kEndSparseJSArray)
        prop_count = 0
        for key, value in sparse_object:
            i = int(key)
            result[i] = value
            prop_count += 1
        expected_num_properties = self._read_le_varint()[0]

        log(f"Actual property count: {prop_count}; stated property count: {expected_num_properties}")
        if prop_count != expected_num_properties:
            raise ValueError("Property count mismatch")

        expected_length = self._read_le_varint()[0]  

        return result

    def _read_js_dense_array(self) -> list:
        log(f"Reading js dense array properties at {self._f.tell()}")
        length = self._read_le_varint()[0]
        result = [None for _ in range(length)]
        self._objects.append(result)

        for i in range(length):
            result[i] = self._read_object()

        
        sparse_object = self._read_js_object_properties(Constants.token_kEndDenseJSArray)
        prop_count = 0
        for key, value in sparse_object:
            i = int(key)
            result[i] = value
            prop_count += 1

        expected_num_properties = self._read_le_varint()[0]

        log(f"Actual property count: {prop_count}; stated property count: {expected_num_properties}")
        if prop_count != expected_num_properties:
            raise ValueError("Property count mismatch")

        expected_length = self._read_le_varint()[0]  

        return result

    def _read_js_map(self) -> dict:
        log(f"Reading js map at {self._f.tell()}")
        result = {}
        self._objects.append(result)
        while True:
            if self._peek_tag() == Constants.token_kEndJSMap:
                log(f"End of map at {self._f.tell()}")
                break

            key = self._read_object()
            value = self._read_object()
            result[key] = value

        assert self._read_tag() == Constants.token_kEndJSMap

        expected_length = self._read_le_varint()[0]
        log(f"Actual map item count: {len(result) * 2}; stated map item count: {expected_length}")
        if expected_length != len(result) * 2:
            raise ValueError("Map count mismatch")

        return result

    def _read_js_set(self) -> set:
        log(f"Reading js set properties at {self._f.tell()}")
        result = set()
        self._objects.append(result)

        while True:
            if self._peek_tag() == Constants.token_kEndJSSet:
                log(f"End of set at {self._f.tell()}")
                break

            result.add(self._read_object())

        assert self._read_tag() == Constants.token_kEndJSSet

        expected_length = self._read_le_varint()[0]
        log(f"Actual set item count: {len(result)}; stated set item count: {expected_length}")
        if expected_length != len(result):
            raise ValueError("Set count mismatch")

        return result

    def _read_js_arraybuffer(self) -> bytes:
        length = self._read_le_varint()[0]
        raw = self._read_raw(length)
        self._objects.append(raw)

        return raw

    def _wrap_js_array_buffer_view(self, raw: bytes) -> tuple:
        if not isinstance(raw, bytes):
            raise TypeError("Only bytes should be passed to be wrapped in a buffer view")

        log(f"Wrapping in ArrayBufferView at offset {self._f.tell()}")

        tag = chr(self._read_le_varint()[0])
        byte_offset = self._read_le_varint()[0]
        byte_length = self._read_le_varint()[0]

        if byte_offset + byte_length > len(raw):
            raise ValueError("Not enough data in the raw data to hold the defined data")

        log(f"ArrayBufferView: tag: {tag}; byte_offset: {byte_offset}; byte_length: {byte_length}")

        fmt = ArrayBufferViewTag.STRUCT_LOOKUP[tag]
        element_length = struct.calcsize(fmt)
        if byte_length % element_length != 0:
            raise ValueError(f"ArrayBufferView doesn't fit nicely: byte_length: {byte_length}; "
                             f"element_length: {element_length}")

        element_count = byte_length // element_length

        return struct.unpack(f"{self._endian}{element_count}{fmt}", raw[byte_offset: byte_offset + byte_length])

    def _read_host_object(self) -> typing.Any:
        result = self._host_object_delegate(self._f)
        self._objects.append(result)
        return result

    def _not_implemented(self):
        raise NotImplementedError("Todo")

    def _read_object_internal(self) -> typing.Tuple[bytes, typing.Any]:
        tag = self._read_tag()

        log(f"Offset: {self._f.tell()}; Tag: {tag}")

        if tag in Deserializer.__ODDBALLS:
            return tag, Deserializer.__ODDBALLS[tag]

        func = {
            Constants.token_kTrueObject: lambda: Deserializer.__ODDBALLS[Constants.token_kTrue],
            Constants.token_kFalseObject: lambda: Deserializer.__ODDBALLS[Constants.token_kFalse],
            Constants.token_kNumberObject: self._read_double,
            Constants.token_kUint32: self._read_le_varint,
            Constants.token_kInt32: self._read_zigzag,
            Constants.token_kDouble: self._read_double,
            Constants.token_kDate: self._read_date,
            Constants.token_kBigInt: self._read_bigint,
            Constants.token_kBigIntObject: self._read_bigint,
            Constants.token_kUtf8String: self._read_utf8_string,
            Constants.token_kOneByteString: self._read_one_byte_string,
            Constants.token_kTwoByteString: self._read_two_byte_string,
            Constants.token_kStringObject: self._read_string,
            Constants.token_kRegExp: self._read_js_regex,
            Constants.token_kObjectReference: self._read_object_by_reference,
            Constants.token_kBeginJSObject: self._read_js_object,
            Constants.token_kBeginSparseJSArray: self._read_js_sparse_array,
            Constants.token_kBeginDenseJSArray: self._read_js_dense_array,
            Constants.token_kBeginJSMap: self._read_js_map,
            Constants.token_kBeginJSSet: self._read_js_set,
            Constants.token_kArrayBuffer: self._read_js_arraybuffer,
            Constants.token_kSharedArrayBuffer: self._not_implemented,  
            Constants.token_kArrayBufferTransfer: self._not_implemented,
            Constants.token_kError: self._not_implemented,
            Constants.token_kWasmModuleTransfer: self._not_implemented,
            Constants.token_kWasmMemoryTransfer: self._not_implemented,
            Constants.token_kHostObject: self._read_host_object,
        }.get(tag)

        if func is None:
            raise ValueError(f"Unknown tag {tag}")

        value = func()

        if tag in Deserializer.__WRAPPED_PRIMITIVES:
            self._objects.append(value)

        return tag, value

    def _read_object(self) -> typing.Any:
        log(f"Read object at offset: {self._f.tell()}")
        tag, o = self._read_object_internal()

        if self._peek_tag() == Constants.token_kArrayBufferView:
            assert self._read_tag() == Constants.token_kArrayBufferView
            o = self._wrap_js_array_buffer_view(o)

        return o

    def _read_header(self) -> int:
        tag = self._read_tag()
        if tag != Constants.token_kVersion:
            raise ValueError("Didn't get version tag in the header")
        version = self._read_le_varint()[0]
        return version

    def read(self) -> typing.Any:
        return self._read_object()
