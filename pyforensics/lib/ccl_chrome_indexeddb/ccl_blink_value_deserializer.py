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
import enum
import typing
from dataclasses import dataclass

import ccl_v8_value_deserializer






















__version__ = "0.1"
__description__ = "Partial reimplementation of the Blink Javascript Object Serialization"
__contact__ = "Alex Caithness"

__DEBUG = True


def log(msg, debug_only=True):
    if __DEBUG or not debug_only:
        caller_name = sys._getframe(1).f_code.co_name
        caller_line = sys._getframe(1).f_code.co_firstlineno
        print(f"{caller_name} ({caller_line}):\t{msg}")


class BlobIndexType(enum.Enum):
    Blob = 0
    File = 1


@dataclass
class BlobIndex:
    index_type: BlobIndexType
    index_id: int


class Constants:
    tag_kMessagePortTag = b"M"  
                                
    tag_kMojoHandleTag = b"h"   
                                
    tag_kBlobTag = b"b"         
                                
    tag_kBlobIndexTag = b"i"    
    tag_kFileTag = b"f"         
    tag_kFileIndexTag = b"e"    
    tag_kDOMFileSystemTag = b"d"  
                                  
    tag_kNativeFileSystemFileHandleTag = b"n"  
                                               
    tag_kNativeFileSystemDirectoryHandleTag = b"N"  
                                                   
    tag_kFileListTag = b"l"                     
    tag_kFileListIndexTag = b"L"                
    tag_kImageDataTag = b"
                                               
                                               
                                               
                                               
    tag_kImageBitmapTag = b"g"        
                                      
                                      
                                      
                                      
    tag_kImageBitmapTransferTag = "G"       
    tag_kOffscreenCanvasTransferTag = b"H"  
                                            
                                            
                                            
    tag_kReadableStreamTransferTag = b"r"    
    tag_kTransformStreamTransferTag = b"m"   
    tag_kWritableStreamTransferTag = b"w"    
    tag_kDOMPointTag = b"Q"                  
    tag_kDOMPointReadOnlyTag = b"W"          
    tag_kDOMRectTag = b"E"                   
    tag_kDOMRectReadOnlyTag = b"R"           
    tag_kDOMQuadTag = b"T"                   
    tag_kDOMMatrixTag = b"Y"                 
    tag_kDOMMatrixReadOnlyTag = b"U"         
    tag_kDOMMatrix2DTag = b"I"               
    tag_kDOMMatrix2DReadOnlyTag = b"O"       
    tag_kCryptoKeyTag = b"K"                 
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    tag_kRTCCertificateTag = b"k"  
    
    tag_kRTCEncodedAudioFrameTag = b"A"  
    tag_kRTCEncodedVideoFrameTag = b"V"  
    tag_kVideoFrameTag = b"v"            

    
    
    
    tag_kDeprecatedDetectedBarcodeTag = b"B"
    tag_kDeprecatedDetectedFaceTag = b"F"
    tag_kDeprecatedDetectedTextTag = b"t"

    tag_kDOMExceptionTag = b"x"  
    tag_kVersionTag = b"\xff"  


class BlinkV8Deserializer:
    def _read_varint(self, stream) -> int:
        return ccl_v8_value_deserializer.read_le_varint(stream)[0]

    def _read_file_index(self, stream: typing.BinaryIO) -> BlobIndex:
        return BlobIndex(BlobIndexType.File, self._read_varint(stream))

    def _read_file_list_index(self, stream: typing.BinaryIO) -> typing.Iterable[BlobIndex]:
        length = self._read_varint(stream)
        result = [self._read_file_index(stream) for _ in range(length)]
        return result

    def _not_implemented(self, stream):
        raise NotImplementedError()

    def read(self, stream: typing.BinaryIO) -> typing.Any:
        tag = stream.read(1)

        func = {
            Constants.tag_kMessagePortTag: lambda x: self._not_implemented(x),
            Constants.tag_kMojoHandleTag: lambda x: self._not_implemented(x),
            Constants.tag_kBlobTag: lambda x: self._not_implemented(x),
            Constants.tag_kBlobIndexTag: lambda x: self._not_implemented(x),
            Constants.tag_kFileTag: lambda x: self._not_implemented(x),
            Constants.tag_kFileIndexTag: lambda x: self._read_file_index(x),
            Constants.tag_kDOMFileSystemTag: lambda x: self._not_implemented(x),
            Constants.tag_kNativeFileSystemFileHandleTag: lambda x: self._not_implemented(x),
            Constants.tag_kNativeFileSystemDirectoryHandleTag: lambda x: self._not_implemented(x),
            Constants.tag_kFileListTag: lambda x: self._not_implemented(x),
            Constants.tag_kFileListIndexTag: lambda x: self._read_file_list_index(x),
            Constants.tag_kImageDataTag: lambda x: self._not_implemented(x),
            Constants.tag_kImageBitmapTag: lambda x: self._not_implemented(x),
            Constants.tag_kImageBitmapTransferTag: lambda x: self._not_implemented(x),
            Constants.tag_kOffscreenCanvasTransferTag: lambda x: self._not_implemented(x),
            Constants.tag_kReadableStreamTransferTag: lambda x: self._not_implemented(x),
            Constants.tag_kTransformStreamTransferTag: lambda x: self._not_implemented(x),
            Constants.tag_kWritableStreamTransferTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMPointTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMPointReadOnlyTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMRectTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMRectReadOnlyTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMQuadTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMMatrixTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMMatrixReadOnlyTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMMatrix2DTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMMatrix2DReadOnlyTag: lambda x: self._not_implemented(x),
            Constants.tag_kCryptoKeyTag: lambda x: self._not_implemented(x),
            Constants.tag_kRTCCertificateTag: lambda x: self._not_implemented(x),
            Constants.tag_kRTCEncodedAudioFrameTag: lambda x: self._not_implemented(x),
            Constants.tag_kRTCEncodedVideoFrameTag: lambda x: self._not_implemented(x),
            Constants.tag_kVideoFrameTag: lambda x: self._not_implemented(x),
            Constants.tag_kDOMExceptionTag: lambda x: self._not_implemented(x)
        }.get(tag)

        if func is None:
            raise ValueError(f"Unknown tag: {tag}")

        return func(stream)
