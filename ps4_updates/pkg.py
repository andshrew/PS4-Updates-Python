#   MIT License

#   Copyright (c) 2025 andshrew
#   https://github.com/andshrew/PS4-Updates-Python

#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:

#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.

#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.

#   With thanks to PS4 Developer Wiki for the information on PKG files
#   PKG: https://www.psdevwiki.com/ps4/PKG_files
#   param.sfo: https://www.psdevwiki.com/ps4/Param.sfo

import logging
import struct
from dataclasses import dataclass, field
from typing import List, Optional

def read_int8(b):
    return struct.unpack('<b', b.read(struct.calcsize('<b')))[0]

def read_int16(b):
    return struct.unpack('<h', b.read(struct.calcsize('<h')))[0]

def read_int32(b):
    return struct.unpack('<i', b.read(struct.calcsize('<i')))[0]

def read_uint32_be(b):
    return struct.unpack('>I', b.read(struct.calcsize('>I')))[0]

def read_uint64_be(b):
    return struct.unpack('>Q', b.read(struct.calcsize('>Q')))[0]

@dataclass
class PKG_File:
    """PKG File object.

    Create a PKG File object to store information about a specific file within a PKG file.

    This object should be appended to the files attribute of a PKG object.

    For more information on the data structure see:

    https://www.psdevwiki.com/ps4/PKG_files#Files
    """
    id: Optional[int] = None
    filename_offset: Optional[int] = None
    flags1: Optional[int] = None
    flags2: Optional[int] = None
    offset: Optional[int] = None
    size: Optional[int] = None
    padding: Optional[int] = None

    def set_from_bytes(self, b):
        """Set object attributes from a ReadableBuffer of bytes.

        The PKG file table is of a fixed size. This will read the supplied ReadableBuffer
        and assign the values to the appropriate attributes. This data is stored in the
        PKG file as big-endian.

        Attributes:
            b: A ReadableBuffer of bytes pre-positioned at the location of
               a PKG file table entry
        """

        self.id = read_uint32_be(b)
        self.filename_offset = read_uint32_be(b)
        self.flags1 = read_uint32_be(b)
        self.flags2 = read_uint32_be(b)
        self.offset = read_uint32_be(b)
        self.size = read_uint32_be(b)
        self.padding = read_uint64_be(b)
    
    def unpack_from_bytes(self, b):
        """Set object attributes from a ReadableBuffer of bytes.

        The PKG file table is of a fixed size. This will read the supplied ReadableBuffer
        and assign the values to the appropriate attributes.

        This is the same as set_from_bytes except this uses struct.unpack to read and assign
        the attributes.

        Attributes:
            b: A ReadableBuffer of bytes pre-positioned at the location of
               a PKG file table entry
        """

        format = '>IIIIIIQ'
        self.id, self.filename_offset, self.flags1, \
            self.flags2, self.offset, self.size, \
            self.padding = struct.unpack(format, b.read(struct.calcsize(format)))

@dataclass
class PKG:
    """PKG header object.

    Create a PKG header object to store a selection of the header entries from a PKG
    file. The files attribute stores a list of the files found within the PKG file.

    For more information on the data structure see:

    https://www.psdevwiki.com/ps4/PKG_files#File_Header
    """

    offset: int
    magic: Optional[str] = None
    file_count: Optional[int] = None
    entry_count: Optional[int] = None
    table_offset: Optional[int] = None
    body_offset: Optional[int] = None
    content_offset: Optional[int] = None
    files: List[PKG_File] = field(default_factory=list)

    def set_from_bytes(self, b):
        """Set object attributes from a ReadableBuffer of bytes.

        The PKG file header entries are at fixed locations offset from the start of the file.
        This will read the supplied ReadableBuffer and assign the values of interest to
        the appropriate attributes. This data is stored in the PKG file as big-endian.

        Attributes:
            b: A ReadableBuffer of bytes pre-positioned at the location of
               a PKG file
        """

        self.magic = b.read(4)
        if self.magic != b'\x7fCNT':
            logging.error(f'The supplied ReadableBuffer is not a PKG file')
            self.magic = None
            return
        b.seek(0x10)
        self.file_count = read_uint32_be(b)
        b.seek(0x18)
        self.table_offset = read_uint32_be(b)
        b.seek(0x20)
        self.body_offset = read_uint64_be(b)
        b.seek(0x30)
        self.content_offset = read_uint64_be(b)

@dataclass
class SFO_Entry:
    """SFO Entry object.

    Create a SFO Entry object to store information about a specific data item within a param.sfo file.

    This object should be appended to the entries attribute of a SFO object. The data_bytes attribute
    stores the raw data bytes for the entry.

    For more information on the data structure see:

    https://www.psdevwiki.com/ps4/Param.sfo#Data_table
    """

    key_table_offset: Optional[int] = None
    data_format: Optional[int] = None
    param_length: Optional[int] = None
    param_max_length: Optional[int] = None
    data_table_offset: Optional[int] = None
    name: Optional[str] = None
    data_bytes: Optional[bytes] = None

    def set_from_bytes(self, b):
        """Set object attributes from a ReadableBuffer of bytes.

        The SFO entry is of a fixed size. This will read the supplied ReadableBuffer
        and assign the values to the appropriate attributes. This data is stored in the
        param.sfo file as little-endian.

        Attributes:
            b: A ReadableBuffer of bytes pre-positioned at the location of
               a SFO entry table item
        """

        self.key_table_offset = read_int16(b)
        self.data_format = read_int16(b)
        self.param_length = read_int32(b)
        self.param_max_length = read_int32(b)
        self.data_table_offset = read_int32(b)

    def unpack_from_bytes(self, b):
        """Set object attributes from a ReadableBuffer of bytes.

        The SFO entry is of a fixed size. This will read the supplied ReadableBuffer
        and assign the values to the appropriate attributes. This data is stored in the
        param.sfo file as little-endian.

        This is the same as set_from_bytes except this uses struct.unpack to read and assign
        the attributes.

        Attributes:
            b: A ReadableBuffer of bytes pre-positioned at the location of
               a SFO entry table item
        """

        format = '<hhiii'
        self.key_table_offset, self.data_format, self.param_length, \
            self.param_max_length, self.data_table_offset \
            = struct.unpack(format, b.read(struct.calcsize(format)))

@dataclass
class SFO:
    """SFO object.

    Create a SFO object to store information from a param.sfo file. The entries attribute
    stores a list of the data entries found within the param.sfo file.

    For more information on the data structure see:

    https://www.psdevwiki.com/ps4/Param.sfo#Header_SFO
    """
    
    offset_relative: int
    offset: int = 0
    magic: Optional[str] = None
    version: Optional[bytes] = None
    key_table_offset: Optional[int] = None
    data_table_offset: Optional[int] = None
    number_of_entries: Optional[int] = None
    entries: List[SFO_Entry] = field(default_factory=list)

    def set_from_bytes(self, b):
        """Set object attributes from a ReadableBuffer of bytes.

        The param.sfo file header entries are of a fixed size.
        This will read the supplied ReadableBuffer and assign the values of interest to
        the appropriate attributes. This data is stored in the param.sfo file as little-endian.

        Attributes:
            b: A ReadableBuffer of bytes pre-positioned at the location of
               a param.sfo file
        """
        self.magic = b.read(4)
        self.version = read_int32(b)
        self.key_table_offset = read_int32(b)
        self.data_table_offset = read_int32(b)
        self.number_of_entries = read_int32(b)
    
    def set_entries_name(self, b):
        """Set an SFO_Entry objects name from a ReadableBuffer of bytes.

        The names for each SFO Entry are stored in a key table within the param.sfo file.
        This will find the name of every entry that has been added to this objects entries attribute.
        This data is stored in the param.sfo file as little-endian.

        Attributes:
            b: A ReadableBuffer of bytes pre-positioned at the location of
               a param.sfo key_table_offset
        """
        if b.tell() != self.key_table_offset:
            logger.warning(f'Reading from a location ({b.tell()}) that does not match the key table location ({self.key_table_offset})')
        key_table_index = 0
        for i in range(self.number_of_entries):
            name = b''
            while True:
                data = b.read(1)
                key_table_index = key_table_index + 1

                if data == b'\x00': # NULL terminated strings
                    try:
                        self.entries[i].name = name.decode()
                    except Exception as ex:
                        logger.error(f'Unable to decode name for SFO entry {i}: {ex.args}')
                    break
                else:
                    name += data
        
        while key_table_index % 4 != 0:
            # The end of the key table is padded to a multiple of 4
            # This will leave the ReadableStream positioned at the end of the key table
            b.read(1)
            key_table_index = key_table_index +1

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    print('https://github.com/andshrew/PS4-Updates-Python')