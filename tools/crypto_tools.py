"""
// Copyright (c) 2019, The Vulkan Developers.
//
// This file is part of Vulkan.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// You should have received a copy of the MIT License
// along with Vulkan. If not, see <https://opensource.org/licenses/MIT>.
"""

import hashlib
import array


def sha256d_hash(input):
    """
    Calculates a double sha256 hash from the input
    """

    ca = hashlib.sha256(input)
    digest = ca.digest()

    cb = hashlib.sha256(digest)
    digest = cb.digest()

    del ca
    del cb

    return digest


def convert_bytes_str_to_array(input):
    """
    Converts a byte array to a hex integer array
    """

    # convert input list to array
    a = array.array("B", bytearray(input))

    # format integers to list
    b = []
    for x in a:
        b.append(format(x, '02x'))

    # return formatted array
    c = ""
    i = 0
    for x in b:
        c += "0x%s" % x
        if i + 1 < len(b):
            c += ", "

        i += 1

    return "[%s]" % c


if __name__ == '__main__':
    digest = sha256d_hash("Hello World!")
    digest_array = convert_bytes_str_to_array(digest)
    print (digest_array)

    digest1 = sha256d_hash("The quick brown fox jumps over the lazy dog")
    digest_array1 = convert_bytes_str_to_array(digest1)
    print (digest_array1)

    digest2 = sha256d_hash("THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG'S BACK 1234567890")
    digest_array2 = convert_bytes_str_to_array(digest2)
    print (digest_array2)

    del digest
    del digest1
    del digest2

    del digest_array
    del digest_array1
    del digest_array2
