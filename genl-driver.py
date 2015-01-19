#!/usr/bin/python

# Copyright 2014, Jiangang Zhang (JZ), Jiaming Zhang & SameNET.com
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
genlhlpr: python driver to support generic netlink protocol
"""
import os
import sys
import struct
import socket
import logging

log = logging.getLogger("genlhlpr")

NETLINK_GENERIC  = 16

NLMSG_ALIGNTO  = 4
NLMSG_HDRLEN = 16
GENL_HDRLEN = 4
NLA_HDRLEN = 4

NLMSG_ERROR = 0x2
NLMSG_DONE  = 0x3

CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
GENL_ID_CTRL = 0x10
NLM_F_REQUEST   =        1
NLM_F_MULTI     =        2

NLM_F_ROOT  =     0x100
NLM_F_MATCH =    0x200
NLM_F_DUMP =     (NLM_F_ROOT|NLM_F_MATCH)

def NLMSG_ALIGN(len) :

        return ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )

def GNLMSG_HDR(buf) :
        """ buf points to start of packet """
        return buf[NLMSG_HDRLEN:]

def GNLMSG_DATA(buf) :
        """ buf points to start of packet """
        return buf[NLMSG_HDRLEN + GENL_HDRLEN:]

def NLATTR_DATA(buf) :
        """ buf points to start of attribute """
        return buf[NLA_HDRLEN:]

#!/usr/bin/python

# Copyright 2014, Jiangang Zhang (JZ), Jiaming Zhang & SameNET.com
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
genlhlpr: python driver to support generic netlink protocol
"""
import os
import sys
import struct
import socket
import logging

log = logging.getLogger("genlhlpr")

NETLINK_GENERIC  = 16

NLMSG_ALIGNTO  = 4
NLMSG_HDRLEN = 16
GENL_HDRLEN = 4
NLA_HDRLEN = 4

NLMSG_ERROR = 0x2
NLMSG_DONE  = 0x3

CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
GENL_ID_CTRL = 0x10
NLM_F_REQUEST   =        1
NLM_F_MULTI     =        2

NLM_F_ROOT  =     0x100
NLM_F_MATCH =    0x200
NLM_F_DUMP =     (NLM_F_ROOT|NLM_F_MATCH)

def NLMSG_ALIGN(len) :

        return ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )

def GNLMSG_HDR(buf) :
        """ buf points to start of packet """
        return buf[NLMSG_HDRLEN:]

def GNLMSG_DATA(buf) :
        """ buf points to start of packet """
        return buf[NLMSG_HDRLEN + GENL_HDRLEN:]

def NLATTR_DATA(buf) :
        """ buf points to start of attribute """
        return buf[NLA_HDRLEN:]


class nlmsghdr:

        nlm_len  = 0          #u32
        nlm_type = 0          #u16
        nlm_flags = 0         #u16
        nlm_seq = 0           #u32
        nlm_pid = os.getpid()     #u32

        def __init__(self, msg_len = 0, msg_type = 0, msg_flags = 0, msg_seq = 0) :

                self.nlm_len = msg_len
                self.nlm_type = msg_type
                self.nlm_flags = msg_flags
                self.nlm_seq = msg_seq

        def pack(self) :

                return struct.pack("IHHII", self.nlm_len, self.nlm_type, self.nlm_flags, self.nlm_seq, self.nlm_pid)

        def unpack_from(self, buff) :

                self.nlm_len, self.nlm_type, self.nlm_flags, self.nlm_seq, self.nlm_pid = struct.unpack_from("IHHII", buff)

        def info(self) :

                log.debug("nlhdr: len = %d, type = %d, flags = %d, seq = %d, pid = %d", self.nlm_len, self.nlm_type, self.nlm_flags, self.nlm_seq, self.nlm_pid)

class gnlmsghdr:

        cmd = 0         #u8               
        version = 0x1   #u8
        reserved = 0    #u16

        def __init__(self, msg_cmd = 0) :

                self.cmd = msg_cmd

        def pack(self) :

                return struct.pack("BBH", self.cmd, self.version, self.reserved)

        def unpack_from(self, buff) :

                self.cmd, self.version, self.reserved = struct.unpack_from("BBH", buff)

        def info(self) :

                log.debug("gnlhdr: cmd = %d, version = %d, reserved = %d", self.cmd, self.version, self.reserved)

class nlattr:

        nla_len = 0     #u16
        nla_type = 0    #u16

        nla_data = 0

        data_len = 0    #no (un)packing

        def __init__(self, nla_type = 0, nla_data = None, data_len = 0) :

                self.nla_type = nla_type
                self.nla_data = nla_data
                self.data_len = data_len

                self.nla_len = NLA_HDRLEN + self.data_len

        def pack(self) :
                if self.nla_data != None :
                        return struct.pack("HH" + str(self.data_len) + "s", self.nla_len, self.nla_type, self.nla_data) + (NLMSG_ALIGN(self.nla_len) - self.nla_len) * '\x00'
                else :
                        return struct.pack("HH", self.nla_len, self.nla_type)

        def unpack_from(self, buff) :

                self.nla_len, self.nla_type = struct.unpack_from("HH", buff)

                self.data_len = self.nla_len - NLA_HDRLEN

                if self.data_len > 0 :
                        self.nla_data = struct.unpack_from(str(self.data_len) + "s", buff[NLA_HDRLEN:])[0]
                else :
                        self.nla_data = None

        def size(self) :
                return NLMSG_ALIGN(self.nla_len)

        def info(self) :
                log.debug("nlattr: len = %d, type = %d, data = %s", self.nla_len, self.nla_type, self.nla_data)

        def nested(self) :

                nested_attrs = []

                attr_start = 0

                size = self.nla_len - NLA_HDRLEN

                while size > 0 :

                        nla = nlattr()

                        nla.unpack_from(self.nla_data[attr_start:])

                        nested_attrs.append(nla)

                        attr_start += nla.size()

                        size -= nla.size()


                return nested_attrs


def get_attr(attrs, kind, from_idx = 0) :

        if attrs == None : return None, -1

        for i in range(from_idx, len(attrs)) :
                if attrs[i].nla_type == kind :
                         return (attrs[i], i)

        return None, -1

class gnlpacket :

        def __init__(self, flags = 0, seq = 0, cmd = 0, type = 0) :

                self.nlh = nlmsghdr(NLMSG_HDRLEN + GENL_HDRLEN, type, flags, seq)

                self.gnh = gnlmsghdr(cmd)

                self.nla = []

                self.nst = {} # transitory attribute nesting state info    

                pass

        def get_type(self) :

                return self.nlh.nlm_type

        def get_cmd(self) :

                return self.gnh.cmd

        def get_seqn(self) :

                return self.nlh.nlm_seq

        def add_attr(self, kind, buf, size) :

                attr = nlattr(kind, buf, size)

                self.nla.append(attr)

                self.nlh.nlm_len +=NLMSG_ALIGN(attr.nla_len)

                return attr

        def add_nested_attr(self, kind) :

                return self.add_attr(kind, None, 0)

        def end_nested_attr(self, attr) :

                if attr == None : return

                idx = self.nla.index(attr) + 1

                num = len(self.nla)

                log.debug("end_nested: start idx = %d, ending idx = %d", idx, num - 1)

                while idx < len(self.nla) :
                        attr.nla_len += self.nla[idx].size()
                        skip_to = self.nst.pop(self.nla[idx], 0)
                        if skip_to > idx :
                                log.debug("skipping inner nest from %d to %d", idx, skip_to)
                                idx = skip_to #skip nested attrs of this nest
                        else :
                                idx += 1

                self.nst[attr] = num

        def pack(self) :

                buff = self.nlh.pack() + self.gnh.pack()

                for i in range(0, len(self.nla)) :
                        buff += self.nla[i].pack()

                return buff


        def unpack_from(self, buff) :

                self.nlh.unpack_from(buff)

                self.nlh.info()

                if self.nlh.nlm_type == NLMSG_ERROR:

                        err = struct.unpack_from("I", buff[NLMSG_HDRLEN:])
                        log.error("error pkt recv'd: %d", err[0])

                        return NLMSG_ERROR

                self.gnh.unpack_from(buff[NLMSG_HDRLEN:])

                self.gnh.info()

                attr_start = NLMSG_HDRLEN + GENL_HDRLEN

                while 1 :

                        if len(buff[attr_start:]) < NLA_HDRLEN : break

                        attr = nlattr()
                        attr.unpack_from(buff[attr_start:])

                        attr.info()

                        self.nla.append(attr)

                        attr_start += NLMSG_ALIGN(attr.nla_len)

                log.debug("%d attrs in pkt", len(self.nla))

                return NLMSG_DONE

        def get_attr(self, kind, from_idx = 0) :
                return get_attr(self.nla, kind, from_idx)

class genl_conn :

        sock = None

        family = ""

        famid = -1

        def __init__(self, family) :
                self.family = family

        def connect(self) :
                self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
                self.sock.bind((os.getpid(),0))
                self.famid = self.familyid()
                return self.sock, self.famid

        def shutdown(self) :
                self.sock.close()

        def familyid(self):

                gnlpkt = gnlpacket(NLM_F_REQUEST, 0, CTRL_CMD_GETFAMILY, GENL_ID_CTRL)

                # kernel expects a \0 for a c-string 
                gnlpkt.add_attr(CTRL_ATTR_FAMILY_NAME, self.family, len(self.family) + 1)

                sent = self.sock.sendto(gnlpkt.pack(), (0,0));

                buf = self.sock.recv(8192);

                gnlpkt.unpack_from(buf)

                nla, i = gnlpkt.get_attr(CTRL_ATTR_FAMILY_ID)

                if nla != None:

                        fmid = struct.unpack_from("H", nla.nla_data)

                        log.debug("family id = %d", fmid[0])

                        return fmid[0]

                else :
                        log.error("error genl family reply")

                        return -1

        def send(self, gnlpkt) :
                if gnlpkt.nlh.nlm_type == 0 : gnlpkt.nlh.nlm_type = self.famid
                sent =  self.sock.sendto(gnlpkt.pack(), (0,0));
                return sent;

        def recv(self) :
                gnlpkt = gnlpacket()
                buf = self.sock.recv(8192);

                if buf :
                        if NLMSG_DONE == gnlpkt.unpack_from(buf) :
                                return gnlpkt
                return None

        def setblocking(self, blocking = False) :
                if blocking : self.sock.setblocking(1)
                else :  self.sock.setblocking(0)
                                                                                                  363,1         Bot

