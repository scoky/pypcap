#!/usr/bin/env python

import struct
import socket
from itertools import izip
import time

class Header(object):
  def __init__(self, *args, **kwargs):
    self.payload = None
    self._fields = [f[0] for f in args]
    self._fmt = (kwargs['endian'] if 'endian' in kwargs else '') + ''.join([f[1] for f in args])
    for f in args:
      setattr(self, f[0], 0x0 if f[1] in 'IHB' else None)

  def from_wire(self, buf, ofs = 0):
    for f, val in izip(self._fields, struct.unpack_from(self._fmt, buf, ofs)):
      setattr(self, f, val)
    self.payload = buffer(buf, ofs + struct.calcsize(self._fmt))
    self._post_from_wire(self.payload, 0)
    return self

  def _post_from_wire(self, buf, ofs):
    pass # for subclasses to override

  def __len__(self):
    return struct.calcsize(self._fmt)

  def __getitem__(self, k):
    try:
        return getattr(self, k)
    except AttributeError:
        raise KeyError

  def to_wire(self, buf, ofs = 0):
    struct.pack_into(self._fmt, buf, ofs, *[getattr(self, f) for f in self._fields])
    self._post_to_wire(buf, ofs + struct.calcsize(self._fmt))

  def _post_to_wire(self, buf, ofs):
    pass # for subclasses to override

  def __str__(self):
    return '{0} [ {1} ]'.format(self.__class__, ', '.join(['{0} = \'{1}\''.format(f, self._format_field(getattr(self, f))) for f in self.fields]))

  @property
  def fields(self):
    return self._fields

  def _format_field(self, field):
    if field is None:
      return field
    if type(field) is str:
      return '0x' + field.encode('hex')
    else:
      return hex(field)

  __repr__ = __str__

  @property
  def next_protocol(self):
    return None

### PCAP FILE FORMAT ###

class PcapFileHeader(Header):
  def __init__(self):
    super(PcapFileHeader, self).__init__(
      ('magic', 'I'),
      ('v_major', 'H'),
      ('v_minor', 'H'),
      ('thiszone', 'I'),
      ('sigfigs', 'I'),
      ('snaplen', 'I'),
      ('linktype', 'I')
    )

  MAGIC = 0xa1b2c3d4

class RecordHeader(Header):
  def __init__(self, fileheader):
    super(RecordHeader, self).__init__(
      ('ts_sec', 'I'),
      ('ts_usec', 'I'),
      ('incl_len', 'I'),
      ('orig_len', 'I')
    )
    self._fileheader = fileheader

  @property
  def next_protocol(self):
    if self._fileheader.linktype in SUPPORT_LINK_TYPES:
      return SUPPORT_LINK_TYPES[self._fileheader.linktype]
    else:
      return None

  def parse(self):
    headers = []
    unparsed = self._collect_headers(self.next_protocol, headers, self.payload)
    return PcapPacket(headers, unparsed)

  def _collect_headers(self, next_protocol, headers, buf):
    if next_protocol is None:
      return buf
    else:
      next_header = next_protocol()
      if len(buf) < len(next_header):
        # Not enough bytes to parse header
        return buf
      next_header.from_wire(buf, 0)
      headers.append(next_header)
      return self._collect_headers(next_header.next_protocol, headers, buffer(buf, len(next_header)))

### LINK LAYER ###

class LinkHeader(Header):
  pass

class EthernetHeader(LinkHeader):
  def __init__(self):
    super(EthernetHeader, self).__init__(
      ('dst', '6s'),
      ('src', '6s'),
      ('next_type', 'H'),
      endian = '!'
    )

  def _mac_to_str(self, mac):
    string = mac.encode('hex')
    return ':'.join(string[i:i+2] for i in range(0,12,2))

  def _str_to_mac(self, string):
    return string.replace(':', '').decode('hex')

  @property
  def next_protocol(self):
    if self.next_type in SUPPORT_NETWORK_TYPES:
      return SUPPORT_NETWORK_TYPES[self.next_type]
    else:
      return None

  TYPE = 1

SUPPORT_LINK_TYPES = {
  subclass.TYPE : subclass for subclass in LinkHeader.__subclasses__()
}

### Network Layer ###

class NetworkHeader(Header):
  pass

class IPv4Header(NetworkHeader):
  def __init__(self):
    super(IPv4Header, self).__init__(
      ('ver_len', 'B'),
      ('diff_ecn', 'B'),
      ('tot_len', 'H'),
      ('ident', 'H'),
      ('flg_ofs', 'H'),
      ('ttl', 'B'),
      ('protocol', 'B'),
      ('checksum', 'H'),
      ('src', 'I'),
      ('dst', 'I'),
      endian = '!'
    )
    #NB: options are ignored

  @property
  def version(self):
    return self.ver_len >> 4

  @version.setter
  def version(self, ver):
    self.ver_len = (self.ver_len & 0x0f) | ((ver << 4) & 0xf0)

  @property
  def ihl(self):
    return self.ver_len & 0x0f

  @ihl.setter
  def ihl(self, v):
    self.ver_len = (self.ver_len & 0xf0) | (v & 0x0f)

  @property
  def diffserv(self):
    return self.diff_ecn >> 2

  @diffserv.setter
  def diffserv(self, v):
    self.diff_ecn = (self.diff_ecn & 0x03) | ((v << 2) & 0xfc)

  @property
  def ecn(self):
    return self.diff_ecn & 0x03

  @ecn.setter
  def ecn(self, v):
    self.diff_ecn = (self.diff_ecn & 0xfc) | (v & 0x03)

  @property
  def flags(self):
    return self.flg_ofs >> 13

  @flags.setter
  def flags(self, v):
    self.flg_ofs = (self.flg_ofs & 0x1fff) | ((v << 13) & 0xe000)

  @property
  def frag_offset(self):
    return self.flg_ofs & 0x1fff

  @frag_offset.setter
  def frag_offset(self, v):
    self.flg_ofs = (self.flg_ofs & 0xe000) | (v & 0x1fff)

  def __len__(self):
    return max(self.ihl * 4, 20)

  def _ip_to_str(self, ip):
    return socket.inet_ntop(socket.AF_INET, struct.pack("!I", ip))

  def _str_to_ip(self, string):
    return struct.unpack("!I", socket.inet_pton(socket.AF_INET, ip))[0]

  @property
  def fields(self):
    for f in super(IPv4Header, self).fields:
      if f == 'ver_len':
        yield 'version'
        yield 'ihl'
      elif f == 'diff_ecn':
        yield 'diffserv'
        yield 'ecn'
      elif f == 'flg_ofs':
        yield 'flags'
        yield 'frag_offset'
      else:
        yield f

  @property
  def next_protocol(self):
    if self.protocol in SUPPORT_TRANSPORT_TYPES:
      return SUPPORT_TRANSPORT_TYPES[self.protocol]
    else:
      return None

  TYPE = 0x0800

class IPv6Header(NetworkHeader):
  def __init__(self):
    super(IPv6Header, self).__init__(
      ('ver_class_flow', 'I'),
      ('payload_length', 'H'),
      ('next_header', 'B'),
      ('hop_limit', 'B'),
      ('src', '16s'),
      ('dst', '16s'),
      endian = '!'
    )

  @property
  def version(self):
    return self.ver_class_flow >> 28

  @version.setter
  def version(self, ver):
    self.ver_class_flow = (self.ver_class_flow & 0x0fffffff) | ((ver << 28) & 0xf0000000)

  @property
  def traffic_class(self):
    return (self.ver_class_flow & 0x0ff00000) >> 20

  @traffic_class.setter
  def traffic_class(self, v):
    self.ver_class_flow = (self.ver_class_flow & 0xf00fffff) | ((v << 20) & 0x0ff00000)

  @property
  def flow_label(self):
    return self.ver_class_flow & 0x000fffff

  @flow_label.setter
  def flow_label(self, v):
    self.ver_class_flow = (self.ver_class_flow & 0xfff00000) | (v & 0x000fffff)

  def _ipv6_to_str(self, ip):
    return socket.inet_ntop(socket.AF_INET6, struct.pack("!QQ", ip >> 64, ip & 0xffffffffffffffff))

  def _str_to_ipv6(self, string):
    hi, lo = struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, string))
    return (hi << 64) | lo

  @property
  def fields(self):
    for f in super(IPv6Header, self).fields:
      if f == 'ver_class_flow':
        yield 'version'
        yield 'traffic_class'
        yield 'flow_label'
      else:
        yield f

  @property
  def next_protocol(self):
    # NB: May actually be an extension header, but lets ignore that for now
    if self.next_header in SUPPORT_TRANSPORT_TYPES:
      return SUPPORT_TRANSPORT_TYPES[self.next_header]
    else:
      return None

  TYPE = 0x86dd

SUPPORT_NETWORK_TYPES = {
  subclass.TYPE : subclass for subclass in NetworkHeader.__subclasses__()
}

### Transport Layer ###

class TransportHeader(Header):
  # Assumption that all implementations of transport will have src_port and dst_port fields
  @property
  def next_protocol(self):
    # Match on port
    if self.dst_port in SUPPORT_APP_TYPES:
      return SUPPORT_APP_TYPES[self.dst_port]
    elif self.src_port in SUPPORT_APP_TYPES:
      return SUPPORT_APP_TYPES[self.src_port]
    else:
      return None

class UDPHeader(TransportHeader):
  def __init__(self):
    super(UDPHeader, self).__init__(
      ('src_port', 'H'),
      ('dst_port', 'H'),
      ('length', 'H'),
      ('checksum', 'H'),
      endian = '!'
    )

  TYPE = 17

class TCPHeader(TransportHeader):
  def __init__(self):
    super(TCPHeader, self).__init__(
      ('src_port', 'H'),
      ('dst_port', 'H'),
      ('seqnum', 'I'),
      ('acknum', 'I'),
      ('rawflags', 'H'),
      ('window', 'H'),
      ('chksum', 'H'),
      ('urgptr', 'H'),
      endian = '!'
    )
    self.options = []
    self.padding = buffer('')

  TYPE = 6

  @property
  def data_offset(self):
    return self.rawflags >> 12

  @data_offset.setter
  def data_offset(self, val):
    self.rawflags = (self.rawflags & 0x0fff) | ((val << 12) & 0xf000)

  @property
  def reserved(self):
    return (self.rawflags >> 6) & 0x003f

  @reserved.setter
  def reserved(self, val):
    self.rawflags = (self.rawflags & 0xf03f) | ((val << 6) & 0x0fc0)

  @property
  def flags(self):
    return self.rawflags & 0x003f

  @flags.setter
  def flags(self, val):
    self.rawflags = (self.rawflags & 0xffc0) | (val & 0x003f)

  def _post_from_wire(self, buf, ofs):
    opt_len = (self.data_offset - 5) * 4
    i_ofs = ofs
    while ofs < i_ofs + opt_len:
      kind = struct.unpack_from('!B', buf, ofs)[0]
      ofs += 1
      if kind == 0x0: # end of options
        self.options.append((kind, buffer(buf, ofs, 0)))
        break
      elif kind == 0x1: # noop
        self.options.append((kind, buffer(buf, ofs, 0)))
      else:
        length = struct.unpack_from('!B', buf, ofs)[0]
        ofs += 1
        self.options.append((kind, buffer(buf, ofs, length - 2)))
        ofs += length - 2
    self.padding = buffer(buf, ofs, opt_len - (ofs - i_ofs))

  def _post_to_wire(self, buf, ofs):
    for opt in self.options:
      struct.pack_into('!BB', buf, ofs, opt[0], len(opt[1] + 2))
      ofs += 2
      buf[ofs:ofs+len(opt)] = opt[1]
      ofs += len(opt)
    buf[ofs:ofs+len(self.padding)] = self.padding

  def __len__(self):
    return 20 + sum(len(opt[1]) + 2 for opt in self.options) + len(self.padding)

  @property
  def fields(self):
    for f in super(TCPHeader, self).fields:
      if f == 'rawflags':
        yield 'data_offset'
        yield 'reserved'
        yield 'flags'
      else:
        yield f

SUPPORT_TRANSPORT_TYPES = {
  subclass.TYPE : subclass for subclass in TransportHeader.__subclasses__()
}

### Application Layer ###

class AppHeader(Header):
  pass
  # NB: Application Layer matches on port number, rather than protocol type

class DNSHeader(AppHeader):
  def __init__(self):
    super(DNSHeader, self).__init__(
      ('ident', 'H'),
      ('flags', 'H'),
      ('num_ques', 'H'),
      ('num_ans', 'H'),
      ('num_auths', 'H'),
      ('num_adds', 'H'),
      endian = '!'
    )
    self.questions = []
    self.answers = []
    self.authorities = []
    self.additionals = []

  def _post_from_wire(self, buf, ofs):
    for i in xrange(self.num_ques):
      q = DNSQuestion()
      q.from_wire(buf, ofs)
      ofs += len(q)
      self.questions.append(q)
    for section, count in ((self.answers, self.num_ans), (self.authorities, self.num_auths), (self.additionals, self.num_adds)):
      for i in xrange(count):
        rr = DNSRecord()
        rr.from_wire(buf, ofs)
        ofs += len(rr)
        section.append(rr)

  def _post_to_wire(self, buf, ofs):
    for section in (self.questions, self.answers, self.authorities, self.additionals):
      for r in section:
        r.to_wire(buf, ofs)
        ofs += len(r)

  def __len__(self):
    l = super(DNSHeader, self).__len__()
    for section in (self.questions, self.answers, self.authorities, self.additionals):
      for r in section:
        l += len(r)
    return l

  def __str__(self):
    val = super(DNSHeader, self).__str__()
    if len(self.questions) > 0:
      val += '\nQUESTIONS:\n' + '\n'.join(map(str, self.questions))
    if len(self.answers) > 0:
      val += '\nANSWERS:\n' + '\n'.join(map(str, self.answers))
    if len(self.authorities) > 0:
      val += '\nAUTHORITIES:\n' + '\n'.join(map(str, self.authorities))
    if len(self.additionals) > 0:
      val += '\nADDITIONALS:\n' + '\n'.join(map(str, self.additionals))
    return val

  __repr__ = __str__

  PORT = 53

class DNSRecord(object):
  def __init__(self):
    self._name = None
    self._rdtype = None
    self._rdclass = None
    self._ttl = None
    self._rlength = None
    self._rdata = None

  def from_wire(self, buf, ofs):
    start_ofs = ofs
    self._name = DNSName()
    self._name.from_wire(buf, ofs)
    ofs += len(self._name)
    self._rdtype, self._rdclass, self._ttl, self._rlength = struct.unpack_from('!HHIH', buf, ofs)
    ofs += 10
    self._rdata = buffer(buf, ofs, self._rlength)

  def to_wire(self, buf, ofs):
    self._name.to_wire(buf, ofs)
    ofs += len(self._name)
    struct.pack_into('!HHIH', buf, ofs, self._rdtype, self._rdclass, self._ttl, self._rlength)
    ofs += 10
    buf[ofs:ofs+self._rlength] = self._rdata

  @property
  def name(self):
    return self._name

  @property
  def rdtype(self):
    return self._rdtype

  @property
  def rdclass(self):
    return self._rdclass

  @property
  def ttl(self):
    return self._ttl

  @property
  def rlength(self):
    return self._rlength

  @property
  def rdata(self):
    return self._rdata

  def __len__(self):
    return len(self._name) + 10 + self._rlength

  def __str__(self):
    return '{0} ({1} {2} {3} {4} {5})'.format(self.__class__, self._name, self._ttl, self._rdclass, self._rdtype, self._rdata)

  __repr__ = __str__

class OPTRecord(object):
  def __init__(self):
    self._name = None
    self._opt = None
    self._payload_size = None
    self._ext_rcode = None
    self._rlength = None
    self._options = []

  def from_record(self, record):
    self._name = record.name
    self._opt = record.rdtype
    self._payload_size = record.rdclass
    self._ext_rcode = record.ttl
    self._rlength = record.rlength
    ofs = 0
    while ofs < self._rlength:
      opt = OPTOption()
      opt.from_wire(record.rdata, ofs)
      ofs += len(opt)
      self._options.append(opt)

  def to_wire(self):
    raise Exception('Not Implemented!')

  @property
  def name(self):
    return self._name

  @property
  def opt(self):
    return self._opt

  @property
  def payload_size(self):
    return self._payload_size

  @property
  def ext_rcode(self):
    return self._ext_rcode

  @property
  def options(self):
    return self._options

  def __len__(self):
    return len(self._name) + 10 + sum(len(opt) for opt in self._options)

  def __str__(self):
    return '{0} ({1} {2} {3} {4} {5})'.format(self.__class__, self._name, self._opt, self._payload_size, self._ext_rcode, len(self._options))

  __repr__ = __str__

class OPTOption(object):
  def __init__(self):
    self._code = None
    self._length = None
    self._data = None

  def from_wire(self, buf, ofs):
    self._code, self._length = struct.unpack_from('!HH', buf, ofs)
    self._data = buffer(buf, ofs + 4, self._length)

  def to_wire(self, buf, ofs):
    struct.pack_into('!HH', buf, ofs, self._code, self._length)
    buf[ofs:ofs+self._length] = self._data

  @property
  def code(self):
    return self._code

  @property
  def length(self):
    return self._length

  @property
  def data(self):
    return self._data

  def __len__(self):
    return 4 + self._length

  def __str__(self):
    return '{0} ({1} {2} {3} {4} {5})'.format(self.__class__, self._code, self._length, self._data)

  __repr__ = __str__

class DNSQuestion(object):
  def __init__(self):
    self._name = None
    self._rdtype = 0
    self._rdclass = 0

  def from_wire(self, buf, ofs):
    self._name = DNSName()
    self._name.from_wire(buf, ofs)
    ofs += len(self._name)
    self._rdtype, self._rdclass = struct.unpack_from('!HH', buf, ofs)

  def to_wire(self, buf, ofs):
    self._name.to_wire(buf, ofs)
    ofs += len(self._name)
    struct.pack_into('!HH', buf, ofs, self._rdtype, self._rdclass)

  @property
  def name(self):
    return self._name

  @property
  def rdtype(self):
    return self._rdtype

  @property
  def rdclass(self):
    return self._rdclass

  def __len__(self):
    return len(self._name) + 4

  def __str__(self):
    return '{0} ({1} {2} {3})'.format(self.__class__, self._name, self._rdclass, self._rdtype)

  __repr__ = __str__

class DNSName(object):
  def __init__(self):
    self._labels = None

  def from_wire(self, buf, ofs):
    start_ofs = ofs
    lbl_len = struct.unpack_from('!B', buf, ofs)[0]
    while True:
      if lbl_len == 0x00:
        # Terminating byte
        ofs += 1
        break
      elif lbl_len & 0xc0 == 0xc0:
        # Reference
        ofs += 2
        break
      elif lbl_len & 0xc0 == 0x00:
        ofs += lbl_len + 1
        lbl_len = struct.unpack_from('!B', buf, ofs)[0]
      else:
        # Unparsable
        break
    self._labels = buffer(buf, start_ofs, ofs - start_ofs)

  def to_wire(self, buf, ofs):
    buf[ofs:ofs+len(self._labels)] = self._labels

  def from_str(self, string):
    raise Exception('Not Implemented!')
    # self._labels = tuple(string.strip('.').split('.'))
    # self._length = sum(len(lbl) + 1 for lbl in self._labels) + 1

  @property
  def labels(self):
    return self._labels

  def __len__(self):
    return len(self._labels)

  def __str__(self):
    return str(self._labels)

  __repr__ = __str__

SUPPORT_APP_TYPES = {
  subclass.PORT : subclass for subclass in AppHeader.__subclasses__()
}

### Reader ###

class store(object):
    def __init__(self, calculate_function):
        self._calculate = calculate_function

    def __get__(self, obj, _=None):
        if obj is None:
            return self
        value = self._calculate(obj)
        setattr(obj, self._calculate.func_name, value)
        return value

class PcapPacket(object):
  def __init__(self, headers = [], buf = ''):
    self._headers = headers
    self._buffer = buf

  @store
  def link(self):
    # Link layer must be the first header
    if len(self._headers) > 0 and type(self._headers[0]) in SUPPORT_LINK_TYPES.values():
        return self._headers[0]
    return None

  @store
  def network(self):
    # network layer should be the second (or possible in some edge cases third) header
    for i in xrange(1, min(3, len(self._headers))):
      if type(self._headers[i]) in SUPPORT_NETWORK_TYPES.values():
        return self._headers[i]
    return None

  @store
  def transport(self):
    # transport layer is the third or fourth header
    for i in xrange(2, min(5, len(self._headers))):
      if type(self._headers[i]) in SUPPORT_TRANSPORT_TYPES.values():
        return self._headers[i]
    return None

  @store
  def application(self):
    # application layer is > third layer
    for i in xrange(3, len(self._headers)):
      if type(self._headers[i]) in SUPPORT_APP_TYPES.values():
        return self._headers[i]
    return None

  @property
  def headers(self):
    return self._headers

  @property
  def unparsed(self):
    # Everything that wasn't parsed (if there was anything)
    return self._buffer

  def __len__(self):
    l = 0
    for h in self._headers:
      l += len(h)
    return l + len(self._buffer)

  def __str__(self):
    val = ''
    for header in self._headers:
      val += str(header) + '\n'
    return val + ' unparsed len({0})'.format(len(self._buffer))

  __repr__ = __str__

class PcapReader:
  def __init__(self, stream):
    self._stream = stream
    self._header = PcapFileHeader()
    buf = self._stream.read(len(self._header))
    self._header.from_wire(buf)
    if self._header.magic != PcapFileHeader.MAGIC:
      raise Exception('Pcap magic does not match!')

  def __iter__(self):
    return self._yield_records()

  def _yield_records(self):
    while True:
      # Read next record header
      record = RecordHeader(self._header)
      buf = self._stream.read(len(record))
      if not buf:
        break
      record.from_wire(buf)

      # Read full record
      buf = self._stream.read(record.incl_len)
      record.payload = buf
      if not buf:
        raise Exception('Missing data!')
      yield record

class PcapWriter:
  def __init__(self, stream, linktype):
    self._stream = stream
    self._header = PcapFileHeader()
    # Set the necessary pcap header values
    self._header.magic = PcapFileHeader.MAGIC
    self._header.v_major = 0x2
    self._header.v_minor = 0x4
    self._header.snaplen = 0x2000
    self._header.linktype = linktype
    # Maximum size buffer to write packets in wireformat to
    self._buffer = bytearray(self._header.snaplen)
    # Write out the pcap header
    self._header.to_wire(self._buffer, 0)
    in_wire = buffer(self._buffer, 0, len(self._header))
    self._stream.write(in_wire)

  def write(self, pkt):
    # Create a new record
    record = RecordHeader(self._header)
    record.ts_sec = int(time.time())
    record.ts_usec = 0
    record.incl_len = min(self._header.snaplen, len(pkt))
    record.orig_len = len(pkt)
    # Write out the packet in wire format to buffer
    ofs = 0
    record.to_wire(self._buffer, ofs)
    ofs += len(record)
    for h in pkt.headers:
      h.to_wire(self._buffer, ofs)
      ofs += len(h)
    self._buffer[ofs:ofs+len(pkt.unparsed)] = pkt.unparsed
    in_wire = buffer(self._buffer, 0, record.incl_len + len(record))
    # Write buffer to stream
    self._stream.write(in_wire)
