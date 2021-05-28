import binascii, random, socket, struct
from dnslib.label import DNSLabel, DNSBuffer
from ranges import BYTES, H,I,IP4,IP6,\
                          check_bytes
from buffer import Buffer
from itertools import chain
from lex import WordLexer

class DNSError(Exception):
    pass


class BimapError(Exception):
    pass


class Bimap(object):
    def __init__(self, name, forward, error=AttributeError):
        self.name = name
        self.error = error
        self.forward = forward.copy()
        self.reverse = dict([(v, k) for (k, v) in list(forward.items())])

    def get(self, k, default=None):
        try:
            return self.forward[k]
        except KeyError as e:
            return default or str(k)


QTYPE = Bimap('QTYPE',
              {1: 'A', 2: 'NS', 12: 'PTR',
               28: 'AAAA',}, DNSError)

CLASS = Bimap('CLASS',
              {1: 'IN', 2: 'CS', 3: 'CH', 4: 'Hesiod', 254: 'None', 255: '*'},
              DNSError)
QR = Bimap('QR',
           {0: 'QUERY', 1: 'RESPONSE'}, DNSError)
RCODE = Bimap('RCODE',
              {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
               4: 'NOTIMP', 5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET',
               8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE'},
              DNSError)
OPCODE = Bimap('OPCODE', {0: 'QUERY', 1: 'IQUERY', 2: 'STATUS', 4: 'NOTIFY', 5: 'UPDATE'},
               DNSError)


class RD(object):

    @classmethod
    def parse(cls,buffer,length):
        """
            Unpack from buffer
        """
        try:
            data = buffer.get(length)
            return cls(data)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking RD [offset=%d]: %s" %
                                    (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        """
            Create new record from zone format data
            RD is a list of strings parsed from DiG output
        """
        # Unknown rata - assume hexdump in zone format
        # (DiG prepends "\\# <len>" to the hexdump so get last item)
        return cls(binascii.unhexlify(rd[-1].encode('ascii')))

    def __init__(self,data=b""):
        # Assume raw bytes
        check_bytes('data',data)
        self.data = bytes(data)

    def pack(self,buffer):
        """
            Pack record into buffer
        """
        buffer.append(self.data)

    def __repr__(self):
        """
            Default 'repr' format should be equivalent to RD zone format
        """
        # For unknown rdata just default to hex
        return binascii.hexlify(self.data).decode()

    def toZone(self):
        return repr(self)

    # Comparison operations - in most cases only need to override 'attrs'
    # in subclass (__eq__ will automatically compare defined atttrs)

    # Attributes for comparison
    attrs = ('data',)

    def __eq__(self,other):
        if type(other) != type(self):
            return False
        else:
            return all([getattr(self,x) == getattr(other,x) for x in self.attrs])

    def __ne__(self,other):
        return not(self.__eq__(other))

def _force_bytes(x):
    if isinstance(x,bytes):
        return x
    else:
        return x.encode()

class A(RD):

    data = IP4('data')

    @classmethod
    def parse(cls,buffer,length):
        try:
            data = buffer.unpack("!BBBB")
            return cls(data)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking A [offset=%d]: %s" %
                                (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(rd[0])

    def __init__(self,data):
        if type(data) in (tuple,list):
            self.data = tuple(data)
        else:
            self.data = tuple(map(int,data.rstrip(".").split(".")))

    def pack(self,buffer):
        buffer.pack("!BBBB",*self.data)

    def __repr__(self):
        return "%d.%d.%d.%d" % self.data

def _parse_ipv6(a):
    l,_,r = a.partition("::")
    l_groups = list(chain(*[divmod(int(x,16),256) for x in l.split(":") if x]))
    r_groups = list(chain(*[divmod(int(x,16),256) for x in r.split(":") if x]))
    zeros = [0] * (16 - len(l_groups) - len(r_groups))
    return tuple(l_groups + zeros + r_groups)

def get_bits(data,offset,bits=1):
    mask = ((1 << bits) - 1) << offset
    return (data & mask) >> offset

def set_bits(data,value,offset,bits=1):
    mask = ((1 << bits) - 1) << offset
    clear = 0xffff ^ mask
    data = (data & clear) | ((value << offset) & mask)
    return data

def binary(n,count=16,reverse=False):
    bits = [str((n >> y) & 1) for y in range(count-1, -1, -1)]
    if reverse:
        bits.reverse()
    return "".join(bits)

def _format_ipv6(a):
    left = []
    right = []
    current = 'left'
    for i in range(0,16,2):
        group = (a[i] << 8) + a[i+1]
        if current == 'left':
            if group == 0 and i < 14:
                if (a[i+2] << 8) + a[i+3] == 0:
                    current = 'right'
                else:
                    left.append("0")
            else:
                left.append("%x" % group)
        else:
            if group == 0 and len(right) == 0:
                pass
            else:
                right.append("%x" % group)
    if len(left) < 8:
        return ":".join(left) + "::" + ":".join(right)
    else:
        return ":".join(left)

def label(label,origin=None):
    if label.endswith("."):
        return DNSLabel(label)
    else:
        return (origin if isinstance(origin,DNSLabel)
                       else DNSLabel(origin)).add(label)

class DNSUtils(object):

    @property
    def q(self):
        return self._q

    @classmethod
    def parse(cls, packet):
        """
            Parse DNS packet data and return DNSRecord instance
            Recursively parses sections (calling appropriate parse method)
        """
        buffer = DNSBuffer(packet)
        try:
            header = DNSHeader.parse(buffer)
            questions = []
            rr = []
            auth = []
            ar = []
            for i in range(header.q):
                questions.append(DNSQuestion.parse(buffer))
            for i in range(header.a):
                rr.append(RR.parse(buffer))
            for i in range(header.auth):
                auth.append(RR.parse(buffer))
            for i in range(header.ar):
                ar.append(RR.parse(buffer))
            return cls(header, questions, rr, auth=auth, ar=ar)
        except DNSError:
            raise
        except (BufferError, BimapError) as e:
            raise DNSError("Error unpacking DNSRecord [offset=%d]: %s" % (
                buffer.offset, e))

    @classmethod
    def question(cls, qname, qtype="A", qclass="IN"):
        return DNSUtils(q=DNSQuestion(qname, getattr(QTYPE, qtype),
                                      getattr(CLASS, qclass)))

    def __init__(self, header=None, questions=None,
                 rr=None, q=None, a=None, auth=None, ar=None):
        """
            Create new DNSRecord
        """
        self._q = None
        self.header = header or DNSHeader()
        self.questions = questions or []
        self.rr = rr or []
        self.auth = auth or []
        self.ar = ar or []
        # Shortcuts to add a single Question/Answer
        if q:
            self.questions.append(q)
        if a:
            self.rr.append(a)
        self.set_header_qa()

    def reply(self, ra=1, aa=1):
        return DNSUtils(DNSHeader(id=self.header.id,
                                  bitmap=self.header.bitmap,
                                  qr=1, ra=ra, aa=aa),
                        q=self.q)

    def replyZone(self, zone, ra=1, aa=1):
        return DNSUtils(DNSHeader(id=self.header.id,
                                  bitmap=self.header.bitmap,
                                  qr=1, ra=ra, aa=aa),
                        q=self.q,
                        rr=RR.fromZone(zone))

    def add_question(self, *q):
        self.questions.extend(q)
        self.set_header_qa()

    def add_answer(self, *rr):
        self.rr.extend(rr)
        self.set_header_qa()

    def add_auth(self, *auth):
        self.auth.extend(auth)
        self.set_header_qa()

    def add_ar(self, *ar):
        self.ar.extend(ar)
        self.set_header_qa()

    def set_header_qa(self):
        self.header.q = len(self.questions)
        self.header.a = len(self.rr)
        self.header.auth = len(self.auth)
        self.header.ar = len(self.ar)

    # Shortcut to get first question
    def get_q(self):
        return self.questions[0] if self.questions else DNSQuestion()

    q = property(get_q)

    # Shortcut to get first answer
    def get_a(self):
        return self.rr[0] if self.rr else RR()

    a = property(get_a)

    def pack(self):
        self.set_header_qa()
        buffer = DNSBuffer()
        self.header.pack(buffer)
        for q in self.questions:
            q.pack(buffer)
        for rr in self.rr:
            rr.pack(buffer)
        for auth in self.auth:
            auth.pack(buffer)
        for ar in self.ar:
            ar.pack(buffer)
        return buffer.data

    def truncate(self):
        return DNSUtils(DNSHeader(id=self.header.id,
                                  bitmap=self.header.bitmap,
                                  tc=1))

    def send(self, dest, port=53, tcp=False, timeout=None, ipv6=False):
        """
            Send packet to nameserver and return response
        """
        data = self.pack()
        if ipv6:
            inet = socket.AF_INET6
        else:
            inet = socket.AF_INET
        try:
            sock = None
            if tcp:
                if len(data) > 65535:
                    raise ValueError("Packet length too long: %d" % len(data))
                data = struct.pack("!H", len(data)) + data
                sock = socket.socket(inet, socket.SOCK_STREAM)
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.connect((dest, port))
                sock.sendall(data)
                response = sock.recv(8192)
                length = struct.unpack("!H", bytes(response[:2]))[0]
                while len(response) - 2 < length:
                    response += sock.recv(8192)
                response = response[2:]
            else:
                sock = socket.socket(inet, socket.SOCK_DGRAM)
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.sendto(self.pack(), (dest, port))
                response, server = sock.recvfrom(8192)
        finally:
            pass
        return response

    def format(self, prefix="", sort=False):
        """
            Formatted 'repr'-style representation of record
            (optionally with prefix and/or sorted RRs)
        """
        s = sorted if sort else lambda x: x
        sections = [repr(self.header)]
        sections.extend(s([repr(q) for q in self.questions]))
        sections.extend(s([repr(rr) for rr in self.rr]))
        sections.extend(s([repr(rr) for rr in self.auth]))
        sections.extend(s([repr(rr) for rr in self.ar]))
        return prefix + ("\n" + prefix).join(sections)

    def toZone(self, prefix=""):
        """
            Formatted 'DiG' (zone) style output
            (with optional prefix)
        """
        z = self.header.toZone().split("\n")
        if self.questions:
            z.append(";; QUESTION SECTION:")
            [z.extend(q.toZone().split("\n")) for q in self.questions]
        if self.rr:
            z.append(";; ANSWER SECTION:")
            [z.extend(rr.toZone().split("\n")) for rr in self.rr]
        if self.auth:
            z.append(";; AUTHORITY SECTION:")
            [z.extend(rr.toZone().split("\n")) for rr in self.auth]
        if self.ar:
            z.append(";; ADDITIONAL SECTION:")
            [z.extend(rr.toZone().split("\n")) for rr in self.ar]
        return prefix + ("\n" + prefix).join(z)

    def short(self):
        """
            Just return RDATA
        """
        return "\n".join([rr.rdata.toZone() for rr in self.rr])

    def diff(self, other):
        """
            Diff records - recursively diff sections (sorting RRs)
        """
        err = []
        if self.header != other.header:
            err.append((self.header, other.header))
        for section in ('questions', 'rr', 'auth', 'ar'):
            if section == 'questions':
                k = lambda x: tuple(map(str, (x.qname, x.qtype)))
            else:
                k = lambda x: tuple(map(str, (x.rname, x.rtype, x.rdata)))
            a = dict([(k(rr), rr) for rr in getattr(self, section)])
            b = dict([(k(rr), rr) for rr in getattr(other, section)])
            sa = set(a)
            sb = set(b)
            for e in sorted(sa.intersection(sb)):
                if a[e] != b[e]:
                    err.append((a[e], b[e]))
            for e in sorted(sa.difference(sb)):
                err.append((a[e], None))
            for e in sorted(sb.difference(sa)):
                err.append((None, b[e]))
        return err

class AAAA(RD):

    """
        Basic support for AAAA record - accepts IPv6 address data as either
        a tuple of 16 bytes or in text format
    """

    data = IP6('data')

    @classmethod
    def parse(cls,buffer,length):
        try:
            data = buffer.unpack("!16B")
            return cls(data)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking AAAA [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(rd[0])

    def __init__(self, data):
        super().__init__(data)
        if type(data) in (tuple,list):
            self.data = tuple(data)
        else:
            self.data = _parse_ipv6(data)

    def pack(self,buffer):
        buffer.pack("!16B",*self.data)

    def __repr__(self):
        return _format_ipv6(self.data)

class CNAME(RD):

    @classmethod
    def parse(cls,buffer,length):
        try:
            label = buffer.decode_name()
            return cls(label)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking CNAME [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(label(rd[0],origin))

    def __init__(self, label=None):
        super().__init__()
        self.label = label

    def set_label(self,label):
        if isinstance(label,DNSLabel):
            self._label = label
        else:
            self._label = DNSLabel(label)

    def get_label(self):
        return self._label

    label = property(get_label,set_label)

    def pack(self,buffer):
        buffer.encode_name(self.label)

    def __repr__(self):
        return "%s" % (self.label)

    attrs = ('label',)


class PTR(CNAME):
    pass

class NS(CNAME):
    pass


RDMAP = { 'A':A, 'AAAA':AAAA, 'PTR':PTR,'NS':NS }

class DNSHeader(object):
    """
        DNSHeader section
    """

    # Ensure attribute values match packet
    id = H('id')
    bitmap = H('bitmap')
    q = H('q')
    a = H('a')
    auth = H('auth')
    ar = H('ar')

    @classmethod
    def parse(cls, buffer):
        """
            Implements parse interface
        """
        try:
            (id, bitmap, q, a, auth, ar) = buffer.unpack("!HHHHHH")
            return cls(id, bitmap, q, a, auth, ar)
        except (BufferError, BimapError) as e:
            raise DNSError("Error unpacking DNSHeader [offset=%d]: %s" % (
                buffer.offset, e))

    def __init__(self, id=None, bitmap=None, q=0, a=0, auth=0, ar=0, **args):
        if id is None:
            self.id = random.randint(0, 65535)
        else:
            self.id = id
        if bitmap is None:
            self.bitmap = 0
            self.rd = 1
        else:
            self.bitmap = bitmap
        self.q = q
        self.a = a
        self.auth = auth
        self.ar = ar
        for k, v in args.items():
            if k.lower() == "qr":
                self.qr = v
            elif k.lower() == "opcode":
                self.opcode = v
            elif k.lower() == "aa":
                self.aa = v
            elif k.lower() == "tc":
                self.tc = v
            elif k.lower() == "rd":
                self.rd = v
            elif k.lower() == "ra":
                self.ra = v
            elif k.lower() == "z":
                self.z = v
            elif k.lower() == "ad":
                self.ad = v
            elif k.lower() == "cd":
                self.cd = v
            elif k.lower() == "rcode":
                self.rcode = v

class EDNSOption(object):
    code = H('code')
    data = BYTES('data')

    def __init__(self,code,data):
        self.code = code
        self.data = data

    def pack(self,buffer):
        buffer.pack("!HH",self.code,len(self.data))
        buffer.append(self.data)

    def __repr__(self):
        return "<EDNS Option: Code=%d Data='%s'>" % (
                    self.code,binascii.hexlify(self.data).decode())

    def toZone(self):
        return "; EDNS: code: %s; data: %s" % (
                    self.code,binascii.hexlify(self.data).decode())


class RR(object):
    """
        DNS Resource Record
        Contains RR header and RD (resource data) instance
    """

    rtype = H('rtype')
    rclass = H('rclass')
    ttl = I('ttl')
    rdlength = H('rdlength')

    @classmethod
    def parse(cls, buffer):
        try:
            rname = buffer.decode_name()
            rtype, rclass, ttl, rdlength = buffer.unpack("!HHIH")
            if rdlength:
                rdata = RDMAP.get(QTYPE.get(rtype), RD).parse(
                    buffer, rdlength)
            else:
                rdata =''
                return cls(rname, rtype, rclass, ttl, rdata)
        except (BufferError, BimapError) as e:
            raise DNSError("Error unpacking RR [offset=%d]: %s" % (
            buffer.offset, e))

    @classmethod
    def fromZone(cls, zone, origin="", ttl=0):
        """
            Parse RR data from zone file and return list of RRs
        """
        return list(ZoneParser(zone, origin=origin, ttl=ttl))

    def __init__(self, rname=None, rtype=1, rclass=1, ttl=0, rdata=""):
        self.rname = rname
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata

    def set_rname(self, rname):
        if isinstance(rname, DNSLabel):
            self._rname = rname
        else:
            self._rname = DNSLabel(rname)

    def get_rname(self):
        return self._rname

    rname = property(get_rname, set_rname)

    def pack(self, buffer):
        buffer.encode_name(self.rname)
        buffer.pack("!HHI", self.rtype, self.rclass, self.ttl)
        rdlength_ptr = buffer.offset
        buffer.pack("!H", 0)
        start = buffer.offset
        self.rdata.pack(buffer)
        end = buffer.offset
        buffer.update(rdlength_ptr, "!H", end - start)

    def __repr__(self):
            return "<DNS RR: '%s' rtype=%s rclass=%s ttl=%d rdata='%s'>" % (
            self.rname, QTYPE.get(self.rtype), CLASS.get(self.rclass),
            self.ttl, self.rdata)

    def toZone(self):
            return '%-23s %-7s %-7s %-7s %s' % (self.rname, self.ttl,
                                                CLASS.get(self.rclass),
                                                QTYPE.get(self.rtype),
                                                self.rdata.toZone())


class DNSQuestion(object):
    """
        DNSQuestion section
    """

    @classmethod
    def parse(cls, buffer):
        try:
            qname = buffer.decode_name()
            qtype, qclass = buffer.unpack("!HH")
            return cls(qname, qtype, qclass)
        except (BufferError, BimapError) as e:
            raise DNSError("Error unpacking DNSQuestion [offset=%d]: %s" % (
                buffer.offset, e))

    def __init__(self, qname=None, qtype=1, qclass=1):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def set_qname(self, qname):
        if isinstance(qname, DNSLabel):
            self._qname = qname
        else:
            self._qname = DNSLabel(qname)

    def get_qname(self):
        return self._qname

    qname = property(get_qname, set_qname)

    def pack(self, buffer):
        buffer.encode_name(self.qname)
        buffer.pack("!HH", self.qtype, self.qclass)

    def toZone(self):
        return ';%-30s %-7s %s' % (self.qname, CLASS.get(self.qclass),
                                   QTYPE.get(self.qtype))

secs = {'s':1,'m':60,'h':3600,'d':86400,'w':604800}

def parse_time(s):
    """
        Parse time spec with optional s/m/h/d/w suffix
    """
    if s[-1].lower() in secs:
        return int(s[:-1]) * secs[s[-1].lower()]
    else:
        return int(s)


class ZoneParser:

    def __init__(self,zone,origin="",ttl=0):
        self.l = WordLexer(zone)
        self.l.commentchars = ';'
        self.l.nltok = ('NL',None)
        self.l.spacetok = ('SPACE',None)
        self.i = iter(self.l)
        if type(origin) is DNSLabel:
            self.origin = origin
        else:
            self.origin= DNSLabel(origin)
        self.ttl = ttl
        self.label = DNSLabel("")
        self.prev = None

    def expect(self,expect):
        t,val = next(self.i)
        if t != expect:
            raise ValueError("Invalid Token: %s (expecting: %s)" % (t,expect))
        return val

    def parse_label(self,label):
        if label.endswith("."):
            self.label = DNSLabel(label)
        elif label == "@":
            self.label = self.origin
        elif label == '':
            pass
        else:
            self.label = self.origin.add(label)
        return self.label

    def parse_rr(self,rr):
        label = self.parse_label(rr.pop(0))
        ttl = int(rr.pop(0)) if rr[0].isdigit() else self.ttl
        rclass = rr.pop(0) if rr[0] in ('IN','CH','HS') else 'IN'
        rtype = rr.pop(0)
        rdata = rr
        rd = RDMAP.get(rtype,RD)
        return RR(rname=label,
                         ttl=ttl,
                         rclass=getattr(CLASS,rclass),
                         rtype=getattr(QTYPE,rtype),
                         rdata=rd.fromZone(rdata,self.origin))

    def __iter__(self):
        return self.parse()

    def parse(self):
        rr = []
        paren = False
        try:
            while True:
                tok,val = next(self.i)
                if tok == 'NL':
                    if not paren and rr:
                        self.prev = tok
                        yield self.parse_rr(rr)
                        rr = []
                elif tok == 'SPACE' and self.prev == 'NL' and not paren:
                    rr.append('')
                elif tok == 'ATOM':
                    if val == '(':
                        paren = True
                    elif val == ')':
                        paren = False
                    elif val == '$ORIGIN':
                        self.expect('SPACE')
                        origin = self.expect('ATOM')
                        self.origin = self.label = DNSLabel(origin)
                    elif val == '$TTL':
                        self.expect('SPACE')
                        ttl = self.expect('ATOM')
                        self.ttl = parse_time(ttl)
                    else:
                        rr.append(val)
                self.prev = tok
        except StopIteration:
            if rr:
                yield self.parse_rr(rr)
