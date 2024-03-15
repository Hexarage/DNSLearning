use std::{fs::File, io::Read, net::Ipv4Addr};


// aliases for ease of coding
type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;


pub struct BytePacketBuffer {
    pub buffer: [u8; 512],
    pub position: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer{
            buffer: [0;512],
            position: 0,
        }
    }

    fn pos(&self) -> usize {
        self.position
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.position += steps;

        Ok(())
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.position = pos;
        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.position >= 512 {
            return Err("End of buffer".into());
        }
        let result = self.buffer[self.position];
        self.position+=1;

        Ok(result)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        Ok(self.buffer[pos])
    }

    fn get_range(&mut self, start: usize, length: usize) -> Result<&[u8]> {
        if start + length >= 512 {
            return Err("End of buffer exceeded".into());
        }
        Ok(&self.buffer[start .. start+length as usize])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let result = ((self.read()? as u16)<< 8) | (self.read()? as u16);

        Ok(result)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let result = ((self.read()? as u32) << 24) 
        | ((self.read()? as u32) << 16)
        | ((self.read()? as u32) << 8)
        | (self.read()? as u32);

        Ok(result)
    }
    
    fn read_q_name(&mut self, outstring: &mut String) -> Result<()> {
        // tracking position in case there are jumps
        let mut pos = self.pos();
        
        // tracking whether there's been jumps and how many
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delimiter = "";
        loop {
            // in case there is a malicious loop in the packet
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps was exceeded",max_jumps).into());
            }

            // labels always begin with a length byte by spec
            let len = self.get(pos)?;

            // check if the next byte needs to be read as well
            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos+2)?;
                }

                // read another byte
                let len_second = self.get(pos+1)? as u16;
                let offset = (((len as u16)^0xC0) << 8) | len_second;
                pos = offset as usize;

                // note that there was a jump performed
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // base scenario where there is a single label read and then appended to the output
            else {
                pos += 1; // move a single byte forward past the length byte

                // domain names are terminated by an empty label with length 0
                // if length is 0 then we are done
                if len == 0 {
                    break;
                }

                outstring.push_str(delimiter);

                // Get the actual ASCII bytes for the label
                let string_buffer = self.get_range(pos,len as usize)?;
                outstring.push_str(&String::from_utf8_lossy(string_buffer).to_lowercase());

                delimiter = ".";

                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num:u8) -> ResultCode {
        match num {
            1 =>ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool, // 1 bit
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8, // 4 bits actually
    pub response: bool,

    pub result_code: ResultCode, // 4 bits actually
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool, 

    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader{
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            result_code: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.result_code = ResultCode::from_num(b&0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A, // 1
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String, 
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_q_name(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16, 
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        address: Ipv4Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();

        let qtype_number = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_number);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_length = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_address = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_address >> 24) & 0xFF) as u8,
                    ((raw_address >> 16) & 0xFF) as u8,
                    ((raw_address >> 8) & 0xFF) as u8,
                    (raw_address & 0xFF) as u8,
                );

                Ok(DnsRecord::A {
                    domain: domain,
                    address: addr,
                    ttl: ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_length as usize)?;

                Ok(DnsRecord::UNKNOWN { 
                    domain: domain,
                    qtype: qtype_number,
                    data_len: data_length,
                    ttl: ttl
                })
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();

        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let answer = DnsRecord::read(buffer)?;
            result.answers.push(answer);
        }

        for _ in 0..result.header.authoritative_entries {
            let authorities = DnsRecord::read(buffer)?;
            result.authorities.push(authorities);
        }

        for _ in 0..result.header.resource_entries {
            let entries = DnsRecord::read(buffer)?;
            result.resources.push(entries);
        }

        Ok(result)
    }
}

fn main() -> Result<()>{
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buffer)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);
    
    for questions in packet.questions {
        println!("{:#?}", questions);
    }
    for answers in packet.answers {
        println!("{:#?}", answers);
    }
    for auths in packet.authorities {
        println!("{:#?}", auths);
    }
    for resources in packet.resources {
        println!("{:#?}", resources);
    }

    Ok(())
}
