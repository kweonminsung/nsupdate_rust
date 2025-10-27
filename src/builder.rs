use crate::internal::protocol::{
    DnsHeader, DnsUpdateMessage, DnsRecord, RData, ZoneSection,
};

pub struct UpdateMessageBuilder {
    zone: String,
    records_to_add: Vec<DnsRecord>,
    records_to_delete: Vec<DnsRecord>,
    tsig: Option<DnsRecord>, // TSIG를 DnsRecord로 보관 (Additional 마지막)
}

impl UpdateMessageBuilder {
    pub fn new(zone: impl Into<String>) -> Self {
        Self {
            zone: zone.into(),
            records_to_add: Vec::new(),
            records_to_delete: Vec::new(),
            tsig: None,
        }
    }

    pub fn add_record(mut self, name: impl Into<String>, ttl: u32, rdata: RData) -> Self {
        let name = fqdn(name);
        let rtype = match rdata {
            RData::A(_) => 1,
            RData::NS(_) => 2,
            RData::CNAME(_) => 5,
            RData::SOA { .. } => 6,
            RData::PTR(_) => 12,
            RData::MX { .. } => 15,
            RData::TXT(_) => 16,
            RData::AAAA(_) => 28,
            RData::SRV { .. } => 33,
            _ => panic!("Unsupported RData type for add_record"),
        };

        self.records_to_add.push(DnsRecord {
            name,
            rtype,
            rclass: 1, // IN
            ttl,
            rdata,
        });
        self
    }

    /// RFC 2136 삭제 규격:
    ///  - 특정 TYPE 삭제: NAME, TYPE=그 타입, CLASS=ANY(255), TTL=0, RDLENGTH=0
    ///  - 모든 타입 삭제: TYPE=ANY(255), CLASS=ANY(255), TTL=0, RDLENGTH=0
    pub fn delete_record(mut self, name: impl Into<String>, rtype: u16) -> Self {
        self.records_to_delete.push(DnsRecord {
            name: fqdn(name),
            rtype,         // 지울 타입(또는 255=ANY)
            rclass: 255,   // CLASS=ANY
            ttl: 0,        // TTL=0
            // ⚠️ encoder가 RDLENGTH=0으로 쓰도록 해야 함 (아래 2) 패치 참고)
            rdata: RData::Empty, 
        });
        self
    }

    /// TSIG를 Additional 섹션에 붙임 (선택)
    pub fn with_tsig(mut self, tsig_record: DnsRecord) -> Self {
        self.tsig = Some(tsig_record);
        self
    }

    pub fn build(self) -> DnsUpdateMessage {
        // Updates = delete 먼저, 그 다음 add (nsupdate 동작과 동일 순서)
        let mut updates = Vec::with_capacity(self.records_to_delete.len() + self.records_to_add.len());
        updates.extend(self.records_to_delete);
        updates.extend(self.records_to_add);

        let mut header = DnsHeader::default();
        header.id = rand::random();
        header.flags = 0x2800; // OPCODE = UPDATE
        header.qdcount = 1;                              // Zone=1
        header.ancount = 0;                              // Prerequisite=0 (지금은 미사용)
        header.nscount = updates.len() as u16;           // Update 개수
        header.arcount = if self.tsig.is_some() { 1 } else { 0 }; // Additional(TSIG) 개수

        let zone = ZoneSection {
            zname: fqdn(self.zone),
            zclass: 1, // IN
            ztype: 6,  // SOA
        };

        let additional = self.tsig.into_iter().collect::<Vec<_>>();

        DnsUpdateMessage {
            header,
            zone,
            prerequisites: Vec::new(),
            updates,
            additional,
        }
    }
}

/// 항상 FQDN으로 맞춰 전송 (끝의 '.' 보장)
fn fqdn<S: Into<String>>(s: S) -> String {
    let mut v = s.into();
    if !v.ends_with('.') {
        v.push('.');
    }
    v
}
