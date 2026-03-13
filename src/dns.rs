use crate::dns_mapping::DnsRecord;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME},
    },
};
use std::{net::IpAddr, str::FromStr};

pub fn build_dns_query(domain: &str, id: u16) -> Result<Vec<u8>, String> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let name = Name::from_str(domain).map_err(|e| e.to_string())?;
    msg.add_query(Query::query(name, RecordType::A));
    msg.to_vec().map_err(|e| e.to_string())
}

pub fn build_dns_response(mut request: Message, domain: &str, ip: IpAddr, ttl: u32) -> Result<Message, String> {
    let record = match ip {
        IpAddr::V4(ip) => Record::from_rdata(Name::from_str(domain)?, ttl, RData::A(A(ip))),
        IpAddr::V6(ip) => Record::from_rdata(Name::from_str(domain)?, ttl, RData::AAAA(AAAA(ip))),
    };

    // We must indicate that this message is a response. Otherwise, implementations may not
    // recognize it.
    request.set_message_type(MessageType::Response);

    request.add_answer(record);
    Ok(request)
}

pub fn build_dns_response_from_cache(mut request: Message, domain: &str, records: &[DnsRecord]) -> Result<Message, String> {
    let domain_name = Name::from_str(domain).map_err(|e| e.to_string())?;
    request.set_message_type(MessageType::Response);

    // Track the last CNAME target so A/AAAA records use the correct owner name
    let mut last_cname_target: Option<Name> = None;

    for record in records {
        match record {
            DnsRecord::Cname(from, to, ttl) => {
                let from_name = Name::from_str(from).map_err(|e| e.to_string())?;
                let to_name = Name::from_str(to).map_err(|e| e.to_string())?;
                let rr = Record::from_rdata(from_name, *ttl, RData::CNAME(CNAME(to_name.clone())));
                request.add_answer(rr);
                last_cname_target = Some(to_name);
            }
            DnsRecord::A(addr, ttl) => {
                let owner = last_cname_target.as_ref().unwrap_or(&domain_name).clone();
                let rr = Record::from_rdata(owner, *ttl, RData::A(A(*addr)));
                request.add_answer(rr);
            }
            DnsRecord::AAAA(addr, ttl) => {
                let owner = last_cname_target.as_ref().unwrap_or(&domain_name).clone();
                let rr = Record::from_rdata(owner, *ttl, RData::AAAA(AAAA(*addr)));
                request.add_answer(rr);
            }
        }
    }
    Ok(request)
}

pub fn remove_ipv6_entries(message: &mut Message) {
    message.answers_mut().retain(|answer| !matches!(answer.data(), RData::AAAA(_)));
}

pub fn extract_ipaddr_from_dns_message(message: &Message) -> Result<IpAddr, String> {
    if message.response_code() != ResponseCode::NoError {
        return Err(format!("{:?}", message.response_code()));
    }
    let mut cname = None;
    for answer in message.answers() {
        match answer.data() {
            RData::A(addr) => {
                return Ok(IpAddr::V4((*addr).into()));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6((*addr).into()));
            }
            RData::CNAME(name) => {
                cname = Some(name.to_utf8());
            }
            _ => {}
        }
    }
    if let Some(cname) = cname {
        return Err(cname);
    }
    Err(format!("{:?}", message.answers()))
}

/// Extract all supported DNS records (A, AAAA, CNAME) from a response message.
pub fn extract_dns_records_from_message(message: &Message) -> Vec<DnsRecord> {
    message
        .answers()
        .iter()
        .filter_map(|answer| match answer.data() {
            RData::A(addr) => Some(DnsRecord::A((*addr).into(), answer.ttl())),
            RData::AAAA(addr) => Some(DnsRecord::AAAA((*addr).into(), answer.ttl())),
            RData::CNAME(target) => {
                let from = answer.name().to_utf8();
                let to = target.to_utf8();
                Some(DnsRecord::Cname(from, to, answer.ttl()))
            }
            _ => None,
        })
        .collect()
}

pub fn extract_domain_from_dns_message(message: &Message) -> Result<String, String> {
    let query = message.queries().first().ok_or("DnsRequest no query body")?;
    let name = query.name().to_string();
    Ok(name)
}

pub fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> Result<Message, String> {
    if used_by_tcp {
        if data.len() < 2 {
            return Err("invalid dns data".into());
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or("invalid dns data")?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| e.to_string())?;
    Ok(message)
}

#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;
