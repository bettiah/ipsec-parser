use enum_primitive::FromPrimitive;
use nom::*;
use ikev2::*;
use ikev2_transforms::*;

named!(pub parse_ikev2_header<IkeV2Header>,
    do_parse!(
           init_spi: take!(8)
        >> resp_spi: take!(8)
        >> np: be_u8
        >> vers: bits!(
             tuple!(take_bits!(u8,4),take_bits!(u8,4))
           )
        >> ex: be_u8
        >> flags: be_u8
        >> id: be_u32
        >> l: be_u32
        >> (
            IkeV2Header{
                init_spi: init_spi,
                resp_spi: resp_spi,
                next_payload: np,
                maj_ver: vers.0,
                min_ver: vers.1,
                exch_type: ex,
                flags: flags,
                msg_id: id,
                length: l,
            }
        )
    )
);

named!(pub parse_ikev2_payload_generic<IkeV2GenericPayload>,
    do_parse!(
           np_type: be_u8
        >> b: bits!(
            tuple!(take_bits!(u8,1),take_bits!(u8,7))
            )
        >> len: be_u16
        >> error_if!(len < 4, Err::Code(ErrorKind::Custom(128)))
        >> data: take!(len-4)
        >> (
            IkeV2GenericPayload{
                hdr: IkeV2PayloadHeader {
                    next_payload_type: np_type,
                    critical: b.0 == 1,
                    reserved: b.1,
                    payload_length: len,
                },
                payload: data,
            }
        )
    )
);

named!(pub parse_ikev2_transform<IkeV2RawTransform>,
    do_parse!(
           last: be_u8
        >> reserved1: be_u8
        >> transform_length: be_u16
        >> transform_type: be_u8
        >> reserved2: be_u8
        >> transform_id: be_u16
        >> attributes: cond!(transform_length > 8,take!(transform_length-8))
        >> (
            IkeV2RawTransform{
                last: last,
                reserved1:reserved1,
                transform_length: transform_length,
                transform_type: transform_type,
                reserved2: reserved2,
                transform_id: transform_id,
                attributes: attributes,
            }
        )
    )
);

named!(pub parse_ikev2_proposal<IkeV2Proposal>,
    do_parse!(
           last: be_u8
        >> reserved: be_u8
        >> p_len: be_u16
        >> p_num: be_u8
        >> proto_id: be_u8
        >> spi_size: be_u8
        >> num_transforms: be_u8
        >> spi: cond!(spi_size > 0,take!(spi_size))
        >> error_if!(p_len < (8u16+spi_size as u16), Err::Code(ErrorKind::Custom(128)))
        >> transforms: flat_map!(
            take!( p_len - (8u16+spi_size as u16) ),
            many_m_n!(num_transforms as usize,num_transforms as usize,parse_ikev2_transform)
            )
        >> ( IkeV2Proposal{
            last:last,
            reserved:reserved,
            proposal_length: p_len,
            proposal_num: p_num,
            protocol_id: proto_id,
            spi_size: spi_size,
            num_transforms: num_transforms,
            spi: spi,
            transforms: transforms,
        })
    )
);

pub fn parse_ikev2_payload_sa<'a>(
    i: &'a [u8],
    _length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    map!(i, many1!(parse_ikev2_proposal), |v| {
        IkeV2PayloadContent::SA(v)
    })
}

pub fn parse_ikev2_payload_kex<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse!(i,
           dh:       be_u16
        >> reserved: be_u16
        >> error_if!(length < 4, Err::Code(ErrorKind::Custom(128)))
        >> data:     take!(length-4)
        >> (
            IkeV2PayloadContent::KE(
                KeyExchangePayload{
                    dh_group: dh,
                    reserved: reserved,
                    kex_data: data,
                }
            )
        )
    )
}

pub fn parse_ikev2_payload_ident_init<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse!(i,
           id_type:   be_u8
        >> reserved1: be_u8
        >> reserved2: be_u16
        >> error_if!(length < 4, Err::Code(ErrorKind::Custom(128)))
        >> data:      take!(length-4)
        >> (
            IkeV2PayloadContent::IDi(
                IdentificationPayload{
                    id_type: id_type,
                    reserved1: reserved1,
                    reserved2: reserved2,
                    ident_data: data,
                }
            )
        ))
}

pub fn parse_ikev2_payload_ident_resp<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse!(i,
           id_type:   be_u8
        >> reserved1: be_u8
        >> reserved2: be_u16
        >> error_if!(length < 4, Err::Code(ErrorKind::Custom(128)))
        >> data:      take!(length-4)
        >> (
            IkeV2PayloadContent::IDr(
                IdentificationPayload{
                    id_type: id_type,
                    reserved1: reserved1,
                    reserved2: reserved2,
                    ident_data: data,
                }
            )
        ))
}

pub fn parse_ikev2_payload_certificate<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse!(i,
           encoding: be_u8
        >> error_if!(length < 1, Err::Code(ErrorKind::Custom(128)))
        >> data: take!(length-1)
        >> (
            IkeV2PayloadContent::Certificate(
                CertificatePayload{
                    cert_encoding: encoding,
                    cert_data: data,
                }
            )
        ))
}

pub fn parse_ikev2_payload_certificate_request<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse!(i,
           encoding: be_u8
        >> error_if!(length < 1, Err::Code(ErrorKind::Custom(128)))
        >> data: take!(length-1)
        >> (
            IkeV2PayloadContent::CertificateRequest(
                CertificateRequestPayload{
                    cert_encoding: encoding,
                    ca_data: data,
                }
            )
        ))
}

pub fn parse_ikev2_payload_authentication<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse!(i,
           method: be_u8 >>
                   error_if!(length < 4, Err::Code(ErrorKind::Custom(128))) >>
                   data: take!(length-4) >>
        (
            IkeV2PayloadContent::Authentication(
                AuthenticationPayload{
                    auth_method: method,
                    auth_data:   data,
                }
            )
        ))
}

pub fn parse_ikev2_payload_nonce<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse!(i,
        data: take!(length)
        >> (
            IkeV2PayloadContent::Nonce(
                NoncePayload{
                    nonce_data: data,
                }
            )
        ))
}

pub fn parse_ikev2_payload_notify<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse!(i,
        proto_id:   be_u8 >>
        spi_sz:     be_u8 >>
        notif_type: be_u16 >>
        spi:        cond!(spi_sz > 0, take!(spi_sz)) >>
        notif_data: cond!(length > 8 + spi_sz as u16, take!(length-(8+spi_sz as u16))) >>
        (
            IkeV2PayloadContent::Notify(
                NotifyPayload{
                    protocol_id: proto_id,
                    spi_size:    spi_sz,
                    notify_type: notif_type,
                    spi:         spi,
                    notify_data: notif_data,
                }
            )
        ))
}

pub fn parse_ikev2_payload_vendor_id<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse!(i,
                   error_if!(length < 4, Err::Code(ErrorKind::Custom(128))) >>
        vendor_id: take!(length-8) >>
        (
            IkeV2PayloadContent::VendorID(
                VendorIDPayload{
                    vendor_id: vendor_id,
                }
            )
        ))
}

pub fn parse_ikev2_payload_delete<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse!(i,
        proto_id:   be_u8 >>
        spi_sz:     be_u8 >>
        num_spi:    be_u16 >>
                    error_if!(length < 8, Err::Code(ErrorKind::Custom(128))) >>
        spi:        take!(length-8) >>
        (
            IkeV2PayloadContent::Delete(
                DeletePayload{
                    protocol_id: proto_id,
                    spi_size:    spi_sz,
                    num_spi:     num_spi,
                    spi:         spi,
                }
            )
        ))
}

fn parse_ts_addr<'a>(i: &'a [u8], t: u8) -> IResult<&'a [u8], &'a [u8]> {
    match t {
        7 => take!(i, 4),
        8 => take!(i, 16),
        _ => IResult::Error(error_code!(ErrorKind::Switch)),
    }
}

fn parse_ikev2_ts<'a>(i: &'a [u8]) -> IResult<&'a [u8], TrafficSelector<'a>> {
    do_parse!(i,
           ts_type: be_u8
        >> ip_proto_id: be_u8
        >> sel_length: be_u16
        >> start_port: be_u16
        >> end_port: be_u16
        >> start_addr: apply!(parse_ts_addr,ts_type)
        >> end_addr: apply!(parse_ts_addr,ts_type)
        >> (
            TrafficSelector{
                ts_type: ts_type,
                ip_proto_id: ip_proto_id,
                sel_length: sel_length,
                start_port: start_port,
                end_port: end_port,
                start_addr: start_addr,
                end_addr: end_addr,
            }
        ))
}

pub fn parse_ikev2_payload_ts<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], TrafficSelectorPayload<'a>> {
    do_parse!(i,
           num_ts: be_u8
        >> reserved: take!(3)
        >> error_if!(length < 4, Err::Code(ErrorKind::Custom(128)))
        >> ts: flat_map!(take!(length-4),
            many1!(parse_ikev2_ts)
        )
        >> (
            TrafficSelectorPayload{
                num_ts: num_ts,
                reserved: reserved,
                ts: ts,
            }
        ))
}

pub fn parse_ikev2_payload_ts_init<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    map!(i, call!(parse_ikev2_payload_ts, length), |x| {
        IkeV2PayloadContent::TSi(x)
    })
}

pub fn parse_ikev2_payload_ts_resp<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    map!(i, call!(parse_ikev2_payload_ts, length), |x| {
        IkeV2PayloadContent::TSr(x)
    })
}

pub fn parse_ikev2_payload_unknown<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    map!(i, take!(length), |d| { IkeV2PayloadContent::Unknown(d) })
}

pub fn parse_ikev2_payload_with_type(
    i: &[u8],
    length: u16,
    next_payload_type: u8,
) -> IResult<&[u8], IkeV2PayloadContent> {
    let f = match IkePayloadType::from_u8(next_payload_type) {
        // Some(IkePayloadType::NoNextPayload)       => parse_ikev2_payload_unknown, // XXX ?
        Some(IkePayloadType::SecurityAssociation) => parse_ikev2_payload_sa,
        Some(IkePayloadType::KeyExchange) => parse_ikev2_payload_kex,
        Some(IkePayloadType::IdentInitiator) => parse_ikev2_payload_ident_init,
        Some(IkePayloadType::IdentResponder) => parse_ikev2_payload_ident_resp,
        Some(IkePayloadType::Certificate) => parse_ikev2_payload_certificate,
        Some(IkePayloadType::CertificateRequest) => parse_ikev2_payload_certificate_request,
        Some(IkePayloadType::Authentication) => parse_ikev2_payload_authentication,
        Some(IkePayloadType::Nonce) => parse_ikev2_payload_nonce,
        Some(IkePayloadType::Notify) => parse_ikev2_payload_notify,
        Some(IkePayloadType::Delete) => parse_ikev2_payload_delete,
        Some(IkePayloadType::VendorID) => parse_ikev2_payload_vendor_id,
        Some(IkePayloadType::TrafficSelectorInitiator) => parse_ikev2_payload_ts_init,
        Some(IkePayloadType::TrafficSelectorResponder) => parse_ikev2_payload_ts_resp,
        // None                                               => parse_ikev2_payload_unknown,
        _ => parse_ikev2_payload_unknown,
        // _ => panic!("unknown type {}",next_payload_type),
    };
    flat_map!(i, take!(length), call!(f, length))
}

fn parse_ikev2_payload_list_fold<'a>(
    res_v: Result<Vec<IkeV2Payload<'a>>, &'static str>,
    p: IkeV2GenericPayload<'a>,
) -> Result<Vec<IkeV2Payload<'a>>, &'static str> {
    let mut v = res_v?;
    // println!("parse_payload_list_fold: v.len={} p={:?}",v.len(),p);
    let next_payload_type = match v.last() {
        Some(el) => el.hdr.next_payload_type,
        None => {
            return Err("next payload type");
        }
    };
    match parse_ikev2_payload_with_type(p.payload, p.hdr.payload_length - 4, next_payload_type) {
        IResult::Done(rem, p2) => {
            // println!("rem: {:?}",rem);
            // println!("p2: {:?}",p2);
            if rem.len() != 0 {
                return Err("parse_ikev2_payload_list_fold: rem is not null");
            }
            let payload = IkeV2Payload {
                hdr: p.hdr.clone(),
                content: p2,
            };
            v.push(payload);
            Ok(v)
        }
        _ => {
            // println!("parsing failed: type={} {:?}", next_payload_type, p.payload);
            Err("parse_payload_list_fold: parsing failed")
        }
    }
}

pub fn parse_ikev2_payload_list<'a>(
    i: &'a [u8],
    initial_type: u8,
) -> IResult<&'a [u8], Result<Vec<IkeV2Payload<'a>>, &'static str>> {
    fold_many1!(
        i,
        parse_ikev2_payload_generic,
        Ok(vec![
            IkeV2Payload {
                hdr: IkeV2PayloadHeader {
                    next_payload_type: initial_type,
                    critical: false,
                    reserved: 0,
                    payload_length: 0,
                },
                content: IkeV2PayloadContent::Dummy,
            },
        ]),
        parse_ikev2_payload_list_fold
    )
    // XXX should we split_first() the vector and return all but the first element ?
}

#[cfg(test)]
mod tests {
    use ikev2_parser::*;
    use nom::IResult;

    static IKEV2_INIT_REQ: &'static [u8] = include_bytes!("../assets/ike-sa-init-req.bin");

    #[test]
    fn test_ikev2_init_req() {
        let empty = &b""[..];
        let bytes = &IKEV2_INIT_REQ[0..28];
        let expected = IResult::Done(
            empty,
            IkeV2Header {
                init_spi: &bytes[0..8],
                resp_spi: &bytes[8..16],
                next_payload: 33,
                maj_ver: 2,
                min_ver: 0,
                exch_type: 34,
                flags: 0x8,
                msg_id: 0,
                length: 328,
            },
        );
        let res = parse_ikev2_header(&bytes);
        assert_eq!(res, expected);
    }

    static IKEV2_INIT_RESP: &'static [u8] = include_bytes!("../assets/ike-sa-init-resp.bin");

    #[test]
    fn test_ikev2_init_resp() {
        let bytes = IKEV2_INIT_RESP;
        let res = parse_ikev2_header(&bytes);
        match res {
            IResult::Done(rem, ref hdr) => {
                match parse_ikev2_payload_list(rem, hdr.next_payload) {
                    IResult::Done(rem2, Ok(ref p)) => {
                        assert_eq!(rem2, &b""[..]);
                        // there are 5 items + dummy => 6
                        assert_eq!(p.len(), 6);
                        // first one is always dummy
                        assert_eq!(p[0].content, IkeV2PayloadContent::Dummy);
                    }
                    e @ _ => {
                        eprintln!("Parsing payload failed: {:?}", e);
                        assert!(false);
                    }
                }
            }
            _ => {
                eprintln!("Parsing header failed");
                assert!(false);
            }
        }
    }

    static IKEV2_PAYLOAD_SA: &'static [u8] = include_bytes!("../assets/ike-payload-sa.bin");

    #[test]
    fn test_ikev2_payload_sa() {
        let empty = &b""[..];
        let bytes = IKEV2_PAYLOAD_SA;
        let expected1 = IResult::Done(
            empty,
            IkeV2GenericPayload {
                hdr: IkeV2PayloadHeader {
                    next_payload_type: IkePayloadType::KeyExchange as u8,
                    critical: false,
                    reserved: 0,
                    payload_length: 40,
                },
                payload: &bytes[4..],
            },
        );
        let res = parse_ikev2_payload_generic(&bytes);
        assert_eq!(res, expected1);
        let attrs1 = &[0x80, 0x0e, 0x00, 0x80];
        let expected2 = IResult::Done(
            empty,
            IkeV2PayloadContent::SA(vec![
                IkeV2Proposal {
                    last: 0,
                    reserved: 0,
                    proposal_length: 36,
                    proposal_num: 1,
                    protocol_id: 1,
                    spi_size: 0,
                    num_transforms: 3,
                    spi: None,
                    transforms: vec![
                        IkeV2RawTransform {
                            last: 3,
                            reserved1: 0,
                            transform_length: 12,
                            transform_type: 1,
                            reserved2: 0,
                            transform_id: 20,
                            attributes: Some(attrs1),
                        },
                        IkeV2RawTransform {
                            last: 3,
                            reserved1: 0,
                            transform_length: 8,
                            transform_type: 2,
                            reserved2: 0,
                            transform_id: 5,
                            attributes: None,
                        },
                        IkeV2RawTransform {
                            last: 0,
                            reserved1: 0,
                            transform_length: 8,
                            transform_type: 4,
                            reserved2: 0,
                            transform_id: 30,
                            attributes: None,
                        },
                    ],
                },
            ]),
        );
        match res {
            IResult::Done(_, ref hdr) => {
                let res2 = parse_ikev2_payload_sa(hdr.payload, 0);
                assert_eq!(res2, expected2);
                println!("{:?}", res2);
            }
            _ => assert!(false),
        };
    }

    #[test]
    fn test_ikev2_parse_payload_many() {
        // let empty = &b""[..];
        let bytes = &IKEV2_INIT_REQ[28..];
        let res = parse_ikev2_payload_list(&bytes, 33);
        println!("{:?}", res);
    }

}
