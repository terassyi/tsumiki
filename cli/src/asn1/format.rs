use asn1::{ASN1Object, Element};
use tsumiki::decoder::Decoder;

use crate::error::Result;

/// Format ASN.1 structure in a tree-like style similar to lapo.it/asn1js
pub fn format_asn1(obj: &ASN1Object, parse_implicit: bool) -> String {
    let mut output = String::new();

    for element in obj.elements() {
        format_element(element, 0, parse_implicit, &mut output);
    }

    output
}

/// Parse OCTET STRING content as ASN.1 structure
/// Returns formatted string if successfully parsed, Err with the decode error otherwise
fn parse_implicit_octets(octets: &asn1::OctetString, depth: usize) -> Result<String> {
    let bytes = octets.as_bytes();

    let der = bytes.decode()?;
    let asn1_obj = der.decode()?;

    // Successfully parsed as ASN.1, show the structure
    let mut output = String::new();
    for elem in asn1_obj.elements() {
        format_element(elem, depth + 1, true, &mut output);
    }
    Ok(output)
}

fn format_element(element: &Element, depth: usize, parse_implicit: bool, output: &mut String) {
    let prefix = if depth == 0 {
        String::new()
    } else {
        "  ".repeat(depth)
    };

    match element {
        Element::Boolean(b) => {
            output.push_str(&format!("{}BOOLEAN {}\n", prefix, b));
        }
        Element::Integer(int) => {
            let int_str = int.to_string();
            // Show both decimal and hex for readability
            if int_str.len() > 20 {
                output.push_str(&format!("{}INTEGER (large value)\n", prefix));
            } else {
                output.push_str(&format!("{}INTEGER {}\n", prefix, int_str));
            }
        }
        Element::BitString(bits) => {
            output.push_str(&format!("{}BIT STRING ({} bits)\n", prefix, bits.bit_len()));
        }
        Element::OctetString(octets) => {
            let hex = octets.to_string();
            let byte_count = hex.split(':').count();

            // Try to parse as ASN.1 if flag is set
            if parse_implicit {
                if let Ok(parsed) = parse_implicit_octets(octets, depth) {
                    if byte_count > 32 {
                        output
                            .push_str(&format!("{}OCTET STRING ({} bytes)\n", prefix, byte_count));
                    } else {
                        output.push_str(&format!("{}OCTET STRING {}\n", prefix, hex));
                    }
                    output.push_str(&parsed);
                    return;
                }
            }

            // Show as hex string
            if byte_count > 32 {
                output.push_str(&format!("{}OCTET STRING ({} bytes)\n", prefix, byte_count));
            } else {
                output.push_str(&format!("{}OCTET STRING {}\n", prefix, hex));
            }
        }
        Element::Null => {
            output.push_str(&format!("{}NULL\n", prefix));
        }
        Element::ObjectIdentifier(oid) => {
            output.push_str(&format!("{}OBJECT IDENTIFIER {}\n", prefix, oid));
        }
        Element::UTF8String(s) => {
            output.push_str(&format!("{}UTF8String '{}'\n", prefix, s));
        }
        Element::PrintableString(s) => {
            output.push_str(&format!("{}PrintableString '{}'\n", prefix, s));
        }
        Element::IA5String(s) => {
            output.push_str(&format!("{}IA5String '{}'\n", prefix, s));
        }
        Element::UTCTime(dt) => {
            output.push_str(&format!(
                "{}UTCTime {}\n",
                prefix,
                dt.format("%Y-%m-%d %H:%M:%S")
            ));
        }
        Element::GeneralizedTime(dt) => {
            output.push_str(&format!(
                "{}GeneralizedTime {}\n",
                prefix,
                dt.format("%Y-%m-%d %H:%M:%S")
            ));
        }
        Element::Sequence(elements) => {
            output.push_str(&format!("{}SEQUENCE ({} elem)\n", prefix, elements.len()));
            for elem in elements {
                format_element(elem, depth + 1, parse_implicit, output);
            }
        }
        Element::Set(elements) => {
            output.push_str(&format!("{}SET ({} elem)\n", prefix, elements.len()));
            for elem in elements {
                format_element(elem, depth + 1, parse_implicit, output);
            }
        }
        Element::ContextSpecific { slot, element } => {
            // Check if this is implicit or explicit tagging
            // Explicit: contains a full ASN.1 element (not OctetString)
            // Implicit: contains raw data as OctetString
            if let Element::OctetString(octets) = element.as_ref() {
                // Implicit tagging
                output.push_str(&format!("{}[{}] (implicit)\n", prefix, slot));

                let hex = octets.to_string();
                let byte_count = if hex.contains(':') {
                    hex.split(':').count()
                } else {
                    hex.len() / 2
                };

                // Try to parse the OctetString content as ASN.1 if flag is set
                if parse_implicit {
                    if let Ok(parsed) = parse_implicit_octets(octets, depth) {
                        if byte_count > 32 {
                            output.push_str(&format!(
                                "{}  OCTET STRING ({} bytes)\n",
                                prefix, byte_count
                            ));
                        } else {
                            output.push_str(&format!("{}  OCTET STRING {}\n", prefix, hex));
                        }
                        output.push_str(&parsed);
                        return;
                    }
                }

                // Show as OctetString (either flag is false or parsing failed)
                if byte_count > 32 {
                    output.push_str(&format!(
                        "{}  OCTET STRING ({} bytes)\n",
                        prefix, byte_count
                    ));
                } else {
                    output.push_str(&format!("{}  OCTET STRING {}\n", prefix, hex));
                }
            } else {
                output.push_str(&format!("{}[{}] (explicit)\n", prefix, slot));
                format_element(element, depth + 1, parse_implicit, output);
            }
        }
        Element::Unimplemented(_) => {
            output.push_str(&format!("{}(unimplemented type)\n", prefix));
        }
    }
}
