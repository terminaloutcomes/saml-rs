//! Internal utilities for doing things with XML

#![deny(unsafe_code)]

use std::io::Write;

use xml::writer::{EventWriter, XmlEvent};

/// Used by the XML Event writer to append events to the response
pub fn write_event<W: Write>(event: XmlEvent, writer: &mut EventWriter<W>) -> String {
    match writer.write(event) {
        Ok(val) => format!("{:?}", val),
        Err(err) => format!("{:?}", err),
    }
}
