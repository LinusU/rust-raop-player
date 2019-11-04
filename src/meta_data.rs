use crate::serialization::Serializable;

use byteorder::{BE, WriteBytesExt};

use std::io::{self, Write};

pub enum MetaDataValue {
    Byte(u8),
    String(String),
    List(Vec<MetaDataItem>),
}

impl Serializable for MetaDataValue {
    fn size(&self) -> usize {
        match self {
            MetaDataValue::Byte(_) => 4 + 1,
            MetaDataValue::String(value) => 4 + value.len(),
            MetaDataValue::List(items) => 4 + items.iter().fold(0, |sum, val| sum + val.size()),
        }
    }

    fn serialize(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u32::<BE>((self.size() - 4) as u32)?;

        match self {
            MetaDataValue::Byte(value) => writer.write_u8(*value)?,
            MetaDataValue::String(value) => write!(writer, "{}", value)?,
            MetaDataValue::List(items) => for item in items.iter() { item.serialize(writer)? },
        }

        Ok(())
    }
}

pub struct MetaDataItem {
    code: [u8; 4],
    value: MetaDataValue,
}

impl MetaDataItem {
    pub fn listing_item(content: Vec<MetaDataItem>) -> MetaDataItem {
        MetaDataItem { code: *b"mlit", value: MetaDataValue::List(content) }
    }

    pub fn item_kind(id: u8) -> MetaDataItem {
        MetaDataItem { code: *b"mikd", value: MetaDataValue::Byte(id) }
    }

    pub fn item_name(name: &str) -> MetaDataItem {
        MetaDataItem { code: *b"minm", value: MetaDataValue::String(name.to_owned()) }
    }

    pub fn song_artist(artist: &str) -> MetaDataItem {
        MetaDataItem { code: *b"asar", value: MetaDataValue::String(artist.to_owned()) }
    }

    pub fn song_album(album: &str) -> MetaDataItem {
        MetaDataItem { code: *b"asal", value: MetaDataValue::String(album.to_owned()) }
    }
}

impl Serializable for MetaDataItem {
    fn size(&self) -> usize { 4 + self.value.size() }

    fn serialize(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.code)?;
        self.value.serialize(writer)
    }
}
