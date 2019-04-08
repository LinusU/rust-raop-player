use std::io::{self, Read, Write};

pub trait Serializable {
    fn size(&self) -> usize;
    fn serialize(&self, writer: &mut Write) -> io::Result<()>;

    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::with_capacity(self.size());
        self.serialize(&mut bytes).unwrap();
        bytes
    }
}

pub trait Deserializable: Sized {
    const SIZE: usize;
    fn deserialize(reader: &mut Read) -> io::Result<Self>;
}
