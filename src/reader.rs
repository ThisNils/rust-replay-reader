#![allow(dead_code)]

use byteorder::{ByteOrder, LittleEndian};
use std::fs::{File, metadata};
use std::io::Read;
use block_modes::{BlockMode, Ecb, block_padding::ZeroPadding};
use aes_soft::Aes256;

pub struct Reader {
  pub buffer: Vec<u8>,
  pub offset: usize,
  pub encryption_key: Option<Vec<u8>>
}

impl Reader {
  pub fn new(path: &str) -> Self {
    let mut f = File::open(&path).expect("no file found");
    let metadata = metadata(&path).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    return Self {
      buffer,
      offset: 0,
      encryption_key: None
    }
  }

  pub fn skip(&mut self, byte_count: &usize) { // d7mn86cg
    self.offset += *byte_count;
  }

  pub fn goto(&mut self, byte_offset: &usize) {
    self.offset = *byte_offset;
  }

  pub fn read_u16(&mut self) -> u16 {
    let num = LittleEndian::read_u16(&self.buffer[self.offset..self.offset + 2]);
    self.skip(&2);
    return num;
  }

  pub fn read_u32(&mut self) -> u32 {
    let num = LittleEndian::read_u32(&self.buffer[self.offset..self.offset + 4]);
    self.skip(&4);
    return num;
  }

  pub fn read_u64(&mut self) -> u64 {
    let num = LittleEndian::read_u64(&self.buffer[self.offset..self.offset + 8]);
    self.skip(&8);
    return num;
  }

  pub fn read_i16(&mut self) -> i16 {
    let num = LittleEndian::read_i16(&self.buffer[self.offset..self.offset + 2]);
    self.skip(&2);
    return num;
  }

  pub fn read_i32(&mut self) -> i32 {
    let num = LittleEndian::read_i32(&self.buffer[self.offset..self.offset + 4]);
    self.skip(&4);
    return num;
  }

  pub fn read_i64(&mut self) -> i64 {
    let num = LittleEndian::read_i64(&self.buffer[self.offset..self.offset + 8]);
    self.skip(&8);
    return num;
  }

  pub fn read_f32(&mut self) -> f32 {
    let num = LittleEndian::read_f32(&self.buffer[self.offset..self.offset + 8]);
    self.skip(&4);
    return num;
  }

  pub fn read_byte(&mut self) -> u8 {
    let byte = self.buffer[self.offset..self.offset + 1][0];
    self.skip(&1);
    return byte;
  }

  pub fn read_bytes(&mut self, &byte_count: &usize) -> &[u8] {
    let bytes = &self.buffer[self.offset..self.offset + byte_count];
    self.offset += byte_count;
    return bytes;
  }

  pub fn read_bool(&mut self) -> bool {
    return self.read_i32() == 1;
  }

  pub fn read_id(&mut self) -> String {
    let bytes = self.read_bytes(&16);
    let mut id = String::from("");

    for byte in bytes.iter() {
      id.push_str(&format!("{:02X?}", byte));
    }

    return id.to_lowercase();
  }

  pub fn read_string(&mut self) -> String {
    let string_length = self.read_i32();
    if string_length == 0 {
      return String::from("");
    }
    else if string_length < 0 {
      let mut u16_vec: Vec<u16> = vec![];
      
      for _ in 0..string_length * -1 {
        u16_vec.push(self.read_u16());
      }

      u16_vec.pop();

      return String::from_utf16(&u16_vec).expect("Cannot parse u16 vector to utf16 string");
    }
    else {
      let bytes = self.read_bytes(&(string_length as usize));
      let mut byte_vec: Vec<u8> = bytes.to_vec();

      byte_vec.pop();

      return String::from_utf8(byte_vec).expect("Cannot parse u8 vector to utf8 string");
    }
  }

  pub fn read_string_vec(&mut self) -> Vec<String> {
    let array_length = self.read_u32();
    let mut vec: Vec<String> = vec![];

    for _ in 0..array_length {
      vec.push(self.read_string())
    }

    return vec;
  }

  pub fn read_string_u32_tuple_vec(&mut self) -> Vec<(String, u32)> {
    let array_length = self.read_u32();
    let mut vec: Vec<(String, u32)> = vec![];

    for _ in 0..array_length {
      vec.push((self.read_string(), self.read_u32()));
    }

    return vec;
  }

  pub fn decrypt_buffer(&mut self, data: Vec<u8>) -> Self {
    let raw_key = match &self.encryption_key {
      Some(key) => key,
      None => panic!("No encryption key found")
    };

    let mut encrypted_data: Vec<u8> = (*data).to_vec();

    let decrypt = Ecb::<Aes256, ZeroPadding>::new_var(&raw_key, Default::default()).unwrap();
    let decrypted_data = decrypt.decrypt(&mut encrypted_data).unwrap();

    return Self {
      offset: 0,
      buffer: decrypted_data.to_vec(),
      encryption_key: None
    }
  }
}
