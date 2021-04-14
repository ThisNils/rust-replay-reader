use crate::reader::Reader;
use regex::Regex;

pub struct Parser {
  pub reader: Reader,
  pub meta: Option<Meta>,
  pub header: Option<Header>,
  pub match_stats: Option<MatchStats>,
  pub team_match_stats: Option<TeamMatchStats>,
  pub eliminations: Vec<Elimination>
}

pub struct Meta {
  pub magic: u32,
  pub file_version: u32,
  pub length_in_ms: u32,
  pub network_version: u32,
  pub changelist: u32,
  pub name: String,
  pub is_live: bool,
  pub timestamp: Option<u32>,
  pub is_compressed: bool,
  pub is_encrypted: bool
}

pub struct GameVersion {
  pub branch: String,
  pub patch: u16,
  pub changelist: u32,
  pub major: u32,
  pub minor: u32
}

pub struct Header {
  pub magic: u32,
  pub network_version: u32,
  pub network_checksum: u32,
  pub engine_network_version: u32,
  pub game_network_protocol: u32,
  pub id: Option<String>,
  pub version: GameVersion,
  pub level_names_and_times: Vec<(String, u32)>,
  pub flags: u32,
  pub game_specific_data: Vec<String>
}

pub struct Player {
  pub id: String,
  pub name: String,
  pub is_bot: bool
}

pub struct Elimination {
  pub eliminated: Player,
  pub eliminator: Player,
  pub gun_type: String,
  pub is_knocked: bool,
  pub timestamp: u32
}

pub struct TeamMatchStats {
  pub placement: u32,
  pub total_players: u32
}

pub struct MatchStats {
  pub accuracy: f32,
  pub assists: u32,
  pub eliminations: u32,
  pub weapon_damage: u32,
  pub other_damage: u32,
  pub revives: u32,
  pub damage_taken: u32,
  pub damage_to_structures: u32,
  pub materials_gathered: u32,
  pub materials_used: u32,
  pub total_traveled: u32
}

impl Parser {
  pub fn new(path: &str) -> Self {
    let reader = Reader::new(path);

    return Self {
      reader: reader,
      meta: None,
      header: None,
      match_stats: None,
      team_match_stats: None,
      eliminations: vec![]
    }
  }

  pub fn parse(&mut self) {
    self.parse_meta();
    self.parse_chunks();
  }

  pub fn parse_meta(&mut self) {
    let magic = self.reader.read_u32();
    let file_version = self.reader.read_u32();
    let length_in_ms = self.reader.read_u32();
    let network_version = self.reader.read_u32();
    let changelist = self.reader.read_u32();
    let name = String::from(self.reader.read_string().trim_end());
    let is_live = self.reader.read_bool();
    
    let mut timestamp = None;
    if file_version >= 3 {
      timestamp = Some(((self.reader.read_u64() - 621355968000000000) / 100000) as u32);
    }

    let mut is_compressed = false;
    if file_version >= 2 {
      is_compressed = self.reader.read_bool();
    }

    let mut is_encrypted = false;
    if file_version >= 6 {
      is_encrypted = self.reader.read_bool();
      if is_encrypted {
        let key_length = self.reader.read_u32();
        self.reader.encryption_key = Some(self.reader.read_bytes(&(key_length as usize)).to_vec());
      }
    }
    
    self.meta = Some(Meta {
      magic,
      file_version,
      length_in_ms,
      network_version,
      changelist,
      name,
      is_live,
      timestamp,
      is_compressed,
      is_encrypted
    });
  }

  pub fn parse_chunks(&mut self) {
    while self.header.is_none() && self.reader.buffer.len() > self.reader.offset {
      let chunk_type = self.reader.read_u32();
      let chunk_size = self.reader.read_i32();
      let start_offset = self.reader.offset;

      if chunk_type == 0 {
        self.header = Some(self.parse_header());
        self.reader.offset = start_offset + chunk_size as usize;
      }
    }

    if self.header.is_none() {
      panic!("Header not found in replay chunks");
    }

    while self.reader.buffer.len() > self.reader.offset {
      let chunk_type = self.reader.read_u32();
      let chunk_size = self.reader.read_i32();
      let start_offset = self.reader.offset;

      match chunk_type {
        0 => { /* Header, parsed above */ },
        1 => { /* Replay Data */ },
        2 => { /* Checkpoint */ },
        3 => {
          self.parse_event();
        }
        _ => {}
      }

      self.reader.offset = start_offset + chunk_size as usize;
    }
  }

  pub fn parse_header(&mut self) -> Header {
    let magic = self.reader.read_u32();
    let network_version = self.reader.read_u32();
    let network_checksum = self.reader.read_u32();
    let engine_network_version = self.reader.read_u32();
    let game_network_protocol = self.reader.read_u32();

    let mut id: Option<String> = None;
    if network_version > 12 {
      id = Some(self.reader.read_id());
    }

    self.reader.skip(&4);
    let patch = self.reader.read_u16();
    let changelist = self.reader.read_u32();
    let branch = self.reader.read_string();
    let level_names_and_times = self.reader.read_string_u32_tuple_vec();
    let flags = self.reader.read_u32();
    let game_specific_data = self.reader.read_string_vec();

    let re = Regex::new(r"\+\+Fortnite\+Release\-(?P<major>\d+)\.(?P<minor>\d*)").unwrap();

    let version_data = re.captures(&branch).unwrap();

    return Header {
      magic,
      network_version,
      network_checksum,
      engine_network_version,
      game_network_protocol,
      id,
      version: GameVersion {
        branch: (*branch).to_string(),
        patch,
        changelist,
        major: version_data["major"].parse().unwrap(),
        minor: version_data["minor"].parse().unwrap()
      },
      level_names_and_times,
      flags,
      game_specific_data,
    }
  }

  pub fn parse_event(&mut self) {
    self.reader.read_string();
    let group = self.reader.read_string();
    let metadata = self.reader.read_string();
    let start_time = self.reader.read_u32();
    self.reader.skip(&4);
    let length = self.reader.read_u32();

    let encrypted_buffer = self.reader.read_bytes(&(length as usize)).to_vec();
    let mut buffer_reader = self.reader.decrypt_buffer(encrypted_buffer);

    if group == "playerElim" {
      self.parse_elimination(&mut buffer_reader, start_time);
    }
    else if metadata == "AthenaMatchStats" {
      self.match_stats = Some(self.parse_match_stats(&mut buffer_reader));
    }
    else if metadata == "AthenaMatchTeamStats" {
      self.team_match_stats = Some(self.parse_team_match_stats(&mut buffer_reader));
    }
    else if metadata == "PlayerStateEncryptionKey" {
      // ignore
    }
  }

  pub fn parse_elimination(&mut self, data: &mut Reader, timestamp: u32) {
    let header = &self.header.as_ref().unwrap();

    #[allow(unused_assignments)]
    let mut eliminated = None;
    #[allow(unused_assignments)]
    let mut eliminator = None;

    if header.engine_network_version >= 11 && header.version.major >= 9 {
      data.skip(&85);
      eliminated = Some(self.parse_player(data));
      eliminator = Some(self.parse_player(data));
    }
    else {
      if header.version.major <= 4 && header.version.minor < 2 {
        data.skip(&12);
      }
      else if header.version.major == 4 && header.version.minor <= 2 {
        data.skip(&40);
      }
      else {
        data.skip(&45);
      }

      eliminated = Some(Player {
        name: String::from(""),
        id: data.read_string(),
        is_bot: false
      });
      eliminator = Some(Player {
        name: String::from(""),
        id: data.read_string(),
        is_bot: false
      });
    }

    let gun_type = data.read_byte();
    let knocked = data.read_bool();

    self.eliminations.push(Elimination {
      eliminated: eliminated.unwrap(),
      eliminator: eliminator.unwrap(),
      gun_type: format!("{:02X?}", gun_type),
      is_knocked: knocked,
      timestamp: timestamp
    });
  }

  pub fn parse_player(&mut self, data: &mut Reader) -> Player {
    let player_type = data.read_byte();
    
    return match player_type {
      3 => Player {
        name: String::from("Bot"),
        id: String::from(""),
        is_bot: true
      },
      16 => Player {
        name: data.read_string(),
        id: String::from(""),
        is_bot: true
      },
      _ => {
        data.skip(&1);
        Player {
          name: String::from(""),
          id: data.read_id(),
          is_bot: false
        }
      }
    }
  }

  pub fn parse_team_match_stats(&mut self, data: &mut Reader) -> TeamMatchStats {
    data.skip(&4);
    let placement = data.read_u32();
    let total_players = data.read_u32();

    return TeamMatchStats {
      placement,
      total_players
    }
  }

  pub fn parse_match_stats(&mut self, data: &mut Reader) -> MatchStats {
    data.skip(&4);
    let accuracy = data.read_f32();
    let assists = data.read_u32();
    let eliminations = data.read_u32();
    let weapon_damage = data.read_u32();
    let other_damage = data.read_u32();
    let revives = data.read_u32();
    let damage_taken = data.read_u32();
    let damage_to_structures = data.read_u32();
    let materials_gathered = data.read_u32();
    let materials_used = data.read_u32();
    let total_traveled = data.read_u32();

    return MatchStats {
      accuracy,
      assists,
      eliminations,
      weapon_damage,
      other_damage,
      revives,
      damage_taken,
      damage_to_structures,
      materials_gathered,
      materials_used,
      total_traveled
    }
  }
}
