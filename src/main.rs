use std::env;

mod parser;
mod reader;

fn parse_replay_file(path: &str) {
  let mut psr = parser::Parser::new(&path);
  psr.parse();

  for elim in psr.eliminations.iter() {
    println!("[{}]: {} eliminated {}", elim.timestamp, elim.eliminator.id, elim.eliminated.id);
  }
}

fn main() {
  let start_args: Vec<String> = env::args().collect();
  let file_path = start_args.get(1);
  let file_path = match file_path {
    Some(data) => data,
    None => {
      eprintln!("Please specify a replay file path");
      return;
    }
  };

  parse_replay_file(file_path);
}
