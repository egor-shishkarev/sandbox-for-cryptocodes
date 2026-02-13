use crossbeam_channel::Sender;
use std::{io, thread};

pub enum UiMsg {
    Line(String),
}

pub fn spawn_input_thread(tx: Sender<UiMsg>) {
    thread::spawn(move || {
        let stdin = io::stdin();
        loop {
            let mut line = String::new();
            if stdin.read_line(&mut line).is_ok() {
                let _ = tx.send(UiMsg::Line(line));
            }
        }
    });
}