use std::time::Duration;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::fmt;

#[derive(Debug)]
#[derive(Clone, Serialize, Deserialize)]
pub struct AttackReport {
    // TODO Мне кажется было бы хорошо сюда добавить название атакованного алгоритма, потому что по истории не понятно будет
    pub attack_name: String,
    pub duration: Duration,
    pub iterations: u64,
    pub result: AttackResult,
    pub seed: u64,

    pub public_parameters: Value,
}

#[derive(Debug)]
#[derive(Clone, Serialize, Deserialize)]
pub enum AttackResult {
    Success { message: String},
    Failed { reason: String },
    Cancelled,
}

impl fmt::Display for AttackReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "================ Отчет об атаке ================")?;
        writeln!(f, "Название:      {}", self.attack_name)?;
        writeln!(f, "Seed:          {}", self.seed)?;
        writeln!(f, "Итераций:      {}", self.iterations)?;
        writeln!(f, "Длительность:  {:?}", self.duration)?;
        writeln!(f, "Результат:     {}", self.result)?;
        write!(f,   "================================================")
    }
}

impl fmt::Display for AttackResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttackResult::Success { message } => {
                write!(f, "Success\nMessage:       {}", message)
            }
            AttackResult::Failed { reason } => {
                write!(f, "Failed\nReason:        {}", reason)
            }
            AttackResult::Cancelled => {
                write!(f, "Cancelled")
            }
        }
    }
}