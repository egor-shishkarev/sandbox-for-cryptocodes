use std::{fs::{File, create_dir_all, read_to_string, rename}, io::Write, path::Path};
use std::io;

use crate::attack_report::AttackReport;

pub fn save_report(report: &AttackReport, file_name: String) -> std::io::Result<()> {
    let dir = Path::new("src/reports");
    create_dir_all(dir)?;
    let path = dir.join(file_name);

    // 1) Прочитать, если файл существует, иначе считаем что он пустой
    let existing = match read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };

    // 2) Превратить в Vec<AttackReport>
    let mut reports: Vec<AttackReport> = if existing.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&existing).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Report file is not a JSON array: {e}"),
            )
        })?
    };

    // 3) Добавить новый отчёт
    reports.push(report.clone());

    // 4) Записать обратно (лучше атомарно: через temp + rename)
    let json = serde_json::to_string_pretty(&reports).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to serialize reports: {e}"))
    })?;

    let tmp_path = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?; // чтобы меньше шансов потерять данные при краше
    }
    rename(tmp_path, path)?;

    Ok(())
}