use std::io::{self, Write};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, Result as SqlResult};

use crate::AppResult;
use crate::config::Config;
use crate::db;

pub fn shell(config: &Config) -> AppResult {
    let conn = db::open_encrypted_database(config)?;

    println!(
        "Connected to {}. Enter SQL, or .exit/.quit to leave.",
        config.database_path().display()
    );

    let stdin = io::stdin();
    loop {
        print!("sql> ");
        io::stdout().flush()?;

        let mut sql = String::new();
        if stdin.read_line(&mut sql)? == 0 {
            break;
        }

        let sql = sql.trim();
        if sql.is_empty() {
            continue;
        }

        if matches!(sql, ".exit" | ".quit") {
            break;
        }

        if let Err(error) = execute_sql(&conn, sql) {
            eprintln!("error: {error}");
        }
    }

    Ok(())
}

fn execute_sql(conn: &Connection, sql: &str) -> SqlResult<()> {
    let mut stmt = conn.prepare(sql)?;
    let column_count = stmt.column_count();

    if column_count == 0 {
        let changed = stmt.execute([])?;
        println!("{changed} row(s) changed");
        return Ok(());
    }

    let headers: Vec<String> = stmt.column_names().into_iter().map(str::to_owned).collect();
    let mut rows = stmt.query([])?;
    let mut values = Vec::new();

    while let Some(row) = rows.next()? {
        let mut row_values = Vec::with_capacity(column_count);
        for index in 0..column_count {
            row_values.push(format_value(row.get_ref(index)?));
        }
        values.push(row_values);
    }

    print_table(&headers, &values);
    Ok(())
}

fn format_value(value: ValueRef<'_>) -> String {
    match value {
        ValueRef::Null => "NULL".to_owned(),
        ValueRef::Integer(value) => value.to_string(),
        ValueRef::Real(value) => value.to_string(),
        ValueRef::Text(value) => String::from_utf8_lossy(value).into_owned(),
        ValueRef::Blob(value) => format!("<{} bytes>", value.len()),
    }
}

fn print_table(headers: &[String], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();

    for row in rows {
        for (index, value) in row.iter().enumerate() {
            widths[index] = widths[index].max(value.len());
        }
    }

    print_row(headers, &widths);
    print_separator(&widths);

    for row in rows {
        print_row(row, &widths);
    }

    println!("{} row(s)", rows.len());
}

fn print_row(values: &[String], widths: &[usize]) {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            print!(" | ");
        }
        print!("{value:<width$}", width = widths[index]);
    }
    println!();
}

fn print_separator(widths: &[usize]) {
    for (index, width) in widths.iter().enumerate() {
        if index > 0 {
            print!("-+-");
        }
        print!("{}", "-".repeat(*width));
    }
    println!();
}
