use super::*;
use rand::RngExt;
use sha2::Sha256;
use std::fs::OpenOptions;
use uuid::Uuid;

fn files_list_factory(n: usize) -> FilesList {
    // Directory with a random name.
    let dir = format!("./tests/playground/tmp/{}", Uuid::new_v4());
    let mut fl = FilesList { dir, files: vec![] };

    for _ in 0..n {
        fl.files.push(Uuid::new_v4().to_string());
    }

    fl
}

fn create_files(fl: &FilesList) -> Result<()> {
    fs::create_dir(fl.dir())?;

    for inx in 0..fl.len() {
        let fw = File::create(fl.path(inx))?;
        let mut writer = BufWriter::new(&fw);
        writeln!(
            writer,
            "{}\n{}\n{}",
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4()
        )?;
    }

    // Verify that the files have been created.
    for inx in 0..fl.len() {
        if !Path::new(&fl.path(inx)).is_file() {
            return Err(FwcError::Internal("File not created"));
        }
    }

    Ok(())
}

fn sha256_cvs_string(fl: &mut FilesList) -> Result<String> {
    let mut cvs = String::from("file,sha256\n");
    for inx in 0..fl.len() {
        let mut file = File::open(fl.path(inx))?;
        let mut sha256 = Sha256::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            sha256.update(&buffer[..read]);
        }
        let line = format!("{},{}\n", fl.name(inx), hex::encode(sha256.finalize()));
        cvs.push_str(&line);
    }

    Ok(cvs)
}

#[test]
fn head_remove_empty_result_if_file_not_exists() {
    let fl = files_list_factory(5);
    let inx = rand::rng().random_range(0..5);
    let empty: Vec<String> = vec![];
    assert_eq!(fl.head_remove(inx, 100).unwrap(), empty);
}

#[test]
fn head_remove_returns_full_file_and_empties_file() -> Result<()> {
    let fl = files_list_factory(5);
    let inx = rand::rng().random_range(0..5);

    create_files(&fl)?;

    let file_content = fl.dump(inx).unwrap().join("\n");
    let result = fl.head_remove(inx, 100).unwrap().join("\n");
    let file_len = fs::metadata(fl.path(inx))?.len();

    fl.remove()?;
    fs::remove_dir(fl.dir())?;

    assert_eq!(result, file_content);
    assert_eq!(file_len, 0);

    Ok(())
}

#[test]
fn head_remove_line_by_line() -> Result<()> {
    let fl = files_list_factory(5);
    let inx = rand::rng().random_range(0..5);

    create_files(&fl)?;

    let file_content = fl.dump(inx)?;
    let file_lines_count = file_content.len();
    for (i, line) in file_content.iter().enumerate() {
        let result = fl.head_remove(inx, 1)?;
        let new_lines_count = fl.dump(inx)?.len();
        assert_eq!(line, &result[0]);
        assert_eq!(new_lines_count, file_lines_count - (i + 1));
    }

    fl.remove()?;
    fs::remove_dir(fl.dir())?;

    Ok(())
}

#[test]
fn head_remove_two_lines_max() -> Result<()> {
    let fl = files_list_factory(5);
    let inx = rand::rng().random_range(0..5);

    create_files(&fl)?;

    let file_content = fl.dump(inx)?;
    let file_lines_count = file_content.len();

    let _result = fl.head_remove(inx, 2)?;
    let new_file_content = fl.dump(inx)?;
    let new_lines_count = new_file_content.len();

    fl.remove()?;
    fs::remove_dir(fl.dir())?;

    assert_eq!(file_content[2], new_file_content[0]);
    assert_eq!(new_lines_count, file_lines_count - 2);

    Ok(())
}

#[test]
fn len_for_zero_files() {
    let fl = files_list_factory(0);
    assert_eq!(fl.len(), 0);
}

#[test]
fn len_for_some_files() {
    let n = rand::rng().random_range(1..6);
    let fl = files_list_factory(n);
    assert_eq!(fl.len(), n);
}

#[test]
fn right_file_name() {
    let fl = files_list_factory(5);
    let inx = rand::rng().random_range(0..5);
    assert_eq!(fl.name(inx), fl.files[inx]);
}

#[test]
fn directory_exists() {
    let fl = files_list_factory(0);
    fs::create_dir(fl.dir()).unwrap();
    assert!(fl.dir_exists());
    fs::remove_dir(fl.dir()).unwrap();
}

#[test]
fn directory_not_exists() {
    let fl = files_list_factory(0);
    assert!(!fl.dir_exists());
}

#[test]
fn get_directory() {
    let fl = files_list_factory(0);
    assert_eq!(fl.dir(), fl.dir);
}

#[test]
fn rename_file() {
    let mut fl = files_list_factory(5);
    let inx = rand::rng().random_range(0..5);
    let new_file_name = "new_file_name";

    fl.rename(inx, new_file_name);
    assert_eq!(fl.files[inx], new_file_name);
}

#[test]
fn change_directory() {
    let mut fl = files_list_factory(0);
    let new_directory_name = "./new_directory_name";

    fl.chdir(new_directory_name);
    assert_eq!(fl.dir, new_directory_name);
}

#[test]
fn remove_all_files() -> Result<()> {
    let n = rand::rng().random_range(1..6);
    let fl = files_list_factory(n);

    create_files(&fl)?;

    // Check that the files have been removed from the directory.
    fl.remove()?;
    for inx in 0..fl.len() {
        if Path::new(&fl.path(inx)).is_file() {
            fs::remove_dir(fl.dir())?;
            return Err(FwcError::Internal("File not removed"));
        }
    }

    fs::remove_dir(fl.dir())?;
    Ok(())
}

#[test]
fn remove_returns_error_if_dir_not_exists() {
    let fl = files_list_factory(0);

    assert!(matches!(fl.remove(), Err(FwcError::DirNotFound)));
}

#[test]
fn get_files_in_dir_gets_all_files() -> Result<()> {
    let n = rand::rng().random_range(1..6);
    let mut fl1 = files_list_factory(n);

    create_files(&fl1)?;

    let mut fl2 = files_list_factory(0);
    fl2.chdir(&fl1.dir());
    fl2.get_files_in_dir()?;
    fl1.remove()?;
    fs::remove_dir(fl1.dir())?;

    // Check that all directory files have been read.
    fl1.files.sort();
    fl2.files.sort();
    assert_eq!(fl1.files, fl2.files);
    Ok(())
}

#[test]
fn get_files_in_dir_returns_error_if_dir_not_exists() {
    let mut fl = files_list_factory(0);

    assert!(matches!(fl.get_files_in_dir(), Err(FwcError::DirNotFound)));
}

#[test]
fn sha256_gives_empty_result_if_dir_is_empty() {
    let fl = files_list_factory(0);

    fs::create_dir(fl.dir()).unwrap();
    assert_eq!(fl.sha256(false).unwrap(), String::from("file,sha256\n"));
    fs::remove_dir(fl.dir()).unwrap();
}

#[test]
fn sha256_gives_empty_result_if_dir_not_exists() {
    let fl = files_list_factory(0);
    assert_eq!(fl.sha256(false).unwrap(), String::from("file,sha256\n"));
}

#[test]
fn sha256_files_without_comments() -> Result<()> {
    let mut fl = files_list_factory(5);

    create_files(&fl)?;
    let result = fl.sha256(false)?;
    let result_ignore_comments = fl.sha256(true)?;
    let compare = sha256_cvs_string(&mut fl)?;
    fl.remove()?;
    fs::remove_dir(fl.dir())?;

    assert_eq!(result, compare);
    // No comments in files, then the result must be the same.
    assert_eq!(result_ignore_comments, compare);

    Ok(())
}

#[test]
fn sha256_files_with_comments() -> Result<()> {
    let mut fl = files_list_factory(5);

    create_files(&fl)?;

    // Add comments to one file.
    let mut file = OpenOptions::new().append(true).open(fl.path(3)).unwrap();
    writeln!(file, "# First comment line!")?;
    writeln!(file, "# Second comment line!")?;

    let result = fl.sha256(false)?;
    let result_ignore_comments = fl.sha256(true)?;
    let compare = sha256_cvs_string(&mut fl)?;
    fl.remove()?;
    fs::remove_dir(fl.dir())?;

    assert_eq!(result, compare);
    // We have comments in one file, then the result when we ignore the comments must be different.
    assert_ne!(result_ignore_comments, compare);

    Ok(())
}

#[test]
fn dumps_the_file_content() -> Result<()> {
    let fl = files_list_factory(5);
    let inx = rand::rng().random_range(0..5);

    create_files(&fl)?;

    // Modify one of the files.
    let mut fw = File::create(fl.path(inx))?;
    let compare = format!("{}\n{}", Uuid::new_v4(), Uuid::new_v4());
    fw.write_all(compare.as_bytes())?;
    drop(fw);

    let result = fl.dump(inx).unwrap().join("\n");

    fl.remove()?;
    fs::remove_dir(fl.dir())?;

    assert_eq!(result, compare);

    Ok(())
}
