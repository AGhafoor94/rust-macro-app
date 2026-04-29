use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::{
    env::args,
    fs::{self, DirEntry, File, FileType},
    io::{self, Read},
    path::Path,
    process::Output,
};
// cargo build --release app.exe
// #![windows_subsystem = "windows"]
use reqwest::header::HeaderMap;
use reqwest::header::{ACCEPT, CONTENT_TYPE};

use windows::Win32::{
    Foundation::*,
    System::{
        DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard, SetClipboardData},
        Shutdown::LockWorkStation,
        SystemInformation::GetLocalTime,
    },
    UI::{Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
};
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Macro {
    app_name: String,
    app: Vec<App>,
    r#loop: usize,
    hotkey: String,
    read_csv: String,
    word_delay: u64,
    delay_for_each_loop: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct App {
    app_value: String,
    website_open: bool,
    r#loop: u16,
    run_once: Vec<Steps>,
    steps: Vec<Steps>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Steps {
    name: String,
    code: u16,
    held: bool,
    sentence: String,
    time: u64,
    r#loop: u8,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Keys {
    keys: Vec<KeyCodesCsv>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyCodesCsv {
    name: String,
    windows: u16,
    ascii: u16,
    shift: bool,
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GraphUserDetails {
    id: String,
    display_name: String,
    user_principal_name: String,
}
#[derive(Serialize, Deserialize)]
// #[serde(rename_all = "camelCase")]
struct GraphToken {
    access_token: String,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = args().collect();
    let mut _current_system_time: SYSTEMTIME = SYSTEMTIME {
        ..Default::default()
    };
    unsafe {
        _current_system_time = GetLocalTime();
    }
    let log_file_path: String = format!(
        "Log File {}-{}-{}.txt",
        check_for_length_time_and_date(_current_system_time.wDay),
        check_for_length_time_and_date(_current_system_time.wMonth),
        _current_system_time.wYear
    );
    let mut _log_file: Result<File, io::Error> = File::open(&log_file_path);
    let error_log_file_path: String = format!(
        "Error Log File {}-{}-{}.txt",
        check_for_length_time_and_date(_current_system_time.wDay),
        check_for_length_time_and_date(_current_system_time.wMonth),
        _current_system_time.wYear
    );
    let mut _error_log_file: Result<File, io::Error> = File::open(&error_log_file_path);
    // let graph_token: GraphToken = get_token().await?;
    let mut keys_buffer: String = String::new();
    // std::thread::sleep(std::time::Duration::from_millis(500));
    // let graph_user: GraphUserDetails = get_user_details_graph(graph_token.access_token).await?;
    // println!("{:?}", graph_user);
    let _ = File::open(".\\keys.json")
        .unwrap()
        .read_to_string(&mut keys_buffer);
    // println!("{:?}", response.access_token);
    // let _ = keys_file.read_to_string(&mut keys_buffer);
    // let directory_files: Result<Output, std::io::Error> = execute_command("cmd", &["/C", "dir /b /a-d"]);

    let keys_json: Keys = serde_json::from_str(&keys_buffer).expect("Unable to get data");
    // keys_json.keys.iter().for_each(|f| {
    //     println!("{}, {}", &f.name, &f.ascii);
    // });
    // match directory_files {
    //     Ok(v) => println!("{:?}", v),
    //     _ => println!("Error"),
    // };
    let mut buffer: String = String::new();
    /*
        let mut file_name: String = String::new();
        let _ = io::stdin().read_line(&mut file_name);
        let _ = File::open(format!(".\\marcos\\{name}.json", name=file_name.trim())).unwrap().read_to_string(&mut buffer);
    */
    let _ = File::open(format!(".\\marcos\\{name}.json", name = &args[1].trim()))
        .unwrap()
        .read_to_string(&mut buffer);
    let data: Macro = serde_json::from_str(&buffer).expect("Not found");
    let app: &Vec<App> = &data.app;
    let log_date: String = format!(
        "{}-{}-{}\n",
        check_for_length_time_and_date(_current_system_time.wDay),
        check_for_length_time_and_date(_current_system_time.wMonth),
        _current_system_time.wYear
    );

    match _log_file {
        Err(e) => {
            let mut buffer_data: String = String::new();
            let _ = File::create(&log_file_path);
            let _ = buffer_data.push_str(format!("Using file: {}.json", &args[1].trim()).as_str());
            // let _ = buffer_data.push_str(format!("Using file: {}.json", &file_name.trim()).as_str());
            fs::write(format!(".\\{}", &log_file_path), log_date.replace("-", "/")).expect("Error");
            update_log_file(
                &log_file_path,
                format!("File didn't exist. Created log file: {}", e).as_str(),
            )
        }
        _ => update_log_file(&log_file_path, "Log file created"),
    }

    update_log_file(
        &log_file_path,
        format!("Using file: {}.json", &args[1].trim()).as_str(),
        // format!("Using file: {}.json", &file_name.trim()).as_str(),
    );
    // let _ = file.read_to_string(&mut buffer);
    // println!("{:?}",&buffer);

    let loops: usize = data.r#loop;
    // let virtual_keys_vec:Vec<u16> = vec![0x5B,0x90,0x91,0x14];
    let mut run_once_vector_steps: Vec<Steps> = Vec::new();
    let mut hold_keys_vector_steps: Vec<Steps> = Vec::new();
    // let mut hold_keys_vector:Vec<u16> = Vec::new();
    // let _virtual_keys_vector: Vec<u16> = Vec::new();
    let mut _program: String = String::new();
    let mut website: bool = false;
    // let continue_app: bool = true;
    let mut csv_lines: Vec<&str> = vec![];
    let mut _read_csv_file: bool = false;
    let mut buffer_csv_lines: String = String::new();
    let mut csv_lines_loop: u16 = 0;

    if !&data.read_csv.is_empty() {
        _read_csv_file = true;
        let csv_file_location: String = data.read_csv.clone();
        if csv_file_location.to_lowercase().contains("contains")
            || csv_file_location.to_lowercase().contains("equals")
        {
            // const KEYWORDS_IN_READ_CSV: [&str; 6] =
            // ["IN", "CONTAINS", "EQUALS", "NEWEST", "OLDEST", "DATE"];
            /*
                Split by space
                get items and keywords
                if second to last index = Date, filter by date
                combine 2 items
            */
            // let _ = &data.read_csv.split(" ").into_iter().for_each(|f| {
            //     let find_keyword = KEYWORDS_IN_READ_CSV.iter().find(|&&x| &f == &x);

            //     match find_keyword {
            //         Some(v) => println!("FIND KEYWORD: {:?}", v),
            //         _ => println!("ERROR FIND KEYWORD"),
            //     }
            // });
            let mut temp_csv_location: String = "%USERPROFILE%\\".to_owned();
            // need to get c drive and username
            let split_string_read_csv: Vec<&str> = data.read_csv.split(" ").collect();
            for (index, &item) in split_string_read_csv.iter().enumerate() {
                match item {
                    "IN" => {
                        temp_csv_location += split_string_read_csv[index + 1];
                        // check cmd to get list of items that contains name
                        // Contains
                        if split_string_read_csv[index + 2] == "CONTAINS" {
                            let file_command_execute = execute_command(
                                "cmd",
                                &[
                                    "/C",
                                    format!(
                                        "cd {} && dir /b /s *.csv | findstr {}*",
                                        temp_csv_location,
                                        split_string_read_csv[index + 3]
                                    )
                                    .as_str(),
                                ],
                            );
                            println!("FILE COMMAND EXECUTE: {:?}", file_command_execute);
                            match file_command_execute {
                                Ok(o) => {
                                    let std_out: String = String::from_utf8(o.stdout).unwrap();
                                    temp_csv_location =
                                        std_out.split("\n").nth(0).unwrap().replace("\r", "")
                                }
                                Err(e) => println!("ERROR RUNNING COMMAND: {}", e),
                            }
                        }
                    }
                    _ => temp_csv_location += "",
                }
            }
            let csv_file: Result<File, io::Error> = File::open(&temp_csv_location);
            println!("READ CSV LINE: {}", &temp_csv_location);
            match csv_file {
                Ok(v) => {
                    let mut lines_to_read: io::BufReader<File> = std::io::BufReader::new(v);
                    let _ = &lines_to_read.read_to_string(&mut buffer_csv_lines);
                }
                Err(e) => {
                    update_log_file(
                        &log_file_path,
                        format!("Error trying to read csv file: {}", e).as_str(),
                    );
                    return Ok(());
                }
            }
            // let _ = &buffer_csv_lines.split("\r\n").into_iter().for_each(|line| println!("{}", line));
            csv_lines_loop = buffer_csv_lines.split("\r\n").clone().count() as u16;
            csv_lines = buffer_csv_lines.split("\r\n").collect();
            if csv_lines[csv_lines.len() - 1].len() == 0 {
                csv_lines_loop = csv_lines_loop - 1;
            }
            // let _ = csv_lines.remove(0);
            println!(
                "CSV LINES: {:?}, NUM: {}",
                csv_lines[csv_lines.len() - 1],
                csv_lines_loop
            );
            update_log_file(
                &log_file_path,
                format!(
                    "Number of loops updated from {} to {}",
                    &data.r#loop, &loops
                )
                .as_str(),
            );
        } else {
            let csv_file: Result<File, io::Error> = File::open(&data.read_csv);
            match csv_file {
                Ok(v) => {
                    let mut lines_to_read: io::BufReader<File> = std::io::BufReader::new(v);
                    let _ = &lines_to_read.read_to_string(&mut buffer_csv_lines);
                }
                Err(e) => {
                    update_log_file(
                        &log_file_path,
                        format!(
                            "Error trying to read csv file ({}): {}",
                            csv_file_location, e
                        )
                        .as_str(),
                    );
                    return Ok(());
                }
            }
            // let _ = &buffer_csv_lines.split("\r\n").into_iter().for_each(|line| println!("{}", line));
            csv_lines_loop = buffer_csv_lines.split("\r\n").clone().count() as u16;
            csv_lines = buffer_csv_lines.split("\r\n").collect();
            if csv_lines[csv_lines.len() - 1].len() == 0 {
                csv_lines_loop = csv_lines_loop - 1;
            }
            // let _ = csv_lines.remove(0);
            println!(
                "CSV LINES: {:?}, NUM: {}",
                csv_lines[csv_lines.len() - 1],
                csv_lines_loop
            );
            update_log_file(
                &log_file_path,
                format!(
                    "Number of loops updated from {} to {}",
                    &data.r#loop, &loops
                )
                .as_str(),
            );
        }
    }
    // println!("{}", log_date);
    // if !continue_app {
    //     std::process::exit(0x000)
    // }
    if !&data.hotkey.is_empty() {
        // println!("{:?}", data.hotkey.split(','));
        // let split_comma_count = data.hotkey.split(',').count();
        println!("Waiting for hot keys...");
        let mut hot_keys: Vec<i32> = vec![];
        let _ = &data.hotkey.split(",").into_iter().for_each(|key| {
            hot_keys.push(key.trim().parse::<i32>().expect("Error parsing to i32"))
        });
        // for word in data.hotkey.split(',').into_iter() {
        //     hot_keys.push(word.trim().parse::<i32>().expect("Error"));
        //     // println!("{:?}", &word.trim().parse::<u8>().expect("Error"));
        // }
        // println!("keys: {:?},{}, {:?},{}",hot_keys[0], key_one, hot_keys[1], key_two);
        while !get_key_state(hot_keys[0]) || !get_key_state(hot_keys[1]) {
            // println!("keys: {:?},{}, {:?},{}",hot_keys[0], key_one, hot_keys[1], key_two);
            if get_key_state(hot_keys[0]) && get_key_state(hot_keys[1]) {
                update_log_file(
                    &log_file_path,
                    format!("Hot Keys Pressed: {}, {}", hot_keys[0], hot_keys[1]).as_str(),
                );
                break;
            }
        }
    }

    for app_iter in app.into_iter() {
        update_log_file(
            &log_file_path,
            format!(
                "Type of app: {} & Number of steps: {}",
                &app_iter.app_value.clone(),
                &app_iter.steps.len()
            )
            .as_str(),
        );
        if String::eq(&app_iter.app_value, "app") || app_iter.app_value.is_empty() {
            _program = app_iter.app_value.to_owned();

            let cloned_app_iter: Vec<Steps> = app_iter.run_once.clone();
            let app_steps: Vec<Steps> = app_iter.steps.clone();
            if app_iter.run_once.len() > 0 {
                let _ = cloned_app_iter
                    .into_iter()
                    .for_each(|step| run_once_vector_steps.push(step));
            }
            let _ = app_steps
                .into_iter()
                .for_each(|step| hold_keys_vector_steps.push(step));
            std::thread::sleep(std::time::Duration::from_millis(250));
        } else {
            if app_iter.website_open {
                _program = app_iter.app_value.to_owned();
                website = true;

                let _ = execute_command(
                    "cmd",
                    &["/C", "start msedge --new-window", &app_iter.app_value],
                );

                update_log_file(
                    &log_file_path,
                    format!("Opening Website: {}", &app_iter.app_value).as_str(),
                );
                unsafe {
                    let _ = SetActiveWindow(GetForegroundWindow());
                }
                let cloned_app_iter: Vec<Steps> = app_iter.run_once.clone();
                let app_steps: Vec<Steps> = app_iter.steps.clone();
                if app_iter.run_once.len() > 0 {
                    let _ = cloned_app_iter
                        .into_iter()
                        .for_each(|step| run_once_vector_steps.push(step));
                }
                let _ = app_steps
                    .into_iter()
                    .for_each(|step| hold_keys_vector_steps.push(step));
            } else {
                _program = app_iter.app_value.to_owned();
                let _ = execute_command(
                    "cmd",
                    &[
                        "/C",
                        "start",
                        format!("{}.exe", &app_iter.app_value).as_str(),
                    ],
                );

                update_log_file(
                    &log_file_path,
                    format!("Opening File: {}.exe", &app_iter.app_value).as_str(),
                );

                // Add function for single step at top

                let cloned_app_iter: Vec<Steps> = app_iter.run_once.clone();
                let app_steps: Vec<Steps> = app_iter.steps.clone();
                if app_iter.run_once.len() > 0 {
                    let _ = cloned_app_iter
                        .into_iter()
                        .for_each(|step| run_once_vector_steps.push(step));
                }
                let _ = app_steps
                    .into_iter()
                    .for_each(|step| hold_keys_vector_steps.push(step));
            }
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
    }
    let mut run_once_length: usize = run_once_vector_steps.len();
    let mut _current_window: HWND = HWND {
        ..Default::default()
    };
    unsafe {
        _current_window = GetForegroundWindow();
        let _ = SetFocus(_current_window);
        let _ = SetActiveWindow(_current_window);
        // PostMessage(_current_window, WM_SYSCOMMAND, SC_RESTORE, 0);
    }
    let mut _result_window_text: String = get_current_window_heading_text(&log_file_path);
    std::thread::sleep(std::time::Duration::from_millis(500));
    // let _ = SetForegroundWindow(_current_window);

    if !_read_csv_file {
        csv_lines_loop = data.app[0].r#loop;
    }

    for i in 0..loops {
        // if _current_system_time.wHour > 14 {
        //     unsafe {
        //         let _ = LockWorkStation();
        //         std::process::exit(0x000)
        //         // let _ = InitiateSystemShutdownA(None,None,0,true, false);
        //         // let _ = InitiateShutdownA(None,None,0,SHUTDOWN_FORCE_OTHERS|SHUTDOWN_GRACE_OVERRIDE,SHTDN_REASON_FLAG_PLANNED);
        //     }
        // }
        if get_key_state(162) && get_key_state(91) {
            std::process::exit(0x000)
        }
        unsafe {
            _current_system_time = GetLocalTime();
        }
        update_log_file(
            &log_file_path,
            format!(
                "Starting Current Loop Iteration: {} of {}. TIME STARTED: {}:{}:{}",
                (i + 1),
                loops,
                _current_system_time.wMinute,
                _current_system_time.wSecond,
                _current_system_time.wMilliseconds
            )
            .as_str(),
        );
        if i > 0 {
            if website {
                // let _ = execute_command(
                //     "cmd",
                //     &["/C", "start msedge --new-window -incognito", &_program],
                // );
                // let _ = execute_command(
                //     "cmd",
                //     &["/C", "start msedge --new-window -inprivate", &_program],
                // );
                let _ = execute_command("cmd", &["/C", "start msedge --new-window", &_program]);
                _result_window_text = get_current_window_heading_text(&log_file_path);
                update_log_file(
                    &log_file_path,
                    format!("Opening Website: {}", &_program).as_str(),
                );
            } else {
                if !String::eq(&_program, "app") {
                    let _ = execute_command(
                        "cmd",
                        &["/C", "start", format!("{}.exe", &_program).as_str()],
                    );
                    update_log_file(
                        &log_file_path,
                        format!("Opening Website: {}.exe", &_program).as_str(),
                    );
                    _result_window_text = get_current_window_heading_text(&log_file_path);
                }
            }
        }
        if run_once_length > 0 as usize {
            run_only_steps(
                &run_once_vector_steps,
                &log_file_path,
                _current_system_time,
                &_program,
                &_result_window_text,
                _read_csv_file,
                &csv_lines,
                &keys_json,
                &data,
                1,
            );
            run_once_length = 0;
        }

        run_only_steps(
            &hold_keys_vector_steps,
            &log_file_path,
            _current_system_time,
            &_program,
            &_result_window_text,
            _read_csv_file,
            &csv_lines,
            &keys_json,
            &data,
            csv_lines_loop as usize,
        );
        println!("Current Item: {}", i);
    }

    update_log_file(&log_file_path, "Ended Macro\n\n");
    Ok(())
    // std::process::exit(0x000)
}
fn send_input_messages_from_i16(virtual_key_num: i16, release_key: bool, individial_press: bool) {
    let get_key_state_int: u16 = virtual_key_num as u16;

    let input_zero: INPUT_0 = INPUT_0 {
        ki: KEYBDINPUT {
            wVk: VIRTUAL_KEY(get_key_state_int),
            wScan: 0,
            dwFlags: KEYEVENTF_UNICODE,
            time: 0,
            dwExtraInfo: 0x0008 as usize,
        },
    };
    let release_zero: INPUT_0 = INPUT_0 {
        ki: KEYBDINPUT {
            wVk: VIRTUAL_KEY(get_key_state_int),
            wScan: 0,
            dwFlags: KEYEVENTF_KEYUP | KEYEVENTF_UNICODE,
            time: 0,
            dwExtraInfo: 0x0008 as usize,
        },
    };
    let input_struct: INPUT = INPUT {
        r#type: INPUT_TYPE(1),
        Anonymous: input_zero,
    };
    let input_release_struct: INPUT = INPUT {
        r#type: INPUT_TYPE(1),
        Anonymous: release_zero,
    };
    // let struct_size:i32 = core::mem::size_of::<INPUT>() as i32;
    if individial_press {
        // println!("{:?}", key_state);
        if release_key {
            unsafe {
                let _ = SendInput(
                    &[input_release_struct],
                    core::mem::size_of::<INPUT>() as i32,
                );
            }
        }
        unsafe {
            let _ = SendInput(&[input_struct], core::mem::size_of::<INPUT>() as i32);
        }
    } else {
        unsafe {
            let _ = SendInput(
                &[input_release_struct],
                core::mem::size_of::<INPUT>() as i32,
            );
        }
    }
}
fn send_multi_input_messages_from_i16(virtual_key_num: i16, virtual_key_num_two: i16, delay: u64) {
    let get_key_state_int = virtual_key_num as u16;
    let get_key_state_int_key_two = virtual_key_num_two as u16;
    let input_zero: INPUT_0 = INPUT_0 {
        ki: KEYBDINPUT {
            wVk: VIRTUAL_KEY(get_key_state_int),
            wScan: 0,
            dwFlags: KEYEVENTF_UNICODE,
            time: 0,
            dwExtraInfo: 0x0008 as usize,
        },
    };
    let release_zero: INPUT_0 = INPUT_0 {
        ki: KEYBDINPUT {
            wVk: VIRTUAL_KEY(get_key_state_int),
            wScan: 0,
            dwFlags: KEYEVENTF_KEYUP | KEYEVENTF_UNICODE,
            time: 0,
            dwExtraInfo: 0x0008 as usize,
        },
    };
    let input_struct: INPUT = INPUT {
        r#type: INPUT_TYPE(1),
        Anonymous: input_zero,
    };
    let input_release_struct: INPUT = INPUT {
        r#type: INPUT_TYPE(1),
        Anonymous: release_zero,
    };
    let input_zero_key_two: INPUT_0 = INPUT_0 {
        ki: KEYBDINPUT {
            wVk: VIRTUAL_KEY(get_key_state_int_key_two),
            wScan: 0,
            dwFlags: KEYEVENTF_UNICODE,
            time: 0,
            dwExtraInfo: 0x0008 as usize,
        },
    };
    let release_zero_key_two: INPUT_0 = INPUT_0 {
        ki: KEYBDINPUT {
            wVk: VIRTUAL_KEY(get_key_state_int_key_two),
            wScan: 0,
            dwFlags: KEYEVENTF_KEYUP | KEYEVENTF_UNICODE,
            time: 0,
            dwExtraInfo: 0x0008 as usize,
        },
    };
    let input_struct_key_two: INPUT = INPUT {
        r#type: INPUT_TYPE(1),
        Anonymous: input_zero_key_two,
    };
    let input_release_struct_key_two: INPUT = INPUT {
        r#type: INPUT_TYPE(1),
        Anonymous: release_zero_key_two,
    };
    unsafe {
        // let _ = GetKeyState(get_key_state_int);
        let _ = SendInput(&[input_struct], core::mem::size_of::<INPUT>() as i32);
        let _ = SendInput(
            &[input_struct_key_two],
            core::mem::size_of::<INPUT>() as i32,
        );
        std::thread::sleep(std::time::Duration::from_millis(delay));
        let _ = SendInput(
            &[input_release_struct],
            core::mem::size_of::<INPUT>() as i32,
        );
        let _ = SendInput(
            &[input_release_struct_key_two],
            core::mem::size_of::<INPUT>() as i32,
        );
        // let shift_key_state:i16 = GetKeyState(get_key_state_int as i32);
        // println!("Shift Key State: {:?}", shift_key_state);
        // if shift_key_state == 1 {
        //     let _ = SendInput(
        //         &[input_release_struct],
        //         core::mem::size_of::<INPUT>() as i32,
        //     );
        // }
    }
}
fn send_input_messages(virtual_key_num: u16, release_key: bool, individial_press: bool) {
    let input_zero: INPUT_0 = INPUT_0 {
        ki: KEYBDINPUT {
            wVk: VIRTUAL_KEY(virtual_key_num),
            wScan: 0,
            dwFlags: KEYEVENTF_UNICODE,
            time: 0,
            dwExtraInfo: 0x0008 as usize,
        },
    };
    let release_zero: INPUT_0 = INPUT_0 {
        ki: KEYBDINPUT {
            wVk: VIRTUAL_KEY(virtual_key_num),
            wScan: 0,
            dwFlags: KEYEVENTF_KEYUP | KEYEVENTF_UNICODE,
            time: 0,
            dwExtraInfo: 0x0008 as usize,
        },
    };
    // let release_shift: INPUT_0 = INPUT_0 {
    //     ki: KEYBDINPUT {
    //         wVk: VIRTUAL_KEY(160),
    //         wScan: 0,
    //         dwFlags: KEYEVENTF_KEYUP | KEYEVENTF_UNICODE,
    //         time: 0,
    //         dwExtraInfo: 0x0008 as usize,
    //     },
    // };
    let input_struct: INPUT = INPUT {
        r#type: INPUT_TYPE(1),
        Anonymous: input_zero,
    };
    let input_release_struct: INPUT = INPUT {
        r#type: INPUT_TYPE(1),
        Anonymous: release_zero,
    };
    // let input_release_shift_struct: INPUT = INPUT {
    //     r#type: INPUT_TYPE(1),
    //     Anonymous: release_shift,
    // };
    // let get_key_state_int = virtual_key_num as i32;

    // let _ = GetKeyState(get_key_state_int);
    match individial_press {
        true => {
            unsafe {
                let _ = SendInput(&[input_struct], core::mem::size_of::<INPUT>() as i32);
            }
            match release_key {
                true => unsafe {
                    let _ = SendInput(
                        &[input_release_struct],
                        core::mem::size_of::<INPUT>() as i32,
                    );
                },
                false => println!(""),
            }
        }
        false => unsafe {
            let _ = SendInput(
                &[input_release_struct],
                core::mem::size_of::<INPUT>() as i32,
            );
        },
    }
    // let _ = SendInput(
    //     &[input_release_shift_struct],
    //     core::mem::size_of::<INPUT>() as i32,
    // );

    // println!("{:?}", key_state);
}
fn execute_command(exe: &str, args: &[&str]) -> Result<Output, std::io::Error> {
    std::process::Command::new(exe).args(&*args).output()
}
fn send_mouse_input_message(
    x: i32,
    y: i32,
    move_mouse: bool,
    mouse_button: u16,
    held: bool,
    log_file_path: &str,
) {
    let mut point_struct: POINT = POINT {
        ..Default::default()
    };
    let mut _system_metrics_x: i32 = 0;
    let mut _system_metrics_y: i32 = 0;
    let mut _input_mouse_struct: INPUT = INPUT {
        ..Default::default()
    };
    unsafe {
        let _ = GetCursorPos(&mut point_struct);
        _system_metrics_x = GetSystemMetrics(SM_CXSCREEN);
        _system_metrics_y = GetSystemMetrics(SM_CYSCREEN);
    }
    match move_mouse {
        true => {
            match held {
                true => {
                    _input_mouse_struct = INPUT {
                        r#type: INPUT_TYPE(0),
                        Anonymous: INPUT_0 {
                            mi: MOUSEINPUT {
                                dx: point_struct.x,
                                dy: point_struct.y,
                                mouseData: 0x01,
                                dwFlags: MOUSEEVENTF_LEFTDOWN,
                                time: 0,
                                dwExtraInfo: Default::default(),
                            },
                        },
                    };
                    // let _ = SendInput(&[_input_mouse_struct],core::mem::size_of::<INPUT>() a     s i32);
                    _input_mouse_struct = INPUT {
                        r#type: INPUT_TYPE(0),
                        Anonymous: INPUT_0 {
                            mi: MOUSEINPUT {
                                dx: x * (65535 / _system_metrics_x),
                                dy: y * (65535 / _system_metrics_y),
                                mouseData: 0x01,
                                dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                                time: 0,
                                dwExtraInfo: Default::default(),
                            },
                        },
                    };
                }
                false => {
                    _input_mouse_struct = INPUT {
                        r#type: INPUT_TYPE(0),
                        Anonymous: INPUT_0 {
                            mi: MOUSEINPUT {
                                dx: point_struct.x,
                                dy: point_struct.y,
                                mouseData: 0x01,
                                dwFlags: MOUSEEVENTF_LEFTUP,
                                time: 0,
                                dwExtraInfo: Default::default(),
                            },
                        },
                    };
                    // let _ = SendInput(&[_input_mouse_struct],core::mem::size_of::<INPUT>() as i32);
                    _input_mouse_struct = INPUT {
                        r#type: INPUT_TYPE(0),
                        Anonymous: INPUT_0 {
                            mi: MOUSEINPUT {
                                dx: x * (65535 / _system_metrics_x),
                                dy: y * (65535 / _system_metrics_y),
                                mouseData: 0x01,
                                dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                                time: 0,
                                dwExtraInfo: Default::default(),
                            },
                        },
                    };
                }
            }
        }
        false => {
            match mouse_button {
                0x01 => {
                    _input_mouse_struct = INPUT {
                        r#type: INPUT_TYPE(0),
                        Anonymous: INPUT_0 {
                            mi: MOUSEINPUT {
                                dx: point_struct.x,
                                dy: point_struct.y,
                                mouseData: 0x01,
                                dwFlags: MOUSEEVENTF_LEFTDOWN,
                                time: 0,
                                dwExtraInfo: Default::default(),
                            },
                        },
                    };
                }
                0x02 => {
                    _input_mouse_struct = INPUT {
                        r#type: INPUT_TYPE(0),
                        Anonymous: INPUT_0 {
                            mi: MOUSEINPUT {
                                dx: point_struct.x,
                                dy: point_struct.y,
                                mouseData: 0x02,
                                dwFlags: MOUSEEVENTF_RIGHTDOWN,
                                time: 0,
                                dwExtraInfo: Default::default(),
                            },
                        },
                    };
                }
                _ => update_log_file(
                    log_file_path,
                    format!("Error clicking mouse {}", mouse_button).as_str(),
                ),
            }

            // println!("582: {:?}", point_struct);
        }
    }
    unsafe {
        let _ = SendInput(&[_input_mouse_struct], core::mem::size_of::<INPUT>() as i32);
    }
    std::thread::sleep(std::time::Duration::from_millis(25));
    match held {
        true => update_log_file(log_file_path, "Mouse button held"),
        false => match move_mouse {
            true => unsafe {
                let _ = SendInput(&[_input_mouse_struct], core::mem::size_of::<INPUT>() as i32);
            },
            false => {
                match mouse_button {
                    0x01 => {
                        _input_mouse_struct = INPUT {
                            r#type: INPUT_TYPE(0),
                            Anonymous: INPUT_0 {
                                mi: MOUSEINPUT {
                                    dx: point_struct.x,
                                    dy: point_struct.y,
                                    mouseData: 0x01,
                                    dwFlags: MOUSEEVENTF_LEFTUP,
                                    time: 0,
                                    dwExtraInfo: Default::default(),
                                },
                            },
                        };
                    }
                    0x02 => {
                        _input_mouse_struct = INPUT {
                            r#type: INPUT_TYPE(0),
                            Anonymous: INPUT_0 {
                                mi: MOUSEINPUT {
                                    dx: point_struct.x,
                                    dy: point_struct.y,
                                    mouseData: 0x02,
                                    dwFlags: MOUSEEVENTF_RIGHTUP,
                                    time: 0,
                                    dwExtraInfo: Default::default(),
                                },
                            },
                        };
                    }
                    _ => update_log_file(
                        log_file_path,
                        format!("Error clicking mouse {}", mouse_button).as_str(),
                    ),
                }
                unsafe {
                    let _ = SendInput(&[_input_mouse_struct], core::mem::size_of::<INPUT>() as i32);
                }
            }
        },
    }
}
async fn get_token() -> Result<GraphToken, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    headers.insert(ACCEPT, "application/json".parse().unwrap());

    let response:GraphToken = client.post("https://login.microsoft.com//oauth2/v2.0/token").body("client_id=&client_secret=&scope=https://graph.microsoft.com/.default&grant_type=client_credentials").headers(headers).send().await?.json::<GraphToken>().await?;
    // println!("{:?}", response.access_token);
    Ok(response)
}
async fn get_user_details_graph(
    token: String,
) -> Result<GraphUserDetails, Box<dyn std::error::Error>> {
    println!("Token: {:?}", token);
    let client = reqwest::Client::new();
    let mut headers: HeaderMap = HeaderMap::new();
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers.insert(
        "Authorization",
        format!("bearer {token_code}", token_code = token)
            .parse()
            .unwrap(),
    );
    let response: GraphUserDetails = client
        .get("https://graph.microsoft.com/v1.0/users/")
        .headers(headers)
        .send()
        .await?
        .json::<GraphUserDetails>()
        .await?;

    // let response:GraphUserDetails = reqwest::get("https://graph.microsoft.com/v1.0/me")
    //     .await?
    //     .json::<GraphUserDetails>()
    //     .await?;
    Ok(response)
}
fn copy_all_files_in_directory(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> io::Result<()> {
    fs::create_dir(&destination)?;
    for entry in fs::read_dir(&source)? {
        let entry: DirEntry = entry?;
        let try_get_file_type: FileType = entry.file_type()?;
        if try_get_file_type.is_dir() {
            copy_all_files_in_directory(
                entry.path(),
                &destination.as_ref().join(entry.file_name()),
            )?;
        } else {
            fs::copy(entry.path(), &destination.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}
fn add_sentence(sentence: &str, code: &u16, keys_json: &Keys, log_file_path: &str, delay: u64) {
    let mut _sentence_pass: Vec<u8> = vec![0];

    if *code == 997 {
        _sentence_pass = BASE64_STANDARD.decode(sentence).expect("Unable to parse");
    } else {
        _sentence_pass = sentence.as_bytes().to_vec();
    }

    _sentence_pass.into_iter().for_each(|f| {
        let mut _u16_total_key: u16 = 0;
        let mut hex_code: String = format!("{f:#X}");
        hex_code = hex_code.replace("0x", "");
        let first_char: String = hex_code[..1].to_owned();
        if f <= 15 {
            _u16_total_key = first_char.parse::<u16>().unwrap();
        } else {
            let first_char: String = hex_code[..1].to_owned();
            let second_char: String = hex_code[1..].to_owned();
            // println!("{}, {}",first_char, second_char);
            _u16_total_key = first_char.parse::<u16>().unwrap();
            _u16_total_key = _u16_total_key * 16;
            match &second_char as &str {
                "A" => _u16_total_key += 10,
                "B" => _u16_total_key += 11,
                "C" => _u16_total_key += 12,
                "D" => _u16_total_key += 13,
                "E" => _u16_total_key += 14,
                "F" => _u16_total_key += 15,
                _ => _u16_total_key += second_char.parse::<u16>().unwrap(),
            };
            // if second_char == "A" || second_char == "a" {
            //     _u16_total_key = _u16_total_key + 10;
            // } else if second_char == "B" || second_char == "b" {
            //     _u16_total_key = _u16_total_key + 11;
            // } else if second_char == "C" || second_char == "c" {
            //     _u16_total_key = _u16_total_key + 12;
            // } else if second_char == "D" || second_char == "d" {
            //     _u16_total_key = _u16_total_key + 13;
            // } else if second_char == "E" || second_char == "e" {
            //     _u16_total_key = _u16_total_key + 14;
            // } else if second_char == "F" || second_char == "f" {
            //     _u16_total_key = _u16_total_key + 15;
            // } else {
            //     _u16_total_key = _u16_total_key + second_char.parse::<u16>().unwrap()
            // }
        }
        let find_key: Option<&KeyCodesCsv> =
            keys_json.keys.iter().find(|f| &f.ascii == &_u16_total_key);
        let mut key_from_json: u16 = 0;
        let mut _key_char: &str = "";
        let mut hold_shift: bool = false;
        match find_key {
            Some(val) => {
                // println!("{}, {}", val.ascii,val.name);
                hold_shift = val.shift;
                _key_char = val.name.as_str();
                key_from_json = val.ascii;
            }
            None => update_log_file(log_file_path, "Can't find matching key"),
        };
        // check if key is less than u16 then shift
        unsafe {
            let key_json: i16 = VkKeyScanW(key_from_json);
            if (key_from_json >> 8 & 1) == 1 {
                // let mut shift_key_state:i16 = GetKeyState(20);

                if hold_shift {
                    send_multi_input_messages_from_i16(16, key_json, delay)
                } else {
                    send_input_messages(20, true, true);
                    // std::thread::sleep(std::time::Duration::from_millis(22));
                    send_input_messages_from_i16(key_json, true, true);
                    // shift_key_state = GetKeyState(20);
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                    // println!("SHIFT STATE SHOULD BE 1 part 2: {:?}", shift_key_state);
                    send_input_messages(20, true, true)
                }
            } else {
                if hold_shift {
                    send_multi_input_messages_from_i16(16, key_json, delay)
                } else {
                    send_input_messages_from_i16(key_json, true, true)
                }
            }
        }
        // std::thread::sleep(std::time::Duration::from_millis(100))
    });
}
fn get_key_state(key_code: i32) -> bool {
    unsafe {
        let key_state: i16 = GetAsyncKeyState(key_code);
        if key_state != 0 {
            true
        } else {
            false
        }
    }
}
fn check_for_length_time_and_date(date_or_time: u16) -> String {
    if date_or_time < 10 {
        format!("0{}", date_or_time)
    } else {
        format!("{}", date_or_time)
    }
}
fn update_log_file(log_file_path: &str, additional_data: &str) {
    let mut _current_system_time: SYSTEMTIME = SYSTEMTIME {
        ..Default::default()
    };
    unsafe {
        _current_system_time = GetLocalTime();
    }
    let log_time: String = format!(
        "\n[{}:{}:{}:{}]:",
        check_for_length_time_and_date(_current_system_time.wHour),
        check_for_length_time_and_date(_current_system_time.wMinute),
        check_for_length_time_and_date(_current_system_time.wSecond),
        check_for_length_time_and_date(_current_system_time.wMilliseconds)
    );
    let mut _data_from_log_file: File = File::open(&log_file_path).expect("Error reading file");
    let mut data_from_log_file: String = String::new();
    let _ = _data_from_log_file.read_to_string(&mut data_from_log_file);

    fs::write(
        format!(".\\{}", &log_file_path),
        format!("{}{} {}", &data_from_log_file, &log_time, &additional_data),
    )
    .expect("Error");
}
fn get_current_window_heading_text(log_file_path: &str) -> String {
    let mut _window_text: Vec<u8> = vec![0; 1500];
    // let mut _window_text_u_16: Vec<u16> = vec![0; 150];

    // unsafe {
    //     let _ = SetActiveWindow(_current_window);
    //     let _ = SetForegroundWindow(_current_window);
    // }
    unsafe {
        let for_ground_window: HWND = GetForegroundWindow();
        // let _ = SetForegroundWindow(for_ground_window);
        let _ = SetActiveWindow(for_ground_window);
        let _ = GetWindowTextA(for_ground_window, &mut _window_text);
    }
    std::thread::sleep(std::time::Duration::from_millis(5));

    let mut result_window_text: String =
        String::from_utf8(_window_text).expect("Unable to export to string");
    // let mut result_window_text_u_16: String = String::from_utf16_lossy(&_window_text_u_16);
    // result_window_text_u_16 = String::from(resultl_window_text_u_16);
    // println!("result_window_text_u_16 {:?}", resut_window_text_u_16);
    result_window_text = String::from(result_window_text.trim_matches(char::from(0)));
    // println!("Current Window Text: {}", result_window_text);
    update_log_file(
        &log_file_path,
        format!("Current Window Text: {}", result_window_text).as_str(),
    );
    result_window_text
}
fn get_current_window_heading_text_by_handle(handle: HWND) -> String {
    let mut _window_text: Vec<u8> = vec![0; 1500];
    // let mut _window_text_u_16: Vec<u16> = vec![0; 150];

    // unsafe {
    //     let _ = SetActiveWindow(_current_window);
    //     let _ = SetForegroundWindow(_current_window);
    // }
    unsafe {
        let _ = GetWindowTextA(handle, &mut _window_text);
    }
    std::thread::sleep(std::time::Duration::from_millis(5));

    let mut result_window_text: String =
        String::from_utf8(_window_text).expect("Unable to export to string");
    // let mut result_window_text_u_16: String = String::from_utf16_lossy(&_window_text_u_16);
    // result_window_text_u_16 = String::from(resultl_window_text_u_16);
    // println!("result_window_text_u_16 {:?}", resut_window_text_u_16);
    result_window_text = String::from(result_window_text.trim_matches(char::from(0)));
    // println!("Current Window Text: {}", result_window_text);

    result_window_text
}
fn mouse_input(key: &Steps, log_file_path: &str) {
    // std::thread::sleep(std::time::Duration::from_millis(100));
    match &key.code {
        801 => {
            update_log_file(
                &log_file_path,
                format!("Mouse Left Click, Key Code: {}", &key.code).as_str(),
            );
            send_mouse_input_message(0, 0, false, 0x01, key.held, &log_file_path)
        }
        802 => {
            update_log_file(
                &log_file_path,
                format!("Mouse Right Click, Key Code: {}", &key.code).as_str(),
            );
            send_mouse_input_message(0, 0, false, 0x02, key.held, &log_file_path)
        }
        804 => {
            if !String::is_empty(&key.sentence) {
                std::thread::sleep(std::time::Duration::from_millis(10));
                let mouse_coords = &key.sentence.split(",").collect::<Vec<&str>>();
                update_log_file(
                    &log_file_path,
                    format!(
                        "Mouse Movement Coords: \"{}\", Key Code: {}",
                        &key.sentence, &key.code
                    )
                    .as_str(),
                );
                send_mouse_input_message(
                    mouse_coords[0]
                        .parse::<i32>()
                        .expect("Failed to parse - Coords 0"),
                    mouse_coords[1]
                        .parse::<i32>()
                        .expect("Failed to parse - Coords 1"),
                    true,
                    0,
                    key.held,
                    &log_file_path,
                )
            }
        }
        _ => return,
    }
    // std::thread::sleep(std::time::Duration::from_millis(100));
}
fn run_steps(
    loops: usize,
    hold_keys_vector_steps: Vec<Steps>,
    log_file_path: &str,
    mut _current_system_time: SYSTEMTIME,
    website: bool,
    mut _program: String,
    mut _result_window_text: String,
    _read_csv_file: bool,
    csv_lines: Vec<&str>,
    keys_json: &Keys,
    data: &Macro,
    run_steps_number: usize,
) {
    let _mouse_movements: Vec<Steps> = Vec::new();
    for i in 0..loops {
        // if _current_system_time.wHour > 14 {
        //     unsafe {
        //         let _ = LockWorkStation();
        //         std::process::exit(0x000)
        //         // let _ = InitiateSystemShutdownA(None,None,0,true, false);
        //         // let _ = InitiateShutdownA(None,None,0,SHUTDOWN_FORCE_OTHERS|SHUTDOWN_GRACE_OVERRIDE,SHTDN_REASON_FLAG_PLANNED);
        //     }
        // }
        if get_key_state(162) && get_key_state(91) {
            std::process::exit(0x000)
        }
        unsafe {
            _current_system_time = GetLocalTime();
        }
        update_log_file(
            &log_file_path,
            format!(
                "Starting Current Loop Iteration: {} of {}. TIME STARTED: {}:{}:{}",
                (i + 1),
                loops,
                _current_system_time.wMinute,
                _current_system_time.wSecond,
                _current_system_time.wMilliseconds
            )
            .as_str(),
        );
        if i > 0 {
            if website {
                // let _ = execute_command(
                //     "cmd",
                //     &["/C", "start msedge --new-window -incognito", &_program],
                // );
                // let _ = execute_command(
                //     "cmd",
                //     &["/C", "start msedge --new-window -inprivate", &_program],
                // );
                let _ = execute_command("cmd", &["/C", "start msedge --new-window", &_program]);
                _result_window_text = get_current_window_heading_text(&log_file_path);
                update_log_file(
                    &log_file_path,
                    format!("Opening Website: {}", &_program).as_str(),
                );
            } else {
                if !String::eq(&_program, "app") {
                    let _ = execute_command(
                        "cmd",
                        &["/C", "start", format!("{}.exe", &_program).as_str()],
                    );
                    update_log_file(
                        &log_file_path,
                        format!("Opening Website: {}.exe", &_program).as_str(),
                    );
                    _result_window_text = get_current_window_heading_text(&log_file_path);
                }
            }
        }
        let mut _current_csv_index: usize = 0;
        for _ in 0..run_steps_number {
            for (_, key) in hold_keys_vector_steps.iter().enumerate() {
                for _ in 0..key.r#loop {
                    // println!("{}", j);
                    // std::thread::sleep(std::time::Duration::from_millis(1));
                    let result_window_title_main: String =
                        get_current_window_heading_text(&log_file_path);
                    println!("GET CURRENT WINDOW: {}", result_window_title_main);
                    unsafe {
                        let _system_metrics_x: i32 = GetSystemMetrics(SM_CXSCREEN);
                        let _system_metrics_y: i32 = GetSystemMetrics(SM_CYSCREEN);
                        println!(
                            "System Metrics: {} x {}",
                            _system_metrics_x, _system_metrics_y
                        );
                    }
                    println!("RESULT MAIN: {:?}", result_window_title_main);

                    if key.held && key.code < 800 {
                        // Key hold for keyboard
                        update_log_file(
                            &log_file_path,
                            format!("Holding Key: {}", key.name).as_str(),
                        );
                        send_input_messages(key.code, false, true)
                        // holding_keys_to_release.push(key.code)
                    } else if key.code == 987 {
                        // Command execute
                        update_log_file(
                            &log_file_path,
                            format!("Running Command: ({})", &key.sentence).as_str(),
                        );
                        let output: Result<Output, io::Error> =
                            execute_command("cmd", &["/C", &key.sentence]);
                        // println!("{:?}", output);
                        match output {
                            Ok(o) => update_log_file(
                                &log_file_path,
                                format!(
                                    "Command Output: {:?}. Command Status: {}",
                                    str::from_utf8(&o.stdout),
                                    &o.status
                                )
                                .as_str(),
                            ),
                            Err(e) => update_log_file(
                                &log_file_path,
                                format!(
                                    "Error Running Command: {}, Sentence: {}",
                                    e, &key.sentence
                                )
                                .as_str(),
                            ),
                        }
                    } else if key.code > 800 && key.code < 850 {
                        // Mouse events
                        mouse_input(key, &log_file_path);
                    } else if key.code == 999 {
                        // Wait
                        update_log_file(
                            &log_file_path,
                            format!("Waiting for: {} seconds", key.time).as_str(),
                        );
                        std::thread::sleep(std::time::Duration::from_millis(key.time.into()))
                    } else if key.code == 998
                        || key.code == 997
                        || key.code == 996
                        || key.code == 995
                    {
                        /*
                            998 = Normal sentence
                            997 = Base 64 string convert
                            996 = Get Caret Postition & JavaScript
                            995 = Add Strings from CSV based on num in sentence
                        */
                        if key.code == 995 {
                            if _read_csv_file {
                                if i == csv_lines.iter().count() {
                                    return;
                                }
                                let _csv_string_array: Vec<&str> =
                                    csv_lines[i].split(",").collect();
                                // let _ = _csv_string_array.remove(0);
                                let code_to_check_csv: usize = _csv_string_array.iter().count();

                                // let mut _csv_string_array:Vec<&str> = vec![];
                                /*
                                    {
                                        "name":"Sentence",
                                        "code": 995,
                                        "sentence": "1",
                                        "held": false,
                                        "time": 0,
                                        "loop": 1
                                    }

                                    potentially works. parses sentence as index of csv line
                                */
                                if _csv_string_array.iter().count() == 1 {
                                    return;
                                } else {
                                    // println!("Code to check CSV: {:?}, current index {}, csv lines count: {}",_csv_string_array, i, csv_lines.iter().count());
                                    update_log_file(
                                    &log_file_path,
                                    format!(
                                        "Getting item in csv data: \"{}\", Sentence: {}, Key Name: {}, Key Code: {}",
                                        _csv_string_array[_current_csv_index], &key.sentence, &key.name, &key.code
                                    )
                                    .as_str(),
                                );
                                    add_sentence(
                                        _csv_string_array[_current_csv_index],
                                        &key.code,
                                        &keys_json,
                                        &log_file_path,
                                        data.word_delay,
                                    );
                                    if code_to_check_csv == _current_csv_index {
                                        _current_csv_index = 0;
                                    } else {
                                        _current_csv_index += 1;
                                    }
                                }
                            }
                        } else {
                            if key.code != 997 {
                                update_log_file(
                                    &log_file_path,
                                    format!(
                                        "Adding sentence: \"{}\", Key Name: {}, Key Code: {}",
                                        &key.sentence, &key.name, &key.code
                                    )
                                    .as_str(),
                                );
                            } else {
                                update_log_file(
                                    &log_file_path,
                                    format!(
                                        "Adding sentence, Key Name: {}, Key Code: {}",
                                        &key.name, &key.code
                                    )
                                    .as_str(),
                                );
                            }
                            add_sentence(
                                &key.sentence,
                                &key.code,
                                &keys_json,
                                &log_file_path,
                                data.word_delay,
                            );
                        }
                    } else if key.code == 994 {
                        // Window Title
                        let mut get_current_window_text_for_loop: String =
                            get_current_window_heading_text(&log_file_path);
                        if key.name.contains("Check") {
                            // println!("CHECK CONDITION");
                            update_log_file(
                            &log_file_path,
                            format!(
                                "Starting Current Loop to try and find Title: {}. TIME STARTED: {}:{}:{}",
                                key.sentence,
                                _current_system_time.wMinute,
                                _current_system_time.wSecond,
                                _current_system_time.wMilliseconds
                            )
                            .as_str(),
                        );
                            let mut time_out: u32 = 0;
                            loop {
                                std::thread::sleep(std::time::Duration::from_millis(500));
                                get_current_window_text_for_loop =
                                    get_current_window_heading_text(&log_file_path);
                                // println!(
                                //     "SLEEPING: {}, SENTENCE: {}",
                                //     get_current_window_text_for_loop, key.sentence
                                // );
                                time_out += 500;
                                // println!("LOOP TIME OUT: {}", time_out);
                                if time_out > 20000 {
                                    // println!("Timed out");
                                    std::process::exit(0x000)
                                }
                                if get_current_window_text_for_loop.contains(key.sentence.as_str())
                                {
                                    // println!(
                                    //     "CURRENT WINDOW: {}",
                                    //     get_current_window_text_for_loop
                                    // );
                                    break;
                                }
                            }
                        }
                        if key.name.contains("Skip") {
                            get_current_window_text_for_loop =
                                get_current_window_heading_text(&log_file_path);
                            let split_key_name_by_hyphen: Vec<&str> = key.name.split("-").collect();
                            // println!(
                            //     "HITTING SKIP {}, SENTENCE: {} SPLIT {}, NAME: {}",
                            //     key.name,
                            //     key.sentence,
                            //     split_key_name_by_hyphen[1],
                            //     get_current_window_text_for_loop
                            // );
                            if get_current_window_text_for_loop
                                .contains(split_key_name_by_hyphen[1])
                                || get_current_window_text_for_loop.to_lowercase().trim()
                                    == split_key_name_by_hyphen[1].to_lowercase().trim()
                            {
                                let sentence_key_split_new_line: Vec<&str> =
                                    key.sentence.split("\n").collect();
                                let key_code_in_sentence: usize =
                                    sentence_key_split_new_line.iter().count();
                                let mut keys_loop_press_vec: Vec<u16> = vec![];

                                for key in 0..key_code_in_sentence {
                                    let strings_keys_split_by_hyphen: Vec<&str> =
                                        sentence_key_split_new_line[key].split("-").collect();

                                    // println!(
                                    //     "{}, {}",
                                    //     strings_keys_split_by_hyphen[0]
                                    //         .trim()
                                    //         .parse::<u16>()
                                    //         .unwrap(),
                                    //     strings_keys_split_by_hyphen[1]
                                    //         .trim()
                                    //         .parse::<u16>()
                                    //         .unwrap()
                                    // );
                                    for _ in 0..strings_keys_split_by_hyphen[1]
                                        .trim()
                                        .parse::<u16>()
                                        .unwrap()
                                    {
                                        keys_loop_press_vec.push(
                                            strings_keys_split_by_hyphen[0]
                                                .trim()
                                                .parse::<u16>()
                                                .unwrap(),
                                        );
                                    }
                                }
                                // println!("keys_loop_press_vec {:?}", keys_loop_press_vec);
                                for key_in_loop_skip in keys_loop_press_vec {
                                    std::thread::sleep(std::time::Duration::from_millis(500));
                                    send_input_messages(key_in_loop_skip, true, true);
                                }
                            }
                        }
                        if key.name.contains("Log") && result_window_title_main.contains("Log") {
                            send_input_messages(162, false, true);
                            send_input_messages(160, false, true);
                            send_input_messages(74, true, true);
                            std::thread::sleep(std::time::Duration::from_millis(1000));
                            send_input_messages(162, true, true);
                            send_input_messages(160, true, true);
                            std::thread::sleep(std::time::Duration::from_millis(1000));
                            add_sentence(
                                &key.sentence,
                                &key.code,
                                &keys_json,
                                &log_file_path,
                                data.word_delay,
                            );
                            std::thread::sleep(std::time::Duration::from_millis(1000));
                            send_input_messages(13, true, true);
                            std::thread::sleep(std::time::Duration::from_millis(1000));
                            send_input_messages(162, false, true);
                            send_input_messages(160, false, true);
                            send_input_messages(74, true, true);
                            std::thread::sleep(std::time::Duration::from_millis(1000));
                            send_input_messages(162, true, true);
                            send_input_messages(160, true, true);
                            std::thread::sleep(std::time::Duration::from_millis(1000))
                        }
                        if key.name.contains("Log") && !result_window_title_main.contains("Log")
                            || !result_window_title_main.contains(&key.name)
                        {
                            // println!("Not Current Screen")
                        } else {
                            // println!(
                            //     "660:- RESULT TITLE: {:?}, sentence {}",
                            //     result_window_title_main, &key.sentence
                            // );
                            send_input_messages(162, false, true);
                            send_input_messages(160, false, true);
                            send_input_messages(74, true, true);
                            std::thread::sleep(std::time::Duration::from_millis(1000));
                            send_input_messages(162, true, true);
                            send_input_messages(160, true, true);
                            std::thread::sleep(std::time::Duration::from_millis(1000));
                            add_sentence(
                                &key.sentence,
                                &key.code,
                                &keys_json,
                                &log_file_path,
                                data.word_delay,
                            );
                            std::thread::sleep(std::time::Duration::from_millis(1000));
                            send_input_messages(13, true, true);
                            std::thread::sleep(std::time::Duration::from_millis(2000));
                            send_input_messages(162, false, true);
                            send_input_messages(160, false, true);
                            send_input_messages(74, true, true);
                            std::thread::sleep(std::time::Duration::from_millis(1000));
                            send_input_messages(162, true, true);
                            send_input_messages(160, true, true)
                        }
                    } else if key.code == 993 {
                        // Clipboard
                        unsafe {
                            let clipboard: Result<(), windows::core::Error> = OpenClipboard(None);
                            match clipboard {
                                Err(e) => update_log_file(
                                    &log_file_path,
                                    format!("Error opening Clipboard: {}", e).as_str(),
                                ),
                                Ok(_) => {
                                    let _ = SetClipboardData(0x001, None);
                                    let clipboard_data = GetClipboardData(0x001);
                                    // println!("{:?}", clipboard_data);
                                    let _ = CloseClipboard();
                                }
                            }
                        }
                    } else if key.code == 992 {
                        // login exit
                        std::thread::sleep(std::time::Duration::from_millis(2500));
                        let result_window_title: String =
                            get_current_window_heading_text(&log_file_path);
                        if result_window_title.contains(&key.name) {
                            update_log_file(
                                &log_file_path,
                                format!("On Page, exited, {}", &key.name).as_str(),
                            );
                            std::process::exit(0x000)
                        } else {
                            continue;
                        }
                    } else {
                        update_log_file(
                            &log_file_path,
                            format!("Pressing key: {} with code: {}", key.name, key.code).as_str(),
                        );
                        send_input_messages(key.code, true, true)
                    }
                }
            }
        }

        unsafe {
            _current_system_time = GetLocalTime();
        }
        update_log_file(
            &log_file_path,
            format!(
                "Ended Current Loop Iteration: {} of {}. TIME ENDED THIS LOOP: {}:{}:{}\n",
                (i + 1),
                loops,
                _current_system_time.wMinute,
                _current_system_time.wSecond,
                _current_system_time.wMilliseconds
            )
            .as_str(),
        );
        std::thread::sleep(std::time::Duration::from_millis(data.delay_for_each_loop));
    }
}
fn run_only_steps(
    steps_vec: &Vec<Steps>,
    log_file_path: &str,
    mut _current_system_time: SYSTEMTIME,
    mut _program: &String,
    mut _result_window_text: &String,
    _read_csv_file: bool,
    csv_lines: &Vec<&str>,
    keys_json: &Keys,
    data: &Macro,
    run_steps_number: usize,
) {
    let _mouse_movements: Vec<Steps> = Vec::new();
    let mut _current_csv_index: usize = 0;
    for i in 0..run_steps_number {
        for (_, key) in steps_vec.iter().enumerate() {
            for _ in 0..key.r#loop {
                // println!("{}", j);
                // std::thread::sleep(std::time::Duration::from_millis(1));
                let result_window_title_main: String =
                    get_current_window_heading_text(&log_file_path);
                unsafe {
                    let _system_metrics_x: i32 = GetSystemMetrics(SM_CXSCREEN);
                    let _system_metrics_y: i32 = GetSystemMetrics(SM_CYSCREEN);
                    println!(
                        "System Metrics: {} x {}",
                        _system_metrics_x, _system_metrics_y
                    );
                }
                println!("RESULT MAIN: {:?}", result_window_title_main);

                if key.held && key.code < 800 {
                    // Key hold for keyboard
                    update_log_file(
                        &log_file_path,
                        format!("Holding Key: {}", key.name).as_str(),
                    );
                    send_input_messages(key.code, false, true)
                    // holding_keys_to_release.push(key.code)
                } else if key.code == 987 {
                    // Command execute
                    update_log_file(
                        &log_file_path,
                        format!("Running Command: ({})", &key.sentence).as_str(),
                    );
                    let output: Result<Output, io::Error> =
                        execute_command("cmd", &["/C", &key.sentence]);
                    // println!("{:?}", output);
                    match output {
                        Ok(o) => update_log_file(
                            &log_file_path,
                            format!(
                                "Command Output: {:?}. Command Status: {}",
                                str::from_utf8(&o.stdout),
                                &o.status
                            )
                            .as_str(),
                        ),
                        Err(e) => update_log_file(
                            &log_file_path,
                            format!("Error Running Command: {}, Sentence: {}", e, &key.sentence)
                                .as_str(),
                        ),
                    }
                } else if key.code > 800 && key.code < 850 {
                    // Mouse events
                    mouse_input(key, &log_file_path);
                } else if key.code == 999 {
                    // Wait
                    update_log_file(
                        &log_file_path,
                        format!("Waiting for: {} seconds", key.time).as_str(),
                    );
                    std::thread::sleep(std::time::Duration::from_millis(key.time.into()))
                } else if key.code == 998 || key.code == 997 || key.code == 996 || key.code == 995 {
                    /*
                        998 = Normal sentence
                        997 = Base 64 string convert
                        996 = Get Caret Postition & JavaScript
                        995 = Add Strings from CSV based on num in sentence
                    */
                    if key.code == 995 {
                        if _read_csv_file {
                            if csv_lines[i].len() > 0 {
                                let key_name_split: &Vec<&str> =
                                    &key.name.split(",").collect::<Vec<&str>>();
                                let mut split_key_name_into_int: [u16; 2] = [0; 2];
                                split_key_name_into_int[0] = key_name_split[0]
                                    .parse::<u16>()
                                    .expect("Failed to parse int");
                                split_key_name_into_int[1] = key_name_split[1]
                                    .parse::<u16>()
                                    .expect("Failed to parse int");
                                let _csv_string_array: Vec<&str> = csv_lines
                                    [(split_key_name_into_int[0] as usize) + i]
                                    .split(",")
                                    .collect();
                                println!(
                                    "SPLIT KEY NAME: 1: ({}), 2: ({}): ITEM: {}: INDEX: {}",
                                    split_key_name_into_int[0],
                                    split_key_name_into_int[1],
                                    (split_key_name_into_int[0] as usize) + i,
                                    i
                                );
                                println!("CSV LINES WITH INDEX: {:?}", csv_lines[i]);
                                update_log_file(
                                        &log_file_path,
                                        format!(
                                            "Getting item in csv data: \"{}\", Sentence: {}, Key Name: {}, Key Code: {}",
                                            _csv_string_array[split_key_name_into_int[1] as usize], &key.sentence, &key.name, &key.code
                                        )
                                        .as_str(),
                                    );
                                add_sentence(
                                    _csv_string_array[split_key_name_into_int[1] as usize],
                                    &key.code,
                                    &keys_json,
                                    &log_file_path,
                                    data.word_delay,
                                );
                            }
                        }
                    } else {
                        if key.code != 997 {
                            update_log_file(
                                &log_file_path,
                                format!(
                                    "Adding sentence: \"{}\", Key Name: {}, Key Code: {}",
                                    &key.sentence, &key.name, &key.code
                                )
                                .as_str(),
                            );
                        } else {
                            update_log_file(
                                &log_file_path,
                                format!(
                                    "Adding sentence, Key Name: {}, Key Code: {}",
                                    &key.name, &key.code
                                )
                                .as_str(),
                            );
                        }
                        add_sentence(
                            &key.sentence,
                            &key.code,
                            &keys_json,
                            &log_file_path,
                            data.word_delay,
                        );
                    }
                } else if key.code == 994 {
                    // Window Title
                    let mut get_current_window_text_for_loop: String =
                        get_current_window_heading_text(&log_file_path);
                    if key.name.contains("Check") {
                        // println!("CHECK CONDITION");
                        update_log_file(
                            &log_file_path,
                            format!(
                                "Starting Current Loop to try and find Title: {}. TIME STARTED: {}:{}:{}",
                                key.sentence,
                                _current_system_time.wMinute,
                                _current_system_time.wSecond,
                                _current_system_time.wMilliseconds
                            )
                            .as_str(),
                        );
                        let mut time_out: u32 = 0;
                        loop {
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            get_current_window_text_for_loop =
                                get_current_window_heading_text(&log_file_path);
                            // println!(
                            //     "SLEEPING: {}, SENTENCE: {}",
                            //     get_current_window_text_for_loop, key.sentence
                            // );
                            time_out += 500;
                            // println!("LOOP TIME OUT: {}", time_out);
                            if time_out > 20000 {
                                // println!("Timed out");
                                std::process::exit(0x000)
                            }
                            if get_current_window_text_for_loop.contains(key.sentence.as_str()) {
                                // println!("CURRENT WINDOW: {}", get_current_window_text_for_loop);
                                break;
                            }
                        }
                    }
                    if key.name.contains("Skip") {
                        get_current_window_text_for_loop =
                            get_current_window_heading_text(&log_file_path);
                        let split_key_name_by_hyphen: Vec<&str> = key.name.split("-").collect();
                        // println!(
                        //     "HITTING SKIP {}, SENTENCE: {} SPLIT {}, NAME: {}",
                        //     key.name,
                        //     key.sentence,
                        //     split_key_name_by_hyphen[1],
                        //     get_current_window_text_for_loop
                        // );
                        if get_current_window_text_for_loop.contains(split_key_name_by_hyphen[1])
                            || get_current_window_text_for_loop.to_lowercase().trim()
                                == split_key_name_by_hyphen[1].to_lowercase().trim()
                        {
                            let sentence_key_split_new_line: Vec<&str> =
                                key.sentence.split("\n").collect();
                            let key_code_in_sentence: usize =
                                sentence_key_split_new_line.iter().count();
                            let mut keys_loop_press_vec: Vec<u16> = vec![];

                            for key in 0..key_code_in_sentence {
                                let strings_keys_split_by_hyphen: Vec<&str> =
                                    sentence_key_split_new_line[key].split("-").collect();

                                // println!(
                                //     "{}, {}",
                                //     strings_keys_split_by_hyphen[0]
                                //         .trim()
                                //         .parse::<u16>()
                                //         .unwrap(),
                                //     strings_keys_split_by_hyphen[1]
                                //         .trim()
                                //         .parse::<u16>()
                                //         .unwrap()
                                // );
                                for _ in 0..strings_keys_split_by_hyphen[1]
                                    .trim()
                                    .parse::<u16>()
                                    .unwrap()
                                {
                                    keys_loop_press_vec.push(
                                        strings_keys_split_by_hyphen[0]
                                            .trim()
                                            .parse::<u16>()
                                            .unwrap(),
                                    );
                                }
                            }
                            // println!("keys_loop_press_vec {:?}", keys_loop_press_vec);
                            for key_in_loop_skip in keys_loop_press_vec {
                                std::thread::sleep(std::time::Duration::from_millis(500));
                                send_input_messages(key_in_loop_skip, true, true);
                            }
                        }
                    }
                    if key.name.contains("Log") && result_window_title_main.contains("Log") {
                        send_input_messages(162, false, true);
                        send_input_messages(160, false, true);
                        send_input_messages(74, true, true);
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        send_input_messages(162, true, true);
                        send_input_messages(160, true, true);
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        add_sentence(
                            &key.sentence,
                            &key.code,
                            &keys_json,
                            &log_file_path,
                            data.word_delay,
                        );
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        send_input_messages(13, true, true);
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        send_input_messages(162, false, true);
                        send_input_messages(160, false, true);
                        send_input_messages(74, true, true);
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        send_input_messages(162, true, true);
                        send_input_messages(160, true, true);
                        std::thread::sleep(std::time::Duration::from_millis(1000))
                    }
                    if key.name.contains("Log") && !result_window_title_main.contains("Log")
                        || !result_window_title_main.contains(&key.name)
                    {
                        // println!("Not Current Screen")
                    } else {
                        // println!(
                        //     "660:- RESULT TITLE: {:?}, sentence {}",
                        //     result_window_title_main, &key.sentence
                        // );
                        send_input_messages(162, false, true);
                        send_input_messages(160, false, true);
                        send_input_messages(74, true, true);
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        send_input_messages(162, true, true);
                        send_input_messages(160, true, true);
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        add_sentence(
                            &key.sentence,
                            &key.code,
                            &keys_json,
                            &log_file_path,
                            data.word_delay,
                        );
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        send_input_messages(13, true, true);
                        std::thread::sleep(std::time::Duration::from_millis(2000));
                        send_input_messages(162, false, true);
                        send_input_messages(160, false, true);
                        send_input_messages(74, true, true);
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        send_input_messages(162, true, true);
                        send_input_messages(160, true, true)
                    }
                } else if key.code == 993 {
                    // Clipboard
                    unsafe {
                        let clipboard: Result<(), windows::core::Error> = OpenClipboard(None);
                        match clipboard {
                            Err(e) => update_log_file(
                                &log_file_path,
                                format!("Error opening Clipboard: {}", e).as_str(),
                            ),
                            Ok(_) => {
                                let _ = SetClipboardData(0x001, None);
                                let clipboard_data = GetClipboardData(0x001);
                                // println!("{:?}", clipboard_data);
                                let _ = CloseClipboard();
                            }
                        }
                    }
                } else if key.code == 992 {
                    // login exit
                    std::thread::sleep(std::time::Duration::from_millis(2500));
                    let result_window_title: String =
                        get_current_window_heading_text(&log_file_path);
                    if result_window_title.contains(&key.name) {
                        update_log_file(
                            &log_file_path,
                            format!("On Page, exited, {}", &key.name).as_str(),
                        );
                        std::process::exit(0x000)
                    } else {
                        continue;
                    }
                } else if key.code == 991 {
                    unsafe {
                        // let com_initialise = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
                        // // println!("COM: {:?}", com_initialise);
                        // std::thread::sleep(std::time::Duration::from_millis(2500));
                        // let _ = CoUninitialize();
                        let points: POINT = POINT { x: 500, y: 250 };
                        // let real_child_window = RealChildWindowFromPoint(GetActiveWindow(), points);

                        // let dlg_item: HWND = GetWindow(for_ground_window_test, GW_HWNDLAST);
                        // let child_window_title: String =
                        //     get_current_window_heading_text_by_handle(real_child_window);
                        // println!("CHILD WINDOW TITLE: {}", child_window_title);
                        let get_child_test_window = GetWindow(GetFocus(), GW_OWNER);
                        let check_child_window = IsChild(GetActiveWindow(), get_child_test_window);
                        println!("CHILD WINDOW? {:?}", check_child_window);
                    }
                    std::process::exit(0x000)
                } else {
                    update_log_file(
                        &log_file_path,
                        format!("Pressing key: {} with code: {}", key.name, key.code).as_str(),
                    );
                    send_input_messages(key.code, true, true)
                }
            }
        }
    }

    unsafe {
        _current_system_time = GetLocalTime();
    }
}
