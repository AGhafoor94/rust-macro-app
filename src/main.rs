use std::{
    env::args,
    fs::{self, DirEntry, File, FileType},
    io::{self, Read},
    path::Path,
    process::Output
};
use serde::{Deserialize, Serialize};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
// cargo build --release app.exe
// #![windows_subsystem = "windows"]
use reqwest::header::HeaderMap;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use windows::Win32::{
    Foundation::*,
    System::{
        DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard, SetClipboardData},
        Shutdown::{LockWorkStation, InitiateShutdownA,SHUTDOWN_FORCE_OTHERS,SHUTDOWN_GRACE_OVERRIDE,SHTDN_REASON_FLAG_PLANNED},
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
    delay_for_each_loop:u64
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct App {
    app_value: String,
    website_open: bool,
    steps: Vec<Steps>,
}
#[derive(Serialize, Deserialize)]
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
    let log_file_path:String = format!(
        "Log File {}-{}-{}.txt",
        check_for_length_time_and_date(_current_system_time.wDay),
        check_for_length_time_and_date(_current_system_time.wMonth),
        _current_system_time.wYear
    );
    let mut _log_file: Result<File, io::Error> = File::open(&log_file_path);
    // let graph_token: GraphToken = get_token().await?;
    let mut keys_buffer: String = String::new();
    // std::thread::sleep(std::time::Duration::from_millis(500));
    // let graph_user: GraphUserDetails = get_user_details_graph(graph_token.access_token).await?;
    // println!("{:?}", graph_user);
    let _ = File::open(".\\keys.json").unwrap().read_to_string(&mut keys_buffer);
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
    let _ = File::open(format!(".\\marcos\\{name}.json", name = &args[1].trim())).unwrap().read_to_string(&mut buffer);
    let data: Macro = serde_json::from_str(&buffer).expect("Not found");
    let app: Vec<App> = data.app;
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
            update_log_file(&log_file_path,format!("File didn't exist. Created log file: {}", e).as_str())
        }
        _ => update_log_file(&log_file_path,"Log file created")
    }

    update_log_file(
        &log_file_path,
        format!("Using file: {}.json", &args[1].trim()).as_str(),
        // format!("Using file: {}.json", &file_name.trim()).as_str(),
    );
    // let _ = file.read_to_string(&mut buffer);
    // println!("{:?}",&buffer);

    let mut loops:usize = data.r#loop;
    // let virtual_keys_vec:Vec<u16> = vec![0x5B,0x90,0x91,0x14];
    let mut hold_keys_vector_steps: Vec<Steps> = Vec::new();
    // let mut hold_keys_vector:Vec<u16> = Vec::new();
    // let _virtual_keys_vector: Vec<u16> = Vec::new();
    let mut _program: String = String::new();
    let mut website: bool = false;
    let continue_app: bool = true;
    let mut csv_lines:Vec<&str> = vec![];
    let mut _read_csv_file:bool = false;
    let mut buffer_csv_lines:String = String::new();
    
    if !&data.read_csv.is_empty() {
        _read_csv_file = true;
        let csv_file:Result<File, io::Error> = File::open(&data.read_csv);
        match csv_file {
            Ok(v) => {
                
                let mut lines_to_read: io::BufReader<File> = std::io::BufReader::new(v);
                let _ = &lines_to_read.read_to_string(&mut buffer_csv_lines);
            },
            Err(e) => {
                update_log_file(
                    &log_file_path,
                    format!("Error trying to read csv file ({}): {}", &data.read_csv, e).as_str(),
                );
                return Ok(())
            }
        }
        // let _ = &buffer_csv_lines.split("\r\n").into_iter().for_each(|line| println!("{}", line));
        loops = buffer_csv_lines.split("\r\n").clone().count();
        csv_lines = buffer_csv_lines.split("\r\n").collect();
        // let _ = csv_lines.remove(0);
        update_log_file(&log_file_path,format!("Number of loops updated from {} to {}", &data.r#loop, &loops).as_str());
    }
    // println!("{}", log_date);
    if !continue_app {
        std::process::exit(0x000)
    }
    if !&data.hotkey.is_empty() {
        // println!("{:?}", data.hotkey.split(','));
        // let split_comma_count = data.hotkey.split(',').count();
        println!("Waiting for hot keys...");
        let mut hot_keys: Vec<i32> = vec![];
        let _ = &data.hotkey.split(",").into_iter().for_each(|key| hot_keys.push(key.trim().parse::<i32>().expect("Error parsing to i32")));
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
    
    for app in app.into_iter() {
        update_log_file(
            &log_file_path,
            format!(
                "Type of app: {} & Number of steps: {}",
                app.app_value.to_owned(),
                app.steps.len()
            )
            .as_str(),
        );
        if String::eq(&app.app_value, "app") || app.app_value.is_empty() {
            _program = app.app_value.to_owned();
            let _ = app.steps.into_iter().for_each(|step| hold_keys_vector_steps.push(step));
            std::thread::sleep(std::time::Duration::from_millis(250));
        } else {
            if app.website_open {
                _program = app.app_value.to_owned();
                website = true;
                let _ = execute_command(
                    "cmd",
                    &["/C", "start msedge --new-window -incognito", &app.app_value],
                );

                update_log_file(
                    &log_file_path,
                    format!("Opening Website: {}", &app.app_value).as_str(),
                );
                unsafe {
                    let _ = SetActiveWindow(GetForegroundWindow());
                }
                let _ = app.steps.into_iter().for_each(|step| hold_keys_vector_steps.push(step));
                
            } else {
                _program = app.app_value.to_owned();
                let _ = execute_command("cmd", &["/C", "start", format!("{}.exe", &app.app_value).as_str()]);
               
                update_log_file(
                    &log_file_path,
                    format!("Opening File: {}.exe", &app.app_value).as_str(),
                );
                
                let _ = app.steps.into_iter().for_each(|step| hold_keys_vector_steps.push(step));
                
            }
            std::thread::sleep(std::time::Duration::from_millis(1250));
        }
    }
    let mut _current_window: HWND = HWND {
        ..Default::default()
    };
    unsafe {
        _current_window = GetForegroundWindow();
        let _ = SetFocus(_current_window);
    }
    let mut _result_window_text: String =
        get_current_window_heading_text(&log_file_path, _current_window);
    std::thread::sleep(std::time::Duration::from_millis(500));
    // let _ = SetForegroundWindow(_current_window);
    if _result_window_text.to_lowercase().contains("login") {}
    
    let _mouse_movements: Vec<Steps> = Vec::new();
    for i in 0..loops {

        if _current_system_time.wHour == 13 && _current_system_time.wMinute >= 30 {
            unsafe {
                // let _ = LockWorkStation();
                // let _ = InitiateSystemShutdownA(None,None,0,true, false);
                let _ = InitiateShutdownA(None,None,0,SHUTDOWN_FORCE_OTHERS|SHUTDOWN_GRACE_OVERRIDE,SHTDN_REASON_FLAG_PLANNED);
            }
            std::process::exit(0x000)
        }
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
                let _ = execute_command(
                    "cmd",
                    &["/C", "start msedge --new-window -incognito", &_program],
                );
                _result_window_text =
                    get_current_window_heading_text(&log_file_path, _current_window);
                update_log_file(
                    &log_file_path,
                    format!("Opening Website: {}", &_program).as_str(),
                );
            } else {
                if !String::eq(&_program, "app") {
                    let _ = execute_command("cmd", &["/C", "start", format!("{}.exe", &_program).as_str()]);
                    update_log_file(
                        &log_file_path,
                        format!("Opening Website: {}.exe", &_program).as_str(),
                    );
                    _result_window_text =
                        get_current_window_heading_text(&log_file_path, _current_window);
                }
            }
        }
        let mut _current_csv_index:usize = 0;
        for (j, key) in hold_keys_vector_steps.iter().enumerate() {
            for _ in 0..key.r#loop {
                // println!("{}", j);
                // std::thread::sleep(std::time::Duration::from_millis(1));
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
                    match output {
                        Ok(o) => update_log_file(&log_file_path,format!("Command Output: {:?}. Command Status: {}", str::from_utf8(&o.stdout),&o.status).as_str()),
                        Err(e) => update_log_file(&log_file_path,format!("Error Running Command: {}, Sentence: {}", e, &key.sentence).as_str()),
                    }
                } else if key.code > 800 && key.code < 850 {
                    // Mouse events
                    mouse_input(key,&log_file_path);
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
                            if i == csv_lines.iter().count() {
                                return Ok(())
                            }
                            let _csv_string_array:Vec<&str> = csv_lines[i].split(",").collect();
                            // let _ = _csv_string_array.remove(0);
                            let code_to_check_csv:usize = _csv_string_array.iter().count();

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
                                return Ok(())
                            }else {
                                println!("Code to check CSV: {:?}, current index {}, csv lines count: {}",_csv_string_array, i, csv_lines.iter().count());
                                update_log_file(
                                    &log_file_path,
                                    format!(
                                        "Getting item in csv data: \"{}\", Sentence: {}, Key Name: {}, Key Code: {}",
                                        _csv_string_array[_current_csv_index], &key.sentence, &key.name, &key.code
                                    )
                                    .as_str(),
                                );
                                add_sentence(_csv_string_array[_current_csv_index], &key.code, &keys_json, &log_file_path, data.word_delay);
                                if code_to_check_csv == _current_csv_index {
                                    _current_csv_index = 0;
                                }else {
                                    _current_csv_index += 1;
                                }
                            }
                        }
                    }else {
                        if key.code != 997 {
                            update_log_file(
                                &log_file_path,
                                format!(
                                    "Adding sentence: \"{}\", Key Name: {}, Key Code: {}",
                                    &key.sentence, &key.name, &key.code
                                )
                                .as_str(),
                            );
                        }else {
                            update_log_file(
                                &log_file_path,
                                format!(
                                    "Adding sentence, Key Name: {}, Key Code: {}", &key.name, &key.code
                                )
                                .as_str(),
                            );
                        }
                        add_sentence(&key.sentence, &key.code, &keys_json, &log_file_path, data.word_delay);
                    }
                } else if key.code == 994 {
                    // Window Title
                    // std::thread::sleep(std::time::Duration::from_millis(10));

                    let result_window_title: String =
                        get_current_window_heading_text(&log_file_path, _current_window);
                    if !result_window_title.contains(&key.sentence) {
                        send_input_messages(hold_keys_vector_steps[j - 1].code, true, true)
                    }
                } else if key.code == 993 {
                    // Clipboard
                    unsafe {
                        let clipboard: Result<(), windows::core::Error> = OpenClipboard(None);
                        match clipboard {
                            Err(e) => update_log_file(&log_file_path,format!("Error opening Clipboard: {}", e).as_str()),
                            Ok(_) => {
                                let _ = SetClipboardData(0x001, None);
                                let clipboard_data = GetClipboardData(0x001);
                                println!("{:?}", clipboard_data);
                                let _ = CloseClipboard();
                            }
                        }
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
    update_log_file(&log_file_path, "Ended Macro\n\n");
    Ok(())
    // std::process::exit(0x000)
}
fn send_input_messages_from_i16(virtual_key_num: i16, release_key: bool, individial_press: bool) {
    let get_key_state_int:u16 = virtual_key_num as u16;

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
fn send_multi_input_messages_from_i16(virtual_key_num: i16, virtual_key_num_two: i16, delay:u64) {
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
                    true => {
                        unsafe {
                            let _ = SendInput(
                                &[input_release_struct],
                                core::mem::size_of::<INPUT>() as i32,
                            );
                        }
                    }
                    false => println!("Not released"),
                }
            }
            false => {
                unsafe {
                    let _ = SendInput(
                        &[input_release_struct],
                        core::mem::size_of::<INPUT>() as i32,
                    );
                }
            }
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
fn send_mouse_input_message(x: i32, y: i32, move_mouse: bool, mouse_button: u16, held: bool, log_file_path: &str) {
    let mut point_struct: POINT = POINT {
        ..Default::default()
    };
    let mut _system_metrics: i32 = 0;
    let mut _input_mouse_struct: INPUT = INPUT {
        ..Default::default()
    };
    unsafe {
        let _ = GetCursorPos(&mut point_struct);
        _system_metrics = GetSystemMetrics(SM_CXSCREEN);
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
                    // let _ = SendInput(&[_input_mouse_struct],core::mem::size_of::<INPUT>() as i32);
                    _input_mouse_struct = INPUT {
                        r#type: INPUT_TYPE(0),
                        Anonymous: INPUT_0 {
                            mi: MOUSEINPUT {
                                dx: x * (65535 / _system_metrics),
                                dy: y * (65535 / _system_metrics),
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
                                dx: x * (65535 / _system_metrics),
                                dy: y * (65535 / _system_metrics),
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
                _ => update_log_file(log_file_path,format!("Error clicking mouse {}", mouse_button).as_str()),
            }

            println!("582: {:?}", point_struct);
        }
    }
    unsafe {
        let _ = SendInput(&[_input_mouse_struct], core::mem::size_of::<INPUT>() as i32);
    }
        std::thread::sleep(std::time::Duration::from_millis(25));
        match held {
            true => update_log_file(log_file_path,"Mouse button held"),
            false => match move_mouse {
                true => {
                    unsafe {
                        let _ = SendInput(&[_input_mouse_struct], core::mem::size_of::<INPUT>() as i32);
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
                        _ => update_log_file(log_file_path,format!("Error clicking mouse {}", mouse_button).as_str()),
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
        let second_char: String = hex_code[1..].to_owned();
        // println!("{}, {}",first_char, second_char);
        _u16_total_key = first_char.parse::<u16>().unwrap();
        _u16_total_key = _u16_total_key * 16;
        // _u16_total_key = match &second_char as &str {
        //     "A" => _u16_total_key + 10,
        //     "B" => _u16_total_key + 11,
        //     "C" => _u16_total_key + 12,
        //     "D" => _u16_total_key + 13,
        //     "E" => _u16_total_key + 14,
        //     "F" => _u16_total_key + 15,
        //     _ => _u16_total_key + second_char.parse::<u16>().unwrap(),
        // };
        if second_char == "A" || second_char == "a" {
            _u16_total_key = _u16_total_key + 10;
        }else if second_char == "B" || second_char == "b" {
            _u16_total_key = _u16_total_key + 11;
        }else if second_char == "C" || second_char == "c"  {
            _u16_total_key = _u16_total_key + 12;
        }else if second_char == "D" || second_char == "d" {
            _u16_total_key = _u16_total_key + 13;
        }else if second_char == "E" || second_char == "e" {
            _u16_total_key = _u16_total_key + 14;
        }else if second_char == "F" || second_char == "f" {
            _u16_total_key = _u16_total_key + 15;
        }else {
            _u16_total_key = _u16_total_key + second_char.parse::<u16>().unwrap()
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
            None => update_log_file(log_file_path,"Can't find matching key"),
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
        let key_state:i16 = GetAsyncKeyState(key_code);
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
fn get_current_window_heading_text(log_file_path: &str, current_window: HWND) -> String {
    let mut _window_text: Vec<u8> = vec![0; 80];
    unsafe {
        let _ = GetWindowTextA(current_window, &mut _window_text);
    }
    std::thread::sleep(std::time::Duration::from_millis(5));

    let mut result_window_text: String =
        String::from_utf8(_window_text).expect("Unable to export to string");
    result_window_text = String::from(result_window_text.trim_matches(char::from(0)));
    println!("Current Window Text: {}", result_window_text);
    update_log_file(
        &log_file_path,
        format!("Current Window Text: {}", result_window_text).as_str(),
    );
    result_window_text
}
fn mouse_input(key:&Steps, log_file_path: &str) { 
    // std::thread::sleep(std::time::Duration::from_millis(100));
    match &key.code {
        801 => {
            update_log_file(
                &log_file_path,
                format!("Mouse Left Click, Key Code: {}", &key.code).as_str(),
            );
            send_mouse_input_message(
                0,
                0,
                false,
                0x01,
                key.held,
                &log_file_path
            )
        },
        802 => {
            update_log_file(
                &log_file_path,
                format!("Mouse Right Click, Key Code: {}", &key.code).as_str(),
            );
            send_mouse_input_message(
                0,
                0,
                false,
                0x02,
                key.held,
                &log_file_path
            )
        }
        804 => {
            if !String::is_empty(&key.sentence){
                std::thread::sleep(std::time::Duration::from_millis(10));
                let mouse_coords = &key.sentence.split(",").collect::<Vec<&str>>();
                update_log_file(
                    &log_file_path,
                    format!("Mouse Movement Coords: \"{}\", Key Code: {}", &key.sentence, &key.code).as_str(),
                );
                send_mouse_input_message(
                    mouse_coords[0].parse::<i32>().expect("Failed to parse - Coords 0"),
                    mouse_coords[1].parse::<i32>().expect("Failed to parse - Coords 1"),
                    true,
                    0,
                    key.held,
                    &log_file_path
                )
            }
        },
        _ => return
    }
    // std::thread::sleep(std::time::Duration::from_millis(100));
}
