use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use actix_web::{
    dev::ServiceRequest, http::header::ContentType, rt::time::sleep, web, App, HttpResponse,
    HttpServer,
};
use actix_web_httpauth::extractors::basic::{BasicAuth, Config};
use actix_web_httpauth::extractors::AuthenticationError;
use actix_web_httpauth::middleware::HttpAuthentication;
use constant_time_eq::constant_time_eq;
use fscommon::BufStream;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::Deserialize;
use sysinfo::{Pid, ProcessExt, Signal, System, SystemExt};
use thiserror::Error;

#[allow(non_upper_case_globals)]
const KiB: usize = 1024;
#[allow(non_upper_case_globals)]
const MiB: usize = 1024 * KiB;

#[derive(Debug, Error)]
pub enum Error {
    #[error("can't find disk device")]
    NoDiskDev,
    #[error("no private keys found in file")]
    NoPrivateKeys,
    #[error("no rootfs set in active cmdline")]
    RootdevUnset,

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("actix_web error: {0}")]
    ActixWeb(#[from] actix_web::Error),
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Deserialize)]
struct DataRequest {
    path: String,
}

#[derive(Clone, Debug, Deserialize)]
struct KillRequest {
    process: String,
    signal: String,
}

async fn handle_reboot() -> HttpResponse {
    println!("request reboot");

    if let Some(init) = System::new_all().process(Pid::from(1)) {
        init.kill_with(Signal::User1);

        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body("rebooting...")
    } else {
        HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body("can't reboot: no pid1")
    }
}

async fn handle_shutdown() -> HttpResponse {
    println!("request shutdown");

    if let Some(init) = System::new_all().process(Pid::from(1)) {
        init.kill_with(Signal::User2);

        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body("shutting down...")
    } else {
        HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body("can't shut down: no pid1")
    }
}

async fn handle_update_boot(data: web::Bytes) -> HttpResponse {
    println!("update boot");

    let boot = match boot_dev() {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .content_type(ContentType::plaintext())
                .body(format!("can't locate boot partition: {}", e))
        }
    };

    match stream_to(boot, &data).await {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body("successfully updated boot partition"),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't update boot partition: {}", e)),
    }
}

async fn handle_update_mbr(data: web::Bytes) -> HttpResponse {
    println!("update mbr");

    let mbr = match dev() {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .content_type(ContentType::plaintext())
                .body(format!("can't locate disk device: {}", e))
        }
    };

    match stream_to(mbr, &data).await {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body("successfully updated mbr"),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't update mbr: {}", e)),
    }
}

async fn handle_update_root(data: web::Bytes) -> HttpResponse {
    println!("update inactive root");

    let root = match inactive_root() {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .content_type(ContentType::plaintext())
                .body(format!("can't locate inactive root partition: {}", e))
        }
    };

    match stream_to(&root, &data).await {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body("successfully updated inactive root partition"),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't update inactive root partition: {}", e)),
    }
}

async fn handle_switch() -> HttpResponse {
    println!("switch to inactive root");

    match switch_to_inactive_root() {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body("successfully switched to inactive root partition"),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't switch to inactive root partition: {}", e)),
    }
}

async fn handle_data_read(info: web::Query<DataRequest>) -> HttpResponse {
    let query = info.into_inner();

    println!("read {}", query.path);

    match fs::read(&query.path) {
        Ok(data) => HttpResponse::Ok()
            .content_type(ContentType::octet_stream())
            .body(data),
        Err(e) => HttpResponse::NotFound()
            .content_type(ContentType::plaintext())
            .body(format!("can't read file at {}: {}", query.path, e)),
    }
}

async fn handle_data_write(info: web::Query<DataRequest>, data: web::Bytes) -> HttpResponse {
    let query = info.into_inner();

    println!("write {}", query.path);

    match stream_to(&query.path, &data).await {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(format!("successfully wrote to {}", query.path)),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't write file at {}: {}", query.path, e)),
    }
}

async fn handle_data_list(info: web::Query<DataRequest>) -> HttpResponse {
    let query = info.into_inner();

    println!("list {}", query.path);

    match fs::read_dir(&query.path) {
        Ok(ls) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(
                ls.map(|result| {
                    result
                        .map(|entry| match entry.metadata() {
                            Ok(meta) => {
                                format!(
                                    "ty={} perm={:4o} uid={:5} gid={:5}  {}",
                                    if meta.is_symlink() {
                                        "s"
                                    } else if meta.is_dir() {
                                        "d"
                                    } else {
                                        "-"
                                    },
                                    meta.permissions().mode() & 0xfff,
                                    meta.uid(),
                                    meta.gid(),
                                    entry.path().display()
                                )
                            }
                            Err(e) => format!(
                                "ty=? perm=????  {} (meta error: {})",
                                entry.path().display(),
                                e
                            ),
                        })
                        .unwrap_or_else(|e| format!("error: {}", e))
                })
                .reduce(|acc, entry| acc + "\n" + &entry)
                .unwrap_or(String::new()),
            ),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't read dir at {}: {}", query.path, e)),
    }
}

async fn handle_data_mkdir(info: web::Query<DataRequest>) -> HttpResponse {
    let query = info.into_inner();

    println!("mkdir {}", query.path);

    match fs::create_dir_all(&query.path) {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(format!("successfully created directory {}", query.path)),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't create directory {}: {}", query.path, e)),
    }
}

async fn handle_data_remove(info: web::Query<DataRequest>) -> HttpResponse {
    let query = info.into_inner();

    println!("remove {}", query.path);

    match fs::remove_file(&query.path) {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(format!("successfully removed {}", query.path)),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't remove {}: {}", query.path, e)),
    }
}

async fn handle_data_removedir(info: web::Query<DataRequest>) -> HttpResponse {
    let query = info.into_inner();

    println!("removedir {}", query.path);

    match fs::remove_dir_all(&query.path) {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(format!("successfully removed directory {}", query.path)),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't remove directory {}: {}", query.path, e)),
    }
}

async fn handle_proc_top() -> HttpResponse {
    println!("monitor processes");

    let mut s = System::new_all();

    for process in s.processes().values() {
        process.cpu_usage();
    }

    sleep(<System as SystemExt>::MINIMUM_CPU_UPDATE_INTERVAL).await;
    s.refresh_all();

    let out = s
        .processes()
        .values()
        .map(|process| format!("{} {}%", process.name(), process.cpu_usage()))
        .reduce(|acc, line| acc + "\n" + &line)
        .unwrap_or(String::new());

    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body(out)
}

async fn handle_proc_kill(info: web::Query<KillRequest>) -> HttpResponse {
    let query = info.into_inner();

    let signal = match query.signal.as_str() {
        "usr1" => Signal::User1,
        "usr2" => Signal::User2,
        "hup" => Signal::Hangup,
        "alrm" => Signal::Alarm,
        "term" => Signal::Term,
        "kill" => Signal::Kill,
        _ => {
            return HttpResponse::BadRequest()
                .content_type(ContentType::plaintext())
                .body("invalid signal, need usr1, usr2, term or kill")
        }
    };

    println!("kill process {} signal {}", query.process, query.signal);

    for process in System::new_all().processes_by_exact_name(&query.process) {
        process.kill_with(signal);
    }

    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body("kill successful")
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    match start().await {
        Ok(_) => {}
        Err(e) => {
            println!("start error: {}", e);
            return Ok(());
        }
    }

    Ok(())
}

async fn start() -> Result<()> {
    let config = load_rustls_config()?;

    println!("start https://[::]:8443");

    Ok(HttpServer::new(|| {
        let auth = HttpAuthentication::basic(basic_auth_validator);
        App::new()
            .app_data(web::PayloadConfig::default().limit(512 * MiB))
            .wrap(auth)
            .service(web::resource("/reboot").to(handle_reboot))
            .service(web::resource("/shutdown").to(handle_shutdown))
            .service(web::resource("/update/boot").to(handle_update_boot))
            .service(web::resource("/update/mbr").to(handle_update_mbr))
            .service(web::resource("/update/root").to(handle_update_root))
            .service(web::resource("/switch").to(handle_switch))
            .service(web::resource("/data/read").to(handle_data_read))
            .service(web::resource("/data/write").to(handle_data_write))
            .service(web::resource("/data/list").to(handle_data_list))
            .service(web::resource("/data/mkdir").to(handle_data_mkdir))
            .service(web::resource("/data/remove").to(handle_data_remove))
            .service(web::resource("/data/removedir").to(handle_data_removedir))
            .service(web::resource("/proc/top").to(handle_proc_top))
            .service(web::resource("/proc/kill").to(handle_proc_kill))
    })
    .bind_rustls("[::]:8443", config)?
    .run()
    .await?)
}

fn load_rustls_config() -> Result<ServerConfig> {
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    let cert_file = &mut BufReader::new(File::open("/data/admind_cert.pem")?);
    let key_file = &mut BufReader::new(File::open("/data/admind_key.pem")?);

    let cert_chain = certs(cert_file)?.into_iter().map(Certificate).collect();

    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)?
        .into_iter()
        .map(PrivateKey)
        .collect();

    if keys.is_empty() {
        return Err(Error::NoPrivateKeys);
    }

    Ok(config.with_single_cert(cert_chain, keys.remove(0))?)
}

async fn basic_auth_validator(
    req: ServiceRequest,
    credentials: BasicAuth,
) -> std::result::Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    let config = req.app_data::<Config>().cloned().unwrap_or_default();

    match validate_credentials(
        credentials.user_id(),
        credentials.password().unwrap_or_default().trim(),
    ) {
        Ok(res) => {
            if res {
                Ok(req)
            } else {
                Err((AuthenticationError::from(config).into(), req))
            }
        }
        Err(_) => Err((AuthenticationError::from(config).into(), req)),
    }
}

fn validate_credentials(user_id: &str, user_password: &str) -> io::Result<bool> {
    let correct_password = fs::read("/data/admind.passwd")?;

    if user_id == "rustkrazy" && constant_time_eq(user_password.as_bytes(), &correct_password) {
        return Ok(true);
    }

    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Invalid credentials",
    ))
}

fn modify_cmdline(new: &str) -> Result<()> {
    let boot = boot_dev()?;
    let boot_partition = OpenOptions::new().read(true).write(true).open(boot)?;
    let buf_stream = BufStream::new(boot_partition);
    let bootfs = fatfs::FileSystem::new(buf_stream, fatfs::FsOptions::new())?;

    let mut file = bootfs.root_dir().open_file("cmdline.txt")?;

    file.write_all(new.as_bytes())?;

    Ok(())
}

fn dev() -> Result<&'static str> {
    let devs = ["/dev/mmcblk0", "/dev/sda", "/dev/vda"];

    for dev in devs {
        if fs::metadata(dev).is_ok() {
            return Ok(dev);
        }
    }

    Err(Error::NoDiskDev)
}

fn boot_dev() -> Result<&'static str> {
    Ok(match dev()? {
        "/dev/mmcblk0" => "/dev/mmcblk0p1",
        "/dev/sda" => "/dev/sda1",
        "/dev/vda" => "/dev/vda1",
        _ => unreachable!(),
    })
}

// fn active_root() -> Result<String> {
//     let cmdline = fs::read_to_string("/proc/cmdline")?;
//
//     for seg in cmdline.split(' ') {
//         if seg.starts_with("root=PARTUUID=00000000-") {
//             let root_id = seg
//                 .split("root=PARTUUID=00000000-0")
//                 .collect::<Vec<&str>>()
//                 .into_iter()
//                 .next_back()
//                 .ok_or(Error::RootdevUnset)?;
//
//             return Ok(match dev()? {
//                 "/dev/mmcblk0" => format!("/dev/mmcblk0p{}", root_id),
//                 "/dev/sda" => format!("/dev/sda{}", root_id),
//                 "/dev/vda" => format!("/dev/vda{}", root_id),
//                 _ => unreachable!(),
//             });
//         }
//     }
//
//     Err(Error::RootdevUnset)
// }

fn inactive_root() -> Result<String> {
    let cmdline = fs::read_to_string("/proc/cmdline")?;

    for seg in cmdline.split(' ') {
        if seg.starts_with("root=PARTUUID=00000000-") {
            let root_id = match seg
                .split("root=PARTUUID=00000000-0")
                .collect::<Vec<&str>>()
                .into_iter()
                .next_back()
                .ok_or(Error::RootdevUnset)?
            {
                "2" => "3",
                "3" => "2",
                _ => unreachable!(),
            };

            return Ok(match dev()? {
                "/dev/mmcblk0" => format!("/dev/mmcblk0p{}", root_id),
                "/dev/sda" => format!("/dev/sda{}", root_id),
                "/dev/vda" => format!("/dev/vda{}", root_id),
                _ => unreachable!(),
            });
        }
    }

    Err(Error::RootdevUnset)
}

async fn stream_to(dst: &str, data: &[u8]) -> Result<()> {
    let mut file = File::create(dst)?;

    file.write_all(data)?;
    file.sync_all()?;

    nix::unistd::sync();
    Ok(())
}

fn switch_to_inactive_root() -> Result<()> {
    let new = inactive_root()?;
    let new = String::from("root=PARTUUID=00000000-0") + &new.chars().last().unwrap().to_string();

    let cmdline = format!("{} init=/bin/init rootwait console=tty1", new);

    modify_cmdline(&cmdline)?;
    nix::unistd::sync();

    Ok(())
}
