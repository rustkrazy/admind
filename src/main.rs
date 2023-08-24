use rustkrazy_admind::{Error, Result};

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Write};

use actix_web::{
    dev::ServiceRequest, http::header::ContentType, web, App, HttpResponse, HttpServer,
};
use actix_web_httpauth::extractors::basic::{BasicAuth, Config};
use actix_web_httpauth::extractors::AuthenticationError;
use actix_web_httpauth::middleware::HttpAuthentication;
use constant_time_eq::constant_time_eq;
use fscommon::BufStream;
use nix::sys::reboot::{reboot, RebootMode};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::Deserialize;

#[allow(non_upper_case_globals)]
const KiB: usize = 1024;
#[allow(non_upper_case_globals)]
const MiB: usize = 1024 * KiB;

#[derive(Clone, Debug, Deserialize)]
struct DataRequest {
    path: String,
}

async fn handle_reboot() -> HttpResponse {
    println!("request reboot");

    match reboot(RebootMode::RB_AUTOBOOT) {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body("rebooting..."),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't reboot: {}", e)),
    }
}

async fn handle_shutdown() -> HttpResponse {
    println!("request shutdown");

    match reboot(RebootMode::RB_POWER_OFF) {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body("shutting down..."),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't shut down: {}", e)),
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

    match stream_to(&query.path, &data).await {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(format!("successfully wrote to {}", query.path)),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't write file at {}: {}", query.path, e)),
    }
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

    nix::unistd::sync();
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
    Ok(())
}
