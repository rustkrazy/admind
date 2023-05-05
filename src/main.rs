use rustkrazy_admind::{Error, Result};

use std::fs::File;
use std::io::{self, BufReader};

use actix_web::{
    dev::ServiceRequest, http::header::ContentType, web, App, HttpResponse, HttpServer,
};
use actix_web_httpauth::extractors::basic::{BasicAuth, Config};
use actix_web_httpauth::extractors::AuthenticationError;
use actix_web_httpauth::middleware::HttpAuthentication;
use nix::sys::reboot::{reboot, RebootMode};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};

async fn handle_reboot() -> HttpResponse {
    match reboot(RebootMode::RB_AUTOBOOT) {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body("rebooting..."),
        Err(e) => HttpResponse::InternalServerError()
            .content_type(ContentType::plaintext())
            .body(format!("can't reboot: {}", e)),
    }
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
    if user_id == "rustkrazy" && user_password == "rustkrazy" {
        return Ok(true);
    }

    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Invalid credentials",
    ))
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    match start().await {
        Ok(_) => {}
        Err(e) => {
            println!("[admind] start error: {}", e);
            return Ok(());
        }
    }

    Ok(())
}

async fn start() -> Result<()> {
    let config = load_rustls_config()?;

    println!("[admind] start https://[::]:8443");

    Ok(HttpServer::new(|| {
        let auth = HttpAuthentication::basic(basic_auth_validator);
        App::new()
            .wrap(auth)
            .service(web::resource("/rustkrazy/reboot").to(handle_reboot))
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
