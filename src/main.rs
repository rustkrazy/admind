use rustkrazy_admind::{Error, Result};

use std::fs::File;
use std::io::{self, BufReader};

use actix_web::{http::header::ContentType, web, App, HttpRequest, HttpResponse, HttpServer};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};

async fn index(req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body("it works")
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

    Ok(
        HttpServer::new(|| App::new().service(web::resource("/").to(index)))
            .bind_rustls("[::]:8443", config)?
            .run()
            .await?,
    )
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
