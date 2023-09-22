pub mod tls_config {
    use openssl::ssl::{SslContext, SslFiletype, SslMethod};
    use std::path::Path;
    use openssl::x509::X509;
    use openssl::pkey::PKey;
    use openssl::ssl::SslAcceptor;
    use std::fs;
    use anyhow::Context;
    pub type Acceptor = openssl::ssl::SslContext;
    //pub type Acceptor = openssl::ssl::SslAcceptor;

       fn tls_acceptor_impl<P: AsRef<Path>>(cert_file: P, key_file: P) -> Acceptor {
        
        //    // Load SSL keys and certificates
        //    let cert_path = "/workspaces/fido-device-onboard-rs/certs/cert.pem";
        //    let key_path = "/workspaces/fido-device-onboard-rs/certs/key.pem";
   
        //    let cert_ = fs::read(cert_path).expect("Failed to read certificate file");
        //    let key_ = fs::read(key_path).expect("Failed to read private key file");
   
        //    // Parse the certificate and private key from bytes to OpenSSL objects
        //    let cert = X509::from_pem(&cert_).context("Error parsing SSL certificate");
        //    let key = PKey::private_key_from_pem(&key_).context("Error parsing SSL private key");
   
   
        //    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        //    builder.set_certificate(&cert);
        //    builder.set_private_key(&key);

   
   
        let mut builder = SslContext::builder(SslMethod::tls_server()).unwrap();
        builder
            .set_certificate_file(cert_file, SslFiletype::PEM)
            .unwrap();
        builder
            .set_private_key_file(key_file, SslFiletype::PEM)
            .unwrap();  
        builder.build()
    }

    pub fn tls_acceptor() -> Acceptor {
        tls_acceptor_impl(
            "/workspaces/fido-device-onboard-rs/certs/trial/server.crt",
            "/workspaces/fido-device-onboard-rs/certs/trial/server.key",
        )
    }

    pub fn tls_acceptor2() -> Acceptor {
        tls_acceptor_impl(
            "/workspaces/fido-device-onboard-rs/certs/trial/server.crt",
            "/workspaces/fido-device-onboard-rs/certs/trial/server.key",
        )
    }
}


pub use tls_config::Acceptor;
pub use tls_config::tls_acceptor;
pub use tls_config::tls_acceptor2;