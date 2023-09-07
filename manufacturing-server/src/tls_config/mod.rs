pub mod tls_config {
    use openssl::ssl::{SslContext, SslFiletype, SslMethod};
    use std::path::Path;
    use openssl::x509::X509;
    use openssl::pkey::PKey;
    use openssl::ssl::SslAcceptor;
    use std::fs;
    use anyhow::Context;
    pub type Acceptor = openssl::ssl::SslContext;

       fn tls_acceptor_impl<P: AsRef<Path>>(cert_file: P, key_file: P) -> Acceptor {
        
        let mut builder = SslContext::builder(SslMethod::tls_server()).unwrap();
        builder
            .set_certificate_file(cert_file, SslFiletype::ASN1)
            .unwrap();
        builder
            .set_private_key_file(key_file, SslFiletype::ASN1)
            .unwrap(); 
        builder.build()
    }

    pub fn tls_acceptor() -> Acceptor {
        tls_acceptor_impl(
            "./examples/tls_config/local.cert",
            "./examples/tls_config/local.key",
        )
    }

    pub fn tls_acceptor2() -> Acceptor {
        tls_acceptor_impl(
            "./examples/tls_config/local2.cert",
            "./examples/tls_config/local2.key",
        )
    }
}


pub use tls_config::Acceptor;
pub use tls_config::tls_acceptor;
pub use  tls_config::tls_acceptor2;