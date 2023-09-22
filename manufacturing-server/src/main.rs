

use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::fs;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{bail, Context, Error, Result};
use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use serde_yaml::Value;
use warp::Filter;

use fdo_data_formats::{
    constants::{KeyStorageType, MfgStringType, PublicKeyType, RendezvousVariable},
    ownershipvoucher::OwnershipVoucher,
    publickey::{PublicKey, X5Chain},
    types::{Guid, RendezvousInfo},
    ProtocolVersion,
};
use fdo_store::Store;
use fdo_util::servers::{
    configuration::manufacturing_server::{DiunSettings, ManufacturingServerSettings},
    settings_for, yaml_to_cbor, OwnershipVoucherStoreMetadataKey,
};


use std::convert::Infallible;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslAcceptorBuilder};
use tokio::net::TcpListener;
use std::net::SocketAddr;
use hyper::server::conn::AddrIncoming;
use tls_listener::TlsListener;

pub mod tls_config;
use tls_config::tls_acceptor;

const PERFORMED_DIUN_SES_KEY: &str = "mfg_global_diun_performed";
const DEVICE_KEY_FROM_DIUN_SES_KEY: &str = "mfg_global_device_key_from_diun";

mod handlers;

struct DiunConfiguration {
    mfg_string_type: MfgStringType,

    key_type: PublicKeyType,
    allowed_key_storage_types: Vec<KeyStorageType>,

    key: PKey<Private>,
    public_keys: PublicKey,
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
enum PublicKeyStoreMetadataKey {}

impl fdo_store::MetadataLocalKey for PublicKeyStoreMetadataKey {
    fn to_key(&self) -> &'static str {
        match *self {}
    }
}

struct ManufacturingServiceUD {
    // Stores
    session_store: Arc<fdo_http_wrapper::server::SessionStore>,
    ownership_voucher_store: Box<
        dyn Store<
            fdo_store::WriteOnlyOpen,
            Guid,
            OwnershipVoucher,
            OwnershipVoucherStoreMetadataKey,
        >,
    >,
    public_key_store:
        Option<Box<dyn Store<fdo_store::ReadOnlyOpen, String, Vec<u8>, PublicKeyStoreMetadataKey>>>,

    // Certificates
    manufacturer_cert: X509,
    manufacturer_key: Option<PKey<Private>>,
    device_cert_key: PKey<Private>,
    device_cert_chain: X5Chain,
    owner_cert: Option<PublicKey>,

    // Rendezvous Info
    rendezvous_info: RendezvousInfo,

    // Protocols
    enable_di: bool,

    // DIUN settings
    diun_configuration: Option<DiunConfiguration>,
}

type ManufacturingServiceUDT = Arc<ManufacturingServiceUD>;

impl TryFrom<DiunSettings> for DiunConfiguration {
    type Error = Error;

    fn try_from(value: DiunSettings) -> Result<DiunConfiguration, Error> {
        let key = fs::read(value.key_path).context("Error reading DIUN key")?;
        let key = PKey::private_key_from_der(&key).context("Error parsing DIUN key")?;
        let public_keys = X5Chain::new(
            X509::stack_from_pem(
                &fs::read(value.cert_path).context("Error reading DIUN certificate")?,
            )
            .context("Error parsing DIUN certificate")?,
        )
        .context("Error generating X5Chain")?
        .try_into()
        .context("Error generating PublicKey")?;

        Ok(DiunConfiguration {
            mfg_string_type: value.mfg_string_type.into(),
            key_type: value.key_type.into(),
            allowed_key_storage_types: value
                .allowed_key_storage_types
                .iter()
                .map(|x| KeyStorageType::from(*x))
                .collect(),

            key,
            public_keys,
        })
    }
}

fn load_rendezvous_info(rvs: &[BTreeMap<String, Value>]) -> Result<RendezvousInfo> {
    let mut info = Vec::new();
    for val in rvs {
        let mut entry = Vec::new();

        for (key, val) in val.iter() {
            let key = RendezvousVariable::from_str(key)
                .with_context(|| format!("Error parsing rendezvous key '{key}'"))?;

            let val = yaml_to_cbor(val)?;
            let val = key
                .value_from_human_to_machine(val)
                .with_context(|| format!("Error parsing value for key '{key:?}'"))?;

            entry.push((key, val));
        }

        info.push(entry);
    }

    RendezvousInfo::new(info).context("Error serializing rendezvous info")
}

const MAINTENANCE_INTERVAL: u64 = 60;

async fn perform_maintenance(
    udt: ManufacturingServiceUDT,
) -> std::result::Result<(), &'static str> {
    log::info!(
        "Scheduling maintenance every {} seconds",
        MAINTENANCE_INTERVAL
    );

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(MAINTENANCE_INTERVAL)).await;

        let ov_maint = udt.ownership_voucher_store.perform_maintenance();
        let ses_maint = udt.session_store.perform_maintenance();

        #[allow(unused_must_use)]
        let (ov_res, ses_res) = tokio::join!(ov_maint, ses_maint);
        if let Err(e) = ov_res {
            log::warn!("Error during ownership voucher store maintenance: {:?}", e);
        }
        if let Err(e) = ses_res {
            log::warn!("Error during session store maintenance: {:?}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    fdo_util::add_version!();
    fdo_http_wrapper::init_logging();

    let settings: ManufacturingServerSettings = settings_for("manufacturing-server")?
        .try_deserialize()
        .context("Error parsing configuration")?;

    // Bind information
    let bind_addr: fdo_util::servers::configuration::Bind = settings.bind.clone();

    // Initialize stores
    let session_store = settings
        .session_store_driver
        .initialize()
        .context("Error initializing session store")?;
    let session_store = fdo_http_wrapper::server::SessionStore::new(session_store);
    let ownership_voucher_store = settings
        .ownership_voucher_store_driver
        .initialize()
        .context("Error initializing ownership voucher store")?;
    let public_key_store = match settings.public_key_store_driver {
        None => None,
        Some(driver) => Some(
            driver
                .initialize()
                .context("Error initializing public key store")?,
        ),
    };

    // Read keys and certificates
    let device_cert_key = PKey::private_key_from_der(
        &fs::read(settings.manufacturing.device_cert_ca_private_key)
            .context("Error reading device CA private key")?,
    )
    .context("Error parsing device CA private key")?;
    let device_cert_chain = X5Chain::new(
        X509::stack_from_pem(
            &fs::read(settings.manufacturing.device_cert_ca_chain)
                .context("Error reading device CA chain")?,
        )
        .context("Error parsing device CA chain")?,
    )
    .context("Error creating device cert chain")?;
    let manufacturer_cert = X509::from_pem(
        &fs::read(settings.manufacturing.manufacturer_cert_path)
            .context("Error reading manufacturer certificate")?,
    )
    .context("Error parsing manufacturer certificate")?;

    let manufacturer_key = match settings.manufacturing.manufacturer_private_key {
        None => None,
        Some(path) => Some(
            PKey::private_key_from_der(
                &fs::read(path).context("Error reading manufacturer private key")?,
            )
            .context("Error parsing manufacturer private key")?,
        ),
    };
    let owner_cert = match settings.manufacturing.owner_cert_path {
        None => None,
        Some(path) => Some(
            X509::from_pem(&fs::read(path).context("Error reading owner certificate")?)
                .context("Error parsing owner certificate")?
                .try_into()
                .context("Error converting owner certificate to PublicKey")?,
        ),
    };

    if manufacturer_key.is_none() != owner_cert.is_none() {
        bail!("Manufacturer private key and owner certificate must both be specified or not specified");
    }

    let diun_configuration = match settings.protocols.diun {
        None => None,
        Some(v) => Some(v.try_into().context("Error parsing DIUN configuration")?),
    };

    let rendezvous_info = load_rendezvous_info(&settings.rendezvous_info)
        .context("Error processing rendezvous info")?;

    // Initialize user data
    let user_data = Arc::new(ManufacturingServiceUD {
        // Stores
        session_store: session_store.clone(),
        ownership_voucher_store,
        public_key_store,

        device_cert_key,
        device_cert_chain,
        manufacturer_cert,
        manufacturer_key,
        owner_cert,

        rendezvous_info,

        enable_di: settings.protocols.plain_di.unwrap_or(false),
        diun_configuration,
    });


    // Initialize handlers
    let hello = warp::get().map(|| "Hello from the manufacturing server");
    let handler_ping = fdo_http_wrapper::server::ping_handler();

    // DI
    let handler_di_app_start = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::di::app_start,
    );
    let handler_di_set_hmac = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::di::set_hmac,
    );

    // DIUN
    let handler_diun_connect = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::diun::connect,
    );
    let handler_diun_request_key_parameters = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::diun::request_key_parameters,
    );
    let handler_diun_provide_key = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::diun::provide_key,
    );

    log::info!("set up warp routes ");
    let routes = warp::post()
        .and(
            hello
                .or(handler_ping)
                // DI
                .or(handler_di_app_start)
                .or(handler_di_set_hmac)
                // DIUN
                .or(handler_diun_connect)
                .or(handler_diun_request_key_parameters)
                .or(handler_diun_provide_key),
        )
        .recover(fdo_http_wrapper::server::handle_rejection)
        .with(warp::log("manufacturing-server"));
        //Method 1 , without using tls-listener lib 

        let addr = ([127, 0, 0, 1], 8080).into();
        // // Load SSL keys and certificates
        // let cert_path = "/workspaces/fido-device-onboard-rs/certs/cert.pem";
        // let key_path = "/workspaces/fido-device-onboard-rs/certs/key.pem";

        // let cert_ = fs::read(cert_path).expect("Failed to read certificate file");
        // let key_ = fs::read(key_path).expect("Failed to read private key file");

        // // Parse the certificate and private key from bytes to OpenSSL objects
        // let cert = X509::from_pem(&cert_).context("Error parsing SSL certificate")?;
        // let key = PKey::private_key_from_pem(&key_).context("Error parsing SSL private key")?;


        // let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        // builder.set_certificate(&cert);
        // builder.set_private_key(&key);
        // //let acceptor = Arc::new(builder.build());
        // let acceptor =  builder.build();


        // Define a test route
        let hello = warp::path!("hello" / "world")
            .map(|| warp::reply::html("This is warp server with https enabled!"));

        let routes_test = hello;

        // Convert routes into a warp service, so that we can use hyper to serve this services with TLS config.
        let service = warp::service(routes_test);

        let make_svc = hyper::service::make_service_fn(move |_| {
            let svc = service.clone();
            async move { Ok::<_, Infallible>(svc) }
        });
        //Trial tls-listener lib
        let incoming = TlsListener::new(tls_acceptor(), AddrIncoming::bind(&addr)?);
        // using tls-listener
        let server = hyper::Server::builder(incoming).serve(make_svc);
        // Server should start here
        log::info!("starting server with https support");
        server.await?;
        // Create a listener and wrap with TLS using the acceptor
        //  let listener = TcpListener::bind("127.0.0.1:8080");
        // let incoming_tls = listener.accept().await;


       // let incoming = TlsListener::new(tls_acceptor(), listener);
       
        // Mtho0d 2: If not using tls-listener lib , just need to figure out a correct way of passing 'incoming' param below
        // which is basically combination of SSlAcceptor & Addrs
       //  let incoming_tls = (acceptor, AddrIncoming::bind(&addr)?);

       // let server = hyper::Server::builder(incoming_tls).serve(make_svc);
   

        
        
        // For Ref only:
        // Serve incoming TLS connections
       // warp::Server::serve_incoming(self, incoming_tls);
            //warp::Server::run(self, addr)
   /*      
        let hello = warp::path!("hello").map(|| "Hello, world!"); // this one always succeeds, even over a network
       
            // Convert it into a `Service`...
        let svc = warp::service(hello.or(routes));

        let make_svc = hyper::service::make_service_fn(move |_| {
            let svc = svc.clone();
            async move { Ok::<_, Infallible>(svc) }
        });

        let addr = SocketAddr::from(([127, 0, 0, 1], 4433));
        let listener = TcpListener::bind(&addr).await?;

        let server = hyper::Server::builder(accept::from_stream(listener.accept()))
            .serve(make_svc);

        let server_handle = tokio::spawn(server);
       
  
    
      */

      
      /* //  let server = hyper::Server::builder(https).serve(make_svc);
        let builder: native_tls::TlsAcceptorBuilder = native_tls::TlsAcceptorBuilder::build(builder);
      //  native_tls::TlsAcceptorBuilder::
        let tls_acceptor = builder.build().expect("Failed to build TLS acceptor");
       // TcpServer::new(Server::new(Http::new(), tls_acceptor), addr).serve(make_svc);
       let server = hyper::Server::builder(tls_acceptor).serve(make_svc);
 */
       
 /* let server = warp::serve(routes);

    let maintenance_runner =
        tokio::spawn(async move { perform_maintenance(user_data.clone()).await });

    let server = server
        .bind_with_graceful_shutdown(bind_addr, async {
            signal(SignalKind::terminate()).unwrap().recv().await;
            log::info!("Terminating");
        })
        .1;
    let server = tokio::spawn(server);

    tokio::select!(
    _ = server => {
        log::info!("Server terminated");
    },
    _ = maintenance_runner => {
        log::info!("Maintenance runner terminated");
    });

 */

    // for https support
    // Define the address to bind to
 /*    let https_addr = ([0, 0, 0, 0], 8080).into(); // Change port to desired HTTPS port
    let https_route = warp::any().map(|| "Hello From https enabled Warp!");

    // Convert it into a `Service`
    let svc = warp::service(https_route);

    //  hyper setup
    let make_svc = hyper::service::make_service_fn(move |_| async move {
        Ok::<_, Infallible>(svc)
    });

    hyper::Server::bind(&https_addr)
        .serve(make_svc)
        .await?;
    // Start the server
    log::info!("Listening on https://{}", https_addr); */
    

    Ok(())
}

