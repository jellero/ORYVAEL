#![forbid(unsafe_code)]

#[cfg(unix)]
mod unix_main {
    use oryvael_control::ControlKind;
    use oryvael_supervisor::service::{
        ServiceConfig, ServiceRequest, ServiceResponse, TrustedService, request,
    };
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::path::PathBuf;
    use std::{env, process};

    pub fn run() -> Result<(), Box<dyn Error>> {
        let mut arguments = env::args().skip(1);
        let command = arguments.next().unwrap_or_else(|| "help".into());
        let options = parse_options(arguments.collect())?;

        match command.as_str() {
            "serve" => {
                let mut config = ServiceConfig::system_defaults();
                apply_common_paths(&mut config, &options);
                let max_requests = options
                    .get("max-requests")
                    .map(|value| value.parse::<usize>())
                    .transpose()?;
                TrustedService::open(config)?.serve(max_requests)?;
            }
            "status" => {
                let socket = socket_path(&options);
                print_response(request(socket, &ServiceRequest::Status)?)?;
            }
            "verify" => {
                let socket = socket_path(&options);
                let kind = required(&options, "kind")?;
                let artifact = required(&options, "artifact")?;
                let response = request(
                    socket,
                    &ServiceRequest::Verify {
                        artifact: PathBuf::from(artifact),
                        kind: ControlKind::parse(kind)?,
                    },
                )?;
                print_response(response)?;
            }
            "supervise" => {
                let socket = socket_path(&options);
                let principal = required(&options, "principal")?;
                let job = required(&options, "job")?;
                let response = request(
                    socket,
                    &ServiceRequest::Supervise {
                        principal: PathBuf::from(principal),
                        job: PathBuf::from(job),
                    },
                )?;
                print_response(response)?;
            }
            "help" | "--help" | "-h" => print_help(),
            other => {
                return Err(format!("unknown command: {other}").into());
            }
        }
        Ok(())
    }

    fn parse_options(values: Vec<String>) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
        let mut options = BTreeMap::new();
        let mut index = 0usize;
        while index < values.len() {
            let flag = &values[index];
            if !flag.starts_with("--") {
                return Err(format!("expected --option, got {flag}").into());
            }
            let key = flag.trim_start_matches("--");
            let value = values
                .get(index + 1)
                .ok_or_else(|| format!("missing value for {flag}"))?;
            if value.starts_with("--") {
                return Err(format!("missing value for {flag}").into());
            }
            if options.insert(key.into(), value.clone()).is_some() {
                return Err(format!("duplicate option: {flag}").into());
            }
            index += 2;
        }
        Ok(options)
    }

    fn apply_common_paths(config: &mut ServiceConfig, options: &BTreeMap<String, String>) {
        if let Some(value) = options.get("socket") {
            config.socket_path = PathBuf::from(value);
        }
        if let Some(value) = options.get("root-policy") {
            config.root_policy_path = PathBuf::from(value);
        }
        if let Some(value) = options.get("minimum-epoch") {
            config.minimum_epoch_path = PathBuf::from(value);
        }
        if let Some(value) = options.get("audit") {
            config.audit_path = PathBuf::from(value);
        }
    }

    fn socket_path(options: &BTreeMap<String, String>) -> PathBuf {
        options
            .get("socket")
            .map(PathBuf::from)
            .unwrap_or_else(|| ServiceConfig::system_defaults().socket_path)
    }

    fn required<'a>(
        options: &'a BTreeMap<String, String>,
        key: &str,
    ) -> Result<&'a str, Box<dyn Error>> {
        options
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("missing required --{key}").into())
    }

    fn print_response(response: ServiceResponse) -> Result<(), Box<dyn Error>> {
        let failed_job = matches!(
            &response,
            ServiceResponse::Supervised { result } if !result.success
        );
        let error = response.is_error();
        println!("{}", serde_json::to_string_pretty(&response)?);
        if error {
            process::exit(2);
        }
        if failed_job {
            process::exit(3);
        }
        Ok(())
    }

    fn print_help() {
        println!(
            "oryvael-service\n\n\
             Commands:\n\
               serve [--socket PATH] [--root-policy PATH] [--minimum-epoch PATH] [--audit PATH] [--max-requests N]\n\
               status [--socket PATH]\n\
               verify --kind KIND --artifact PATH [--socket PATH]\n\
               supervise --principal PATH --job PATH [--socket PATH]"
        );
    }
}

#[cfg(unix)]
fn main() {
    if let Err(error) = unix_main::run() {
        eprintln!("oryvael-service: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("oryvael-service currently requires a Unix host");
    std::process::exit(2);
}
