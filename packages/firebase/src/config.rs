use crate::{is_demo_project, is_valid_project_id, Error};

/// Which Firebase project to talk to, and how.
#[derive(Clone, Debug)]
pub struct FirebaseConfig {
    /// The project's Web API key. Not a secret: it identifies the project to Firebase.
    pub api_key: String,
    /// The project ID.
    pub project_id: String,
    emulator_host: Option<String>,
}

impl FirebaseConfig {
    /// A configuration for the real Firebase.
    pub fn new(api_key: impl Into<String>, project_id: impl Into<String>) -> Result<Self, Error> {
        let config = Self {
            api_key: api_key.into(),
            project_id: project_id.into(),
            emulator_host: None,
        };
        if !is_valid_project_id(&config.project_id) || config.api_key.is_empty() {
            return Err(Error::Configuration(
                "a Firebase API key and a valid project ID are needed".into(),
            ));
        }
        Ok(config)
    }

    /// Talks to the Firebase Auth emulator at `host:port` instead. Only for `demo-` projects, so
    /// a production configuration can never end up at an emulator.
    pub fn with_emulator(mut self, host: impl Into<String>) -> Result<Self, Error> {
        let host = host.into();
        if !is_demo_project(&self.project_id) {
            return Err(Error::Configuration(
                "the emulator is only allowed for a \"demo-\" project".into(),
            ));
        }
        let valid = host
            .rsplit_once(':')
            .is_some_and(|(name, port)| !name.is_empty() && port.parse::<u16>().is_ok());
        if !valid {
            return Err(Error::Configuration(
                "the emulator host must be host:port".into(),
            ));
        }
        self.emulator_host = Some(host);
        Ok(self)
    }

    /// The emulator's `host:port`, when one is configured.
    pub fn emulator_host(&self) -> Option<&str> {
        self.emulator_host.as_deref()
    }

    pub(crate) fn identity_toolkit(&self, method: &str) -> String {
        match &self.emulator_host {
            Some(host) => format!(
                "http://{host}/identitytoolkit.googleapis.com/v1/accounts:{method}?key={}",
                self.api_key
            ),
            None => format!(
                "https://identitytoolkit.googleapis.com/v1/accounts:{method}?key={}",
                self.api_key
            ),
        }
    }

    pub(crate) fn secure_token(&self) -> String {
        match &self.emulator_host {
            Some(host) => format!(
                "http://{host}/securetoken.googleapis.com/v1/token?key={}",
                self.api_key
            ),
            None => format!(
                "https://securetoken.googleapis.com/v1/token?key={}",
                self.api_key
            ),
        }
    }
}
