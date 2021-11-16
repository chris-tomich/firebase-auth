use std::{collections::{HashMap, HashSet}, error, fmt};

use actix_web::client::{Client, JsonPayloadError, SendRequestError};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

#[derive(Debug, Serialize, Deserialize)]
struct FirebaseIdentities {
    identities: Option<HashMap<String, Vec<String>>>,
    sign_in_provider: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirebaseClaims {
    exp: usize,
    iat: Option<usize>,
    aud: Option<String>,
    iss: Option<String>,
    sub: Option<String>,
    auth_time: Option<usize>,
    name: Option<String>,
    picture: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    user_id: Option<String>,
    firebase: Option<FirebaseIdentities>,
}

#[derive(Debug)]
pub struct ValidationError {
    description: Option<String>,
    inner_error: Option<Box<(dyn error::Error + 'static)>>,
}

impl ValidationError {
    fn new(description: String) -> ValidationError {
        ValidationError {
            description: Some(description),
            inner_error: None,
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.description {
            Some(description) => write!(f, "issues with token validation; {}; ", description)?,
            None => write!(f, "issues with token validation; ")?,
        };

        if let Some(err) = &self.inner_error {
            err.fmt(f)?;
        }

        Ok(())
    }
}

impl error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.inner_error.as_deref()
    }
}

impl From<jsonwebtoken::errors::Error> for ValidationError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        ValidationError {
            description: None,
            inner_error: Some(Box::new(err)),
        }
    }
}

impl From<SendRequestError> for ValidationError {
    fn from(err: SendRequestError) -> Self {
        ValidationError {
            description: None,
            inner_error: Some(Box::new(err)),
        }
    }
}

impl From<JsonPayloadError> for ValidationError {
    fn from(err: JsonPayloadError) -> Self {
        ValidationError {
            description: None,
            inner_error: Some(Box::new(err)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Keys {
    keys: Vec<HashMap<String, String>>,
}

#[derive(Clone)]
pub struct TokenValidator {
    pub firebase_project_id: String,
    pub firebase_project_issuer: String,
    pub firebase_public_keys_jwk_url: String,
}

impl TokenValidator {
    pub async fn validate(&self, token: &str) -> Result<FirebaseClaims, ValidationError> {
        let validation = Validation {
            aud: Some(HashSet::from([self.firebase_project_id.clone()])),
            iss: Some(self.firebase_project_issuer.clone()),
            ..Validation::new(Algorithm::RS256)
        };

        let header = decode_header(token)?;
        let kid = match header.kid {
            Some(kid) => kid,
            None => return Err(ValidationError::new(String::from("the token header did not contain a Key ID"))),
        };

        let client = Client::default();
        let mut response = client.get(self.firebase_public_keys_jwk_url.clone()).send().await?;
        let keys = response.json::<Keys>().await?;

        for key in keys.keys {
            if let Some(cert_kid) = key.get("kid") {
                if kid.eq(cert_kid) {
                    let token = decode::<FirebaseClaims>(token, &DecodingKey::from_rsa_components(key.get("n").unwrap(), key.get("e").unwrap()), &validation)?;

                    return Ok(token.claims);
                }
            }
        }

        Err(ValidationError::new(String::from("token failed validation as the referenced public key couldn't be found")))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
