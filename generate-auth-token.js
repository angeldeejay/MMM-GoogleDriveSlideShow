// region Dependencies
const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { google } = require("googleapis");
const { Validator } = require("jsonschema");

const SCOPES = ["https://www.googleapis.com/auth/drive.readonly"];
const SCHEMAS_PATH = path.join(__dirname, "schemas");
const SECRETS_PATH = path.join(__dirname, "secrets");
const TOKEN_PATH = path.join(SECRETS_PATH, "token.json");
const CREDENTIALS_PATH = path.join(SECRETS_PATH, "credentials.json");

// region Initial checks
if (!fs.existsSync(SECRETS_PATH)) {
  console.log(`${SECRETS_PATH} folder does not exists, creating it.`);
  fs.mkdirSync(SECRETS_PATH);
}

if (!fs.existsSync(CREDENTIALS_PATH)) {
  console.error(
    `${CREDENTIALS_PATH} file does not exists. Follow README.md instructions to create it`,
  );
  process.exit(1);
}

// region Definitions
/** @typedef {import("google-auth-library").OAuth2ClientOptions} OAuth2ClientOptions */
/** @typedef {import("google-auth-library").OAuth2Client} OAuth2Client */
/** @typedef {import("google-auth-library").Credentials} Credentials */
/**
 * @typedef {Object} CredentialsInstalled
 * @property {OAuth2ClientOptions['clientId']} client_id - The client ID.
 * @property {OAuth2ClientOptions['projectId']} project_id - The project ID.
 * @property {string|null|undefined} auth_uri - The authorization URI.
 * @property {string|null|undefined} token_uri - The token URI.
 * @property {string|null|undefined} auth_provider_x509_cert_url - The auth provider x509 cert URL.
 * @property {OAuth2ClientOptions['clientSecret']} client_secret - The client secret.
 * @property {Array<string>|null|undefined} redirect_uris - The redirect URIs.
 */
/**
 * @typedef {Object} CredentialsFileData
 * @property {CredentialsInstalled} installed - The installed credentials.
 */

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const credentialsSchema = JSON.parse(
  fs.readFileSync(path.join(SCHEMAS_PATH, "credentials.schema.json"), "utf8"),
);

const tokenSchema = JSON.parse(
  fs.readFileSync(path.join(SCHEMAS_PATH, "token.schema.json"), "utf8"),
);

// region Functions
/**
 * Get instance of Google OAuth2 client
 *
 * @param {CredentialsFileData} credentials
 * @returns {OAuth2Client}
 */
const getAuthClient = (credentials) => {
  const {
      installed: {
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uris: redirectUris,
      },
    } = credentials,
    redirectUri = (redirectUris ?? [])[0];

  if (!redirectUri) {
    console.error("No redirect URI found in credentials");
    process.exit(1);
  }

  return new google.auth.OAuth2({ clientId, clientSecret, redirectUri });
};

/**
 * Validate credentials data
 *
 * @param {Object} credentials
 */
const validateCredentials = (credentials) => {
  if (typeof credentials !== "object" || credentials === null) {
    console.error(
      "Invalid credentials data: Credentials must be a non-null object",
    );
    process.exit(1);
  }

  const validator = new Validator();
  const validationResult = validator.validate(credentials, credentialsSchema);

  if (!validationResult.valid) {
    const messages = [];
    for (const error of validationResult.errors) {
      messages.push(`- ${error.stack}`);
    }
    console.error(`Invalid credentials data:\n${messages.join("\n")}`);
    process.exit(1);
  }
};

/**
 * Validate token data
 *
 * @param {Object} token
 */
const validateToken = (token) => {
  if (typeof token !== "object" || token === null) {
    console.error("Invalid token data: Token must be a non-null object");
    process.exit(1);
  }

  const validator = new Validator();
  const validationResult = validator.validate(token, tokenSchema);

  if (!validationResult.valid) {
    const messages = [];
    for (const error of validationResult.errors) {
      messages.push(`- ${error.stack}`);
    }
    console.error(`Invalid token data:\n${messages.join("\n")}`);
    process.exit(1);
  }
};

/**
 * Get client credentials from a local file
 *
 * @returns {CredentialsFileData}
 */
const getCredentials = () => {
  try {
    const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, "utf8"));
    validateCredentials(credentials);
    return credentials;
  } catch (err) {
    console.error("Invalid credentials file:", err);
    process.exit(1);
  }
};

/**
 * Store token data into local file
 *
 * @param {Credentials} token
 */
const storeToken = (token) => {
  fs.writeFileSync(TOKEN_PATH, JSON.stringify(token, null, 2), "utf-8");
  console.log("Token successfully stored");
};

/**
 * Get client token from a local file.
 *
 * @param {CredentialsFileData} credentials
 * @returns {Promise<Credentials|undefined>}
 */
const getCurrentToken = async (credentials) => {
  if (fs.existsSync(TOKEN_PATH)) {
    try {
      /** @type {Credentials} */
      const token = JSON.parse(fs.readFileSync(TOKEN_PATH, "utf8"));
      validateToken(token);

      const authClient = getAuthClient(credentials);
      authClient.setCredentials(token);

      if (token.refresh_token) {
        const accessTokenResp = await authClient.getAccessToken();
        if (accessTokenResp?.token) {
          console.log("Token refreshed");
          /** @type {Credentials} */
          const updatedToken = {
            ...token,
            ...authClient.credentials,
            refresh_token: token.refresh_token,
          };
          storeToken(updatedToken);
          return updatedToken;
        }
        return undefined;
      }

      // Si NO hay refresh_token, el token no es útil para un sistema headless
      console.error(
        "Token has no refresh_token. Re-authorize with prompt=consent.",
      );
      return undefined;
    } catch (err) {
      console.error("Invalid token:", err);
    }
  }
  return undefined;
};

/**
 * Issue a new token
 *
 * @param {CredentialsFileData} credentials
 */
const issueNewToken = (credentials) => {
  const authClient = getAuthClient(credentials);
  const authUrl = authClient.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
  });

  console.log("Authorize the app by visiting this url:", authUrl);
  rl.question("Enter the code from that page here: ", (code) => {
    rl.close();

    try {
      authClient.getToken(code, (err, token) => {
        if (err) {
          console.error("Error retrieving access token: ", err);
          process.exit(1);
        }
        // store the token on disk
        validateToken(token);
        storeToken(token);
      });
    } catch (err) {
      console.error("Error retrieving access token:", err);
      process.exit(1);
    }
  });
};

/**
 * Main function
 */
const main = async () => {
  const credentials = getCredentials();
  const token = await getCurrentToken(credentials);
  if (token) {
    process.exit(0);
  }

  issueNewToken(credentials);
};

void main();
