use crate::errors::SdkError;
use std::fs;

const USER_REPORT_DATA_PATH: &str = "/dev/attestation/user_report_data";
const QUOTE_PATH: &str = "/dev/attestation/quote";

/// Write exactly 64 bytes to /dev/attestation/user_report_data
pub fn write_user_report_data(data: &[u8; 64]) -> Result<(), SdkError> {
    tracing::debug!(path = USER_REPORT_DATA_PATH, "Writing user report data to attestation device");
    fs::write(USER_REPORT_DATA_PATH, data).map_err(|e| {
        SdkError::AttestationUnavailable(format!("Failed to write user_report_data: {}", e))
    })
}

/// Read the full DCAP quote from /dev/attestation/quote
pub fn read_quote() -> Result<Vec<u8>, SdkError> {
    tracing::debug!(path = QUOTE_PATH, "Reading DCAP quote from attestation device");
    fs::read(QUOTE_PATH)
        .map_err(|e| SdkError::QuoteReadFailed(format!("Failed to read quote: {}", e)))
}
