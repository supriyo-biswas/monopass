use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirResponse {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactResponse {
    pub email: String,
    pub name: Option<String>,
    #[serde(rename = "age_public_key")]
    pub age_public_key: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobAcceptedResponse {
    #[serde(rename = "job_id")]
    pub job_id: String,
    pub status: JobStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobResponse {
    #[serde(rename = "job_id")]
    pub job_id: String,
    #[serde(rename = "type")]
    pub job_type: String,
    pub status: JobStatus,
    pub target: JobTarget,
    #[serde(rename = "output_path")]
    pub output_path: Option<std::path::PathBuf>,
    pub error: Option<JobErrorResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobTarget {
    pub dir: String,
    pub item: String,
    pub contact: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub entries: Vec<T>,
    #[serde(rename = "next_marker")]
    pub next_marker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateContactRequest {
    pub name: Option<String>,
    #[serde(rename = "age_public_key")]
    pub age_public_key: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateContactRequest {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Option<String>>,
    #[serde(rename = "age_public_key")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateSettingRequest {
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemResponse {
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub total_versions: u64,
    pub fields: Vec<Field>,
    pub files: Vec<FileMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSummaryResponse {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemVersionSummaryResponse {
    pub version: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateItemRequest {
    #[serde(default)]
    pub fields: Vec<CreateField>,
    #[serde(default)]
    pub files: Vec<FileInput>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateItemRequest {
    #[serde(default)]
    pub fields: Vec<UpdateFieldEntry>,
    #[serde(default)]
    pub files: Vec<UpdateFileEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concealed: Option<bool>,
    pub data: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpdateFieldEntry {
    Set(UpdateFieldSet),
    Remove(RemoveEntry),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateFieldSet {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concealed: Option<bool>,
    pub data: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    pub concealed: bool,
    pub data: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInput {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpdateFileEntry {
    Set(UpdateFileSet),
    Remove(RemoveEntry),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateFileSet {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveEntry {
    pub name: String,
    pub remove: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CreateFileResponse {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    String,
    File,
    Totp,
}
