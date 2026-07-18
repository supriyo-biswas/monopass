use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessScope {
    #[default]
    Items,
    Settings,
}

impl AccessScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Items => "items",
            Self::Settings => "settings",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub struct AuthScopeQuery {
    pub scope: Option<AccessScope>,
}

impl AuthScopeQuery {
    pub fn access_scope(self) -> AccessScope {
        self.scope.unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStatusResponse {
    #[serde(rename = "reauth_timestamp")]
    pub reauth_timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthUnlockMethodsResponse {
    pub methods: Vec<AuthUnlockMethod>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthUnlockMethod {
    pub url: String,
    #[serde(rename = "accepts_master_password")]
    pub accepts_master_password: bool,
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
    pub job_type: JobType,
    pub status: JobStatus,
    pub target: JobTarget,
    pub created_at: String,
    pub updated_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    #[serde(rename = "output_path")]
    pub output_path: Option<String>,
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
pub enum JobType {
    Import,
    Export,
}

impl JobType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Export => "export",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
}

impl JobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "queued" => Some(Self::Queued),
            "running" => Some(Self::Running),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirResponse {
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub items: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactResponse {
    pub email: String,
    pub name: Option<String>,
    #[serde(rename = "age_public_key")]
    pub age_public_key: String,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub entries: Vec<T>,
    #[serde(rename = "next_marker")]
    pub next_marker: Option<String>,
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ListPageQuery {
    pub count: Option<u64>,
    pub marker: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListDirection {
    #[default]
    Asc,
    Desc,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ListItemsQuery {
    pub count: Option<u64>,
    pub marker: Option<String>,
    pub glob: Option<String>,
    pub dir: Option<ListDirection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateDirRequest {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateSettingRequest {
    pub value: String,
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
    #[serde(default)]
    pub name: Option<Option<String>>,
    #[serde(rename = "age_public_key")]
    pub age_public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemResponse {
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub total_versions: u64,
    pub fields: Vec<FieldEntry>,
    pub files: Vec<FileMetadataEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSummaryResponse {
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
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
#[serde(deny_unknown_fields)]
pub struct CreateField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
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
#[serde(deny_unknown_fields)]
pub struct UpdateFieldSet {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    pub concealed: Option<bool>,
    pub data: SecretString,
}

impl From<UpdateFieldSet> for CreateField {
    fn from(field: UpdateFieldSet) -> Self {
        Self {
            name: field.name,
            field_type: field.field_type,
            concealed: field.concealed,
            data: field.data,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    #[serde(rename = "type")]
    pub field_type: FieldType,
    pub concealed: bool,
    pub data: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    pub concealed: bool,
    pub data: SecretString,
}

impl FieldEntry {
    pub fn from_named(name: String, field: Field) -> Self {
        Self {
            name,
            field_type: field.field_type,
            concealed: field.concealed,
            data: field.data,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadataEntry {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct UpdateFileSet {
    pub name: String,
    pub id: String,
}

impl From<UpdateFileSet> for FileInput {
    fn from(file: UpdateFileSet) -> Self {
        Self {
            name: file.name,
            id: file.id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveEntry {
    pub name: String,
    #[serde(deserialize_with = "deserialize_true")]
    pub remove: bool,
}

fn deserialize_true<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let remove = bool::deserialize(deserializer)?;
    if remove {
        Ok(remove)
    } else {
        Err(serde::de::Error::custom("remove must be true"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[cfg(test)]
mod tests {
    use super::{UpdateFieldEntry, UpdateFileEntry, UpdateItemRequest};

    #[test]
    fn update_item_request_deserializes_set_and_remove_entries() {
        let request: UpdateItemRequest = serde_json::from_value(serde_json::json!({
            "fields": [
                {"name": "username", "type": "string", "data": "alice"},
                {"name": "password", "remove": true}
            ],
            "files": [
                {"name": "notes", "id": "00112233445566778899aabbccddeeff"},
                {"name": "old", "remove": true}
            ]
        }))
        .unwrap();

        assert!(matches!(request.fields[0], UpdateFieldEntry::Set(_)));
        assert!(matches!(request.fields[1], UpdateFieldEntry::Remove(_)));
        assert!(matches!(request.files[0], UpdateFileEntry::Set(_)));
        assert!(matches!(request.files[1], UpdateFileEntry::Remove(_)));
    }

    #[test]
    fn update_item_request_rejects_ambiguous_or_false_removes() {
        for value in [
            serde_json::json!({"fields": [{"name": "password", "remove": true, "type": "string", "data": "new"}]}),
            serde_json::json!({"files": [{"name": "notes", "remove": true, "id": "00112233445566778899aabbccddeeff"}]}),
            serde_json::json!({"fields": [{"name": "password", "remove": false}]}),
            serde_json::json!({"files": [{"name": "notes", "remove": false}]}),
            serde_json::json!({"fields": [{"name": "password", "type": "string"}]}),
            serde_json::json!({"files": [{"name": "notes"}]}),
            serde_json::json!({"fields": {"password": {"remove": true}}}),
            serde_json::json!({"files": {"notes": {"remove": true}}}),
        ] {
            assert!(serde_json::from_value::<UpdateItemRequest>(value).is_err());
        }
    }
}
