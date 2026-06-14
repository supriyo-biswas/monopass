pub(crate) fn inferred_concealed(name: &str) -> bool {
    let name = name.to_lowercase();
    name.contains("password")
        || name.contains("secret")
        || name.contains("private")
        || name.contains("key") && !name.contains("public")
}
