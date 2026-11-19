//! The `delegations` member of a top-level targets file, read apart from the targets
//! ([`super::model::Targets::delegations`]): the publishers' roles, their keys and paths.
//!
//! Reading has two levels. What makes the member unreadable as a whole is an error of that
//! reading ([`TufError`]), never of the targets: a field missing or of the wrong type, a key
//! id that is not the hash of its key, a role name that is not `pub-<publisher>`
//! ([`RoleName`]), a name listed twice.
//! What breaks the profile of one role refuses that role alone ([`RefusedRole`], with a
//! [`DelegationError`]), so a mistake in one publisher's entry never touches another's:
//!
//! - `paths` exactly `["plugins/<publisher>/*/*"]` ([`PathPattern`]), no `path_hash_prefixes`;
//! - `terminating: true`;
//! - key ids distinct, each in `keys`, and the threshold between 1 and their number;
//! - no key listed by two roles (the same rule as in a root: one key, one role). The root's
//!   keys are checked when the role is used, against the root in force.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::error::{DelegationError, TufError};
use super::keys::{KeyId, PublicKey};
use super::model::{RoleKeys, array, field, object, uint};
use super::names::{PathPattern, RoleName};

/// The delegations of a top-level targets file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegations {
    keys: BTreeMap<KeyId, PublicKey>,
    roles: Vec<Result<DelegatedRole, RefusedRole>>,
}

/// A delegated role whose entry keeps the profile: what its file must be signed by and the
/// targets it may list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegatedRole {
    name: RoleName,
    keys: RoleKeys,
    pattern: PathPattern,
}

/// A delegated role whose entry breaks the profile: it is not used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusedRole {
    /// The role.
    pub name: RoleName,
    /// The rule its entry breaks.
    pub error: DelegationError,
}

impl DelegatedRole {
    /// The role's name.
    pub fn name(&self) -> &RoleName {
        &self.name
    }

    /// The keys that sign the role's file, and how many must.
    pub fn keys(&self) -> &RoleKeys {
        &self.keys
    }

    /// The targets the role may list.
    pub fn pattern(&self) -> &PathPattern {
        &self.pattern
    }
}

/// One role's entry as read, before its profile is checked.
struct Entry {
    name: RoleName,
    keyids: Vec<KeyId>,
    threshold: u64,
    terminating: bool,
    paths: Option<Vec<String>>,
    hash_prefixes: bool,
}

impl Delegations {
    /// Reads the `delegations` member of a top-level targets file.
    ///
    /// # Errors
    ///
    /// [`TufError::Malformed`] for a field missing or of the wrong type, a key id that is
    /// not 64 hex digits, a role name that is not a [`RoleName`] or is listed twice;
    /// [`TufError::BadKeyId`] for a key under another id than its hash;
    /// [`TufError::Unsupported`] for a key that is not Ed25519.
    pub(super) fn from_value(value: &Value) -> Result<Delegations, TufError> {
        let members = object(value, "delegations")?;
        let mut keys = BTreeMap::new();
        for (claimed, key) in object(field(members, "keys", "delegations")?, "delegations.keys")? {
            let id = KeyId::from_hex(claimed).ok_or_else(|| {
                TufError::malformed("delegations.keys", "a key id is not 64 hex digits")
            })?;
            let key = PublicKey::from_value(key)?;
            let actual = key.key_id();
            if actual != id {
                return Err(TufError::BadKeyId {
                    claimed: claimed.clone(),
                    actual: actual.to_hex(),
                });
            }
            keys.insert(id, key);
        }
        let mut names = BTreeSet::new();
        let mut entries = Vec::new();
        for entry in array(field(members, "roles", "delegations")?, "delegations.roles")? {
            let entry = Entry::from_value(entry)?;
            if !names.insert(entry.name.clone()) {
                return Err(TufError::malformed(
                    "delegations.roles",
                    format!("the role {} is listed twice", entry.name),
                ));
            }
            entries.push(entry);
        }
        // How many roles list each key: a key of two roles refuses both.
        let mut listed_by: BTreeMap<KeyId, usize> = BTreeMap::new();
        for entry in &entries {
            for id in entry.keyids.iter().collect::<BTreeSet<_>>() {
                *listed_by.entry(*id).or_default() += 1;
            }
        }
        let roles = entries
            .into_iter()
            .map(|entry| {
                let shared = entry
                    .keyids
                    .iter()
                    .find(|id| listed_by.get(id).is_some_and(|n| *n > 1));
                let role = match shared {
                    Some(id) => Err(DelegationError::KeyReused { keyid: *id }),
                    None => entry.profile(&keys),
                };
                role.map_err(|error| RefusedRole {
                    name: entry.name.clone(),
                    error,
                })
            })
            .collect();
        Ok(Delegations { keys, roles })
    }

    /// Every key of the delegations, by its id (recomputed on reading).
    pub fn keys(&self) -> &BTreeMap<KeyId, PublicKey> {
        &self.keys
    }

    /// The roles, in the order the targets list them: the order of the search (section
    /// 5.6.7 of the specification).
    pub fn roles(&self) -> &[Result<DelegatedRole, RefusedRole>] {
        &self.roles
    }

    /// The role `name`, if the delegations have it.
    pub fn role(&self, name: &RoleName) -> Option<Result<&DelegatedRole, &RefusedRole>> {
        self.roles
            .iter()
            .map(|role| role.as_ref())
            .find(|role| match role {
                Ok(role) => role.name() == name,
                Err(refused) => refused.name == *name,
            })
    }
}

impl Entry {
    fn from_value(value: &Value) -> Result<Entry, TufError> {
        let what = "a delegated role";
        let members = object(value, what)?;
        let name = field(members, "name", what)?
            .as_str()
            .ok_or_else(|| TufError::malformed(what, "name is not a string"))?;
        let name = RoleName::parse(name).map_err(|e| TufError::malformed(what, e.to_string()))?;
        let what = format!("the delegated role {name}");
        let mut keyids = Vec::new();
        for id in array(field(members, "keyids", &what)?, "keyids")? {
            keyids.push(
                id.as_str()
                    .and_then(KeyId::from_hex)
                    .ok_or_else(|| TufError::malformed(&what, "a key id is not 64 hex digits"))?,
            );
        }
        let threshold = uint(members, "threshold", &what)?;
        let terminating = field(members, "terminating", &what)?
            .as_bool()
            .ok_or_else(|| TufError::malformed(&what, "terminating is not a boolean"))?;
        let paths = members
            .get("paths")
            .map(|paths| strings(paths, &what))
            .transpose()?;
        let hash_prefixes = members
            .get("path_hash_prefixes")
            .map(|prefixes| strings(prefixes, &what))
            .transpose()?
            .is_some();
        Ok(Entry {
            name,
            keyids,
            threshold,
            terminating,
            paths,
            hash_prefixes,
        })
    }

    /// The role, if its entry keeps the profile.
    fn profile(&self, keys: &BTreeMap<KeyId, PublicKey>) -> Result<DelegatedRole, DelegationError> {
        if self.hash_prefixes {
            return Err(DelegationError::HashPrefixes);
        }
        let pattern = PathPattern::of(&self.name.publisher());
        let expected = pattern.to_string();
        match self.paths.as_deref() {
            Some([only]) if *only == expected => {}
            _ => return Err(DelegationError::Pattern),
        }
        if !self.terminating {
            return Err(DelegationError::NotTerminating);
        }
        let mut seen = BTreeSet::new();
        for id in &self.keyids {
            if !seen.insert(id) {
                return Err(DelegationError::DuplicateKey { keyid: *id });
            }
            if !keys.contains_key(id) {
                return Err(DelegationError::UnknownKey { keyid: *id });
            }
        }
        let threshold = u32::try_from(self.threshold)
            .ok()
            .filter(|threshold| (1..=self.keyids.len()).contains(&(*threshold as usize)))
            .ok_or(DelegationError::Threshold {
                threshold: self.threshold,
                keys: self.keyids.len(),
            })?;
        Ok(DelegatedRole {
            name: self.name.clone(),
            keys: RoleKeys {
                keyids: self.keyids.clone(),
                threshold,
            },
            pattern,
        })
    }
}

/// An array of strings.
fn strings(value: &Value, what: &str) -> Result<Vec<String>, TufError> {
    array(value, what)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| TufError::malformed(what, "a path is not a string"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, json};

    use super::*;
    use crate::tuf::model::{Profile, Targets};

    fn key(n: u8) -> (KeyId, Value) {
        let key = PublicKey::from_bytes([n; 32]);
        (key.key_id(), key.to_value())
    }

    fn id(n: u8) -> String {
        key(n).0.to_hex()
    }

    fn role_name(name: &str) -> RoleName {
        RoleName::parse(name).unwrap()
    }

    /// The entry of `pub-<publisher>` signed by the key `n`, keeping the profile.
    fn entry(publisher: &str, n: u8) -> Value {
        json!({
            "name": format!("pub-{publisher}"),
            "keyids": [id(n)],
            "threshold": 1,
            "paths": [format!("plugins/{publisher}/*/*")],
            "terminating": true,
        })
    }

    /// Delegations of keys 1 to 4 and of `roles`.
    fn delegations(roles: Vec<Value>) -> Value {
        let keys: Map<String, Value> = (1..=4).map(|n| (id(n), key(n).1)).collect();
        json!({"keys": keys, "roles": roles})
    }

    fn read(roles: Vec<Value>) -> Delegations {
        Delegations::from_value(&delegations(roles)).unwrap()
    }

    fn edited(mut v: Value, edit: impl FnOnce(&mut Value)) -> Value {
        edit(&mut v);
        v
    }

    /// The error `entry`, the only role, is refused with.
    fn refusal(entry: Value) -> DelegationError {
        let read = read(vec![entry]);
        match &read.roles()[0] {
            Err(refused) => refused.error.clone(),
            Ok(role) => panic!("{} was accepted", role.name()),
        }
    }

    fn targets(extra: Value, profile: Profile) -> Result<Targets, TufError> {
        let mut v = json!({
            "_type": "targets", "spec_version": "1.0.31", "version": 1,
            "expires": "2026-11-22T00:00:00Z", "targets": {},
        });
        if let (Some(v), Some(extra)) = (v.as_object_mut(), extra.as_object()) {
            v.extend(extra.clone());
        }
        Targets::from_signed(&v, profile)
    }

    #[test]
    fn the_legacy_profile_still_refuses_any_delegations() {
        for delegations in [delegations(vec![]), json!({}), Value::Null] {
            assert!(
                matches!(
                    targets(json!({"delegations": delegations}), Profile::Legacy),
                    Err(TufError::Unsupported(m)) if m.contains("delegations")
                ),
                "{delegations}"
            );
        }
        assert!(matches!(
            targets(json!({}), Profile::Legacy).unwrap().delegations(),
            Ok(None)
        ));
    }

    #[test]
    fn the_delegating_profile_reads_targets_without_delegations() {
        let read = targets(json!({}), Profile::Delegating).unwrap();
        assert!(matches!(read.delegations(), Ok(None)));
    }

    #[test]
    fn the_delegating_profile_keeps_unreadable_delegations_unread() {
        let rsa = json!({
            "keytype": "rsa", "scheme": "rsassa-pss-sha256",
            "keyval": {"public": "-----BEGIN PUBLIC KEY-----"},
        });
        let one_key = |keyid: String, public: Value| {
            let keys: Map<String, Value> = [(keyid, public)].into_iter().collect();
            json!({"keys": keys, "roles": []})
        };
        let unreadable = [
            json!(5),
            json!({}),
            json!({"keys": {}, "roles": 7}),
            delegations(vec![edited(entry("abc", 1), |e| {
                e["name"] = json!("not-a-publisher");
            })]),
            one_key(id(1), rsa),
            delegations(vec![entry("abc", 1), entry("abc", 2)]),
            one_key(id(2), key(1).1),
        ];
        for member in unreadable {
            let read = targets(json!({"delegations": member.clone()}), Profile::Delegating)
                .unwrap_or_else(|e| panic!("{member}: the targets are refused: {e}"));
            assert!(read.delegations().is_err(), "{member}");
        }
    }

    #[test]
    fn empty_delegations_are_no_roles() {
        let read = targets(
            json!({"delegations": {"keys": {}, "roles": []}}),
            Profile::Delegating,
        )
        .unwrap();
        let delegations = read.delegations().unwrap().unwrap();
        assert!(delegations.roles().is_empty());
        assert!(delegations.keys().is_empty());
    }

    #[test]
    fn roles_that_keep_the_profile_are_read_in_order() {
        let read = read(vec![entry("ecc", 1), entry("abc", 2)]);
        let names: Vec<&str> = read
            .roles()
            .iter()
            .map(|role| role.as_ref().unwrap().name().as_str())
            .collect();
        assert_eq!(names, ["pub-ecc", "pub-abc"]);
        let ecc = read.role(&role_name("pub-ecc")).unwrap().unwrap();
        assert_eq!(ecc.keys().keyids, [key(1).0]);
        assert_eq!(ecc.keys().threshold, 1);
        assert_eq!(ecc.pattern().to_string(), "plugins/ecc/*/*");
        assert!(read.role(&role_name("pub-other")).is_none());
        assert_eq!(read.keys().len(), 4);
    }

    #[test]
    fn a_threshold_of_two_of_two_keys_is_read() {
        let read = read(vec![edited(entry("ecc", 1), |v| {
            v["keyids"] = json!([id(1), id(2)]);
            v["threshold"] = json!(2);
        })]);
        assert_eq!(read.roles()[0].as_ref().unwrap().keys().threshold, 2);
    }

    #[test]
    fn a_key_under_another_id_refuses_the_delegations() {
        let mut v = delegations(vec![entry("ecc", 1)]);
        v["keys"][id(1)] = key(9).1;
        assert!(matches!(
            Delegations::from_value(&v),
            Err(TufError::BadKeyId { claimed, .. }) if claimed == id(1)
        ));
    }

    #[test]
    fn a_key_id_that_is_not_hex_refuses_the_delegations() {
        let mut v = delegations(vec![]);
        v["keys"]["not-hex"] = key(9).1;
        assert!(matches!(
            Delegations::from_value(&v),
            Err(TufError::Malformed { .. })
        ));
        let v = delegations(vec![edited(entry("ecc", 1), |v| {
            v["keyids"] = json!(["xyz"])
        })]);
        assert!(matches!(
            Delegations::from_value(&v),
            Err(TufError::Malformed { .. })
        ));
    }

    #[test]
    fn a_role_name_listed_twice_refuses_the_delegations() {
        let v = delegations(vec![entry("ecc", 1), entry("ecc", 2)]);
        assert!(matches!(
            Delegations::from_value(&v),
            Err(TufError::Malformed { why, .. }) if why.contains("twice")
        ));
    }

    #[test]
    fn a_top_level_role_name_refuses_the_delegations() {
        for name in ["root", "targets", "snapshot", "timestamp"] {
            let v = delegations(vec![edited(entry("ecc", 1), |v| v["name"] = json!(name))]);
            assert!(
                matches!(Delegations::from_value(&v), Err(TufError::Malformed { .. })),
                "{name}"
            );
        }
    }

    #[test]
    fn a_role_name_that_is_not_pub_and_a_publisher_refuses_the_delegations() {
        for name in [
            "ecc",
            "pub-",
            "pub-Ecc",
            "pub-root",
            "pub-ab",
            "publisher-ecc",
        ] {
            let v = delegations(vec![edited(entry("ecc", 1), |v| v["name"] = json!(name))]);
            assert!(
                matches!(Delegations::from_value(&v), Err(TufError::Malformed { .. })),
                "{name}"
            );
        }
    }

    #[test]
    fn a_field_missing_or_of_the_wrong_type_refuses_the_delegations() {
        type Edit = Box<dyn Fn(&mut Value)>;
        let edits: Vec<(&str, Edit)> = vec![
            (
                "no keys",
                Box::new(|v| drop(v.as_object_mut().unwrap().remove("keys"))),
            ),
            (
                "no roles",
                Box::new(|v| drop(v.as_object_mut().unwrap().remove("roles"))),
            ),
            ("roles object", Box::new(|v| v["roles"] = json!({}))),
            ("keys array", Box::new(|v| v["keys"] = json!([]))),
            (
                "role not object",
                Box::new(|v| v["roles"] = json!(["pub-ecc"])),
            ),
            (
                "no name",
                Box::new(|v| drop(v["roles"][0].as_object_mut().unwrap().remove("name"))),
            ),
            (
                "no terminating",
                Box::new(|v| drop(v["roles"][0].as_object_mut().unwrap().remove("terminating"))),
            ),
            (
                "terminating string",
                Box::new(|v| v["roles"][0]["terminating"] = json!("true")),
            ),
            (
                "threshold string",
                Box::new(|v| v["roles"][0]["threshold"] = json!("1")),
            ),
            (
                "negative threshold",
                Box::new(|v| v["roles"][0]["threshold"] = json!(-1)),
            ),
            (
                "paths string",
                Box::new(|v| v["roles"][0]["paths"] = json!("plugins/ecc/*/*")),
            ),
            (
                "path number",
                Box::new(|v| v["roles"][0]["paths"] = json!([1])),
            ),
            (
                "keyids string",
                Box::new(|v| v["roles"][0]["keyids"] = json!(id(1))),
            ),
        ];
        for (name, edit) in edits {
            let v = edited(delegations(vec![entry("ecc", 1)]), |v| edit(v));
            assert!(
                matches!(Delegations::from_value(&v), Err(TufError::Malformed { .. })),
                "{name}"
            );
        }
        assert!(matches!(
            Delegations::from_value(&json!([])),
            Err(TufError::Malformed { .. })
        ));
    }

    #[test]
    fn path_hash_prefixes_refuse_the_role() {
        let v = edited(entry("ecc", 1), |v| {
            let members = v.as_object_mut().unwrap();
            members.remove("paths");
            members.insert("path_hash_prefixes".to_owned(), json!(["00"]));
        });
        assert_eq!(refusal(v), DelegationError::HashPrefixes);
        // Also next to the right paths.
        let v = edited(entry("ecc", 1), |v| v["path_hash_prefixes"] = json!([]));
        assert_eq!(refusal(v), DelegationError::HashPrefixes);
    }

    #[test]
    fn paths_other_than_the_publishers_pattern_refuse_the_role() {
        for paths in [
            json!([]),
            json!(["plugins/abc/*/*"]),
            json!(["plugins/ecc/*"]),
            json!(["plugins/ecc/*/*/*"]),
            json!(["plugins/ecc/**"]),
            json!(["plugins/ecc/*/*", "plugins/ecc/*/*"]),
            json!(["plugins/ecc/*/*", "indexes/*"]),
            json!(["*"]),
        ] {
            let v = edited(entry("ecc", 1), |v| v["paths"] = paths.clone());
            assert_eq!(refusal(v), DelegationError::Pattern, "{paths}");
        }
        let v = edited(entry("ecc", 1), |v| {
            v.as_object_mut().unwrap().remove("paths");
        });
        assert_eq!(refusal(v), DelegationError::Pattern);
    }

    #[test]
    fn a_role_that_is_not_terminating_is_refused() {
        let v = edited(entry("ecc", 1), |v| v["terminating"] = json!(false));
        assert_eq!(refusal(v), DelegationError::NotTerminating);
    }

    #[test]
    fn a_key_id_listed_twice_by_a_role_refuses_it() {
        let v = edited(entry("ecc", 1), |v| v["keyids"] = json!([id(1), id(1)]));
        assert_eq!(
            refusal(v),
            DelegationError::DuplicateKey { keyid: key(1).0 }
        );
    }

    #[test]
    fn a_key_id_not_in_the_delegations_keys_refuses_the_role() {
        let v = edited(entry("ecc", 1), |v| v["keyids"] = json!([id(9)]));
        assert_eq!(refusal(v), DelegationError::UnknownKey { keyid: key(9).0 });
    }

    #[test]
    fn a_threshold_of_zero_or_above_the_keys_refuses_the_role() {
        for (threshold, keys) in [(0, 1), (2, 1), (u64::from(u32::MAX) + 1, 1)] {
            let v = edited(entry("ecc", 1), |v| v["threshold"] = json!(threshold));
            assert_eq!(
                refusal(v),
                DelegationError::Threshold { threshold, keys },
                "{threshold}"
            );
        }
    }

    #[test]
    fn a_key_of_two_publishers_refuses_both_roles_and_no_other() {
        let read = read(vec![entry("ecc", 1), entry("abc", 1), entry("xyz", 2)]);
        for (role, name) in read.roles()[..2].iter().zip(["pub-ecc", "pub-abc"]) {
            assert_eq!(
                role,
                &Err(RefusedRole {
                    name: role_name(name),
                    error: DelegationError::KeyReused { keyid: key(1).0 },
                })
            );
        }
        assert!(read.roles()[2].is_ok());
    }

    #[test]
    fn one_role_refused_leaves_the_others() {
        let read = read(vec![
            entry("ecc", 1),
            edited(entry("abc", 2), |v| v["terminating"] = json!(false)),
            entry("xyz", 3),
        ]);
        assert!(read.roles()[0].is_ok());
        assert!(matches!(read.role(&role_name("pub-abc")), Some(Err(_))));
        assert!(read.roles()[2].is_ok());
    }

    #[test]
    fn unknown_members_are_ignored() {
        let mut v = delegations(vec![edited(entry("ecc", 1), |v| v["x-note"] = json!(1))]);
        v["x-other"] = json!({});
        assert!(Delegations::from_value(&v).unwrap().roles()[0].is_ok());
    }
}
