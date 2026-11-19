//! The plugins in the daemon's windows: the plugin window's services over the
//! [`PluginService`] ([`WindowServices`]), and the user asked in the install confirmation
//! ([`WindowInstallUi`]).

use std::path::PathBuf;
use std::sync::Arc;

use oncl_plugin::{Localized, Replaces};
use oncl_ui::plugins_view::{
    AvailablePlugin, CatalogLine, InstalledPlugin, LocalizedText, PendingUpdate, PluginOrigin,
    PluginStatus, PublisherOrigin, ReplacedBundle, SourceArchive,
};
use oncl_ui::{
    InstallPluginRequest, InstalledVersion, PluginActionError, PluginsServices, PluginsView,
    RequestKind,
};

use super::{
    CatalogView, InstallRequest, InstallUi, PluginService, PluginState, ReleaseOrigin, ServiceView,
};

/// Asks the user in the install confirmation window ([`oncl_ui::ask_install_plugin`]).
pub struct WindowInstallUi;

impl InstallUi for WindowInstallUi {
    fn confirm(&self, request: InstallRequest, decide: Box<dyn FnOnce(bool) + Send>) {
        oncl_ui::ask_install_plugin(install_request(request, decide));
    }
}

/// `request` as the confirmation window shows it.
pub fn install_request(
    request: InstallRequest,
    decide: Box<dyn FnOnce(bool) + Send>,
) -> InstallPluginRequest {
    InstallPluginRequest {
        origin: request.origin,
        name: text(&request.name),
        version: request.version.to_string(),
        replaces: request.replaces.as_ref().map(bundle),
        replacing: request.replacing.map(|(version, from)| InstalledVersion {
            version: version.to_string(),
            origin: origin(from),
        }),
        capabilities: request.capabilities.lines(),
        operations: request.operations,
        kind: match request.replaces_port {
            Some((port, version)) => RequestKind::ReplacePort {
                port: text(&port),
                version: version.to_string(),
            },
            None => RequestKind::Install,
        },
        window: None,
        origin_kind: origin(request.origin_kind),
        decide,
    }
}

/// The plugin window's services: the plugins of `service`, or, if they could not start,
/// why (the window says so and does nothing else).
pub struct WindowServices(pub Result<Arc<PluginService>, String>);

impl PluginsServices for WindowServices {
    fn view(&self) -> PluginsView {
        match &self.0 {
            Ok(service) => plugins_view(service.view()),
            Err(e) => PluginsView {
                catalog: CatalogLine::Off(e.clone()),
                installed: Vec::new(),
                available: Vec::new(),
            },
        }
    }

    fn install(&self, id: &str) -> Result<(), PluginActionError> {
        self.service()?.install_from_catalog(id, None)
    }

    fn install_file(&self, path: PathBuf) -> Result<(), PluginActionError> {
        self.service()?.install_from_file(path)
    }

    fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), PluginActionError> {
        self.service()?.set_enabled(id, enabled)
    }

    fn remove(&self, id: &str) -> Result<(), PluginActionError> {
        self.service()?.remove(id)
    }

    fn confirm_update(&self, id: &str, expected_sha256: &str) -> Result<(), PluginActionError> {
        self.service()?.confirm_update(id, expected_sha256)
    }

    fn replace_port(&self, port: &str) -> Result<(), PluginActionError> {
        self.service()?.replace_port(port)
    }

    fn refresh(&self) {
        if let Ok(service) = &self.0 {
            service.check_now();
        }
    }
}

impl WindowServices {
    /// The service, or why the plugins are off.
    fn service(&self) -> Result<&Arc<PluginService>, PluginActionError> {
        self.0
            .as_ref()
            .map_err(|e| PluginActionError::Failed(e.clone()))
    }
}

/// `view` as the plugin window shows it.
pub fn plugins_view(view: ServiceView) -> PluginsView {
    PluginsView {
        catalog: match view.catalog {
            CatalogView::Unavailable => CatalogLine::Unavailable,
            CatalogView::Ready {
                channel,
                generated,
                error,
                ..
            } => CatalogLine::Ready {
                channel: channel.to_string(),
                generated,
                error,
            },
            CatalogView::Missing { channel, error } => CatalogLine::Missing {
                channel: channel.to_string(),
                error,
            },
        },
        installed: view
            .installed
            .into_iter()
            .map(|p| InstalledPlugin {
                name: text(&p.name),
                version: p.version.to_string(),
                replaces: p.replaces.as_ref().map(bundle),
                origin: origin(p.origin),
                state: match p.state {
                    PluginState::Enabled => PluginStatus::Enabled,
                    PluginState::Disabled => PluginStatus::Disabled,
                    PluginState::Withdrawn => PluginStatus::Withdrawn,
                    PluginState::Error(e) => PluginStatus::Error(e),
                },
                pending_update: p.pending_update.map(|update| PendingUpdate {
                    version: update.version.to_string(),
                    added: update.lines(),
                    operations: update.operations,
                    package_sha256: update.package_sha256,
                    origin: origin(update.origin),
                }),
                replacement: p.replacement.as_ref().map(text),
                id: p.id,
            })
            .collect(),
        available: view
            .available
            .into_iter()
            .map(|p| AvailablePlugin {
                name: text(&p.name),
                version: p.version.to_string(),
                replaces: p.replaces.as_ref().map(bundle),
                origin: origin(p.origin),
                needed: p.needed_by.is_some(),
                needed_by: p.needed_by.flatten(),
                id: p.id,
            })
            .collect(),
    }
}

/// `from` as the windows show it.
fn origin(from: ReleaseOrigin) -> PluginOrigin {
    match from {
        ReleaseOrigin::Project => PluginOrigin::Project,
        ReleaseOrigin::Publisher { display, source } => PluginOrigin::Publisher(PublisherOrigin {
            display: text(&display),
            source: source.map(|s| SourceArchive {
                file: s.name,
                url: s.url,
                license: s.license,
            }),
        }),
        ReleaseOrigin::Unknown => PluginOrigin::Unknown,
        ReleaseOrigin::LocalFile => PluginOrigin::LocalFile,
    }
}

fn text(name: &Localized) -> LocalizedText {
    LocalizedText {
        ru: name.ru.clone(),
        kk: name.kk.clone(),
        en: name.en.clone(),
    }
}

fn bundle(replaces: &Replaces) -> ReplacedBundle {
    ReplacedBundle {
        symname: replaces.symname.clone(),
        version: replaces.version.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{AvailableView, InstalledView, PendingView};
    use oncl_flows::capabilities::CapabilityLine;
    use oncl_plugin::{Capabilities, HttpPrefix};
    use oncl_update::{Channel, Version};
    use time::macros::datetime;

    fn name() -> Localized {
        Localized {
            ru: "Пример".to_owned(),
            kk: "Үлгі".to_owned(),
            en: "Example".to_owned(),
        }
    }

    const SOURCE_URL: &str = "https://github.com/arynyklas/OpenNCALayer/releases/download/pub-acme-ab/kz.acme.b-2.0.0.src.tar.gz";

    fn acme() -> ReleaseOrigin {
        ReleaseOrigin::Publisher {
            display: name(),
            source: Some(oncl_update::catalog::SourceArchive {
                name: "kz.acme.b-2.0.0.src.tar.gz".to_owned(),
                url: SOURCE_URL.to_owned(),
                license: "MIT".to_owned(),
            }),
        }
    }

    fn acme_shown() -> PluginOrigin {
        PluginOrigin::Publisher(PublisherOrigin {
            display: text(&name()),
            source: Some(SourceArchive {
                file: "kz.acme.b-2.0.0.src.tar.gz".to_owned(),
                url: SOURCE_URL.to_owned(),
                license: "MIT".to_owned(),
            }),
        })
    }

    #[test]
    fn the_request_lists_what_the_plugin_may_do() {
        let request = InstallRequest {
            origin: Some("https://shop.kz".to_owned()),
            name: name(),
            version: Version::new(1, 2, 3),
            replaces: Some(Replaces {
                symname: "kz.example.echo".to_owned(),
                version: "1.0.0".to_owned(),
            }),
            replacing: Some((Version::new(1, 0, 0), ReleaseOrigin::LocalFile)),
            capabilities: Capabilities {
                keys: true,
                dialogs: false,
                files: true,
                http: vec![
                    "https://a.kz/api/".parse::<HttpPrefix>().unwrap(),
                    "https://b.kz:8443/".parse::<HttpPrefix>().unwrap(),
                ],
                origins: vec!["https://*.shop.kz".parse().unwrap()],
                http_insecure: vec![
                    HttpPrefix::parse_insecure("http://local.shop.kz:8080/").unwrap(),
                ],
                key_files: true,
                page_files: true,
                page_files_ext: vec!["cms".to_owned()],
                settings: true,
                shared: true,
                builtin: false,
            },
            operations: Vec::new(),
            origin_kind: ReleaseOrigin::LocalFile,
            replaces_port: None,
        };
        let shown = install_request(request, Box::new(|_| {}));
        assert_eq!(shown.origin.as_deref(), Some("https://shop.kz"));
        assert_eq!(shown.name.kk, "Үлгі");
        assert_eq!(shown.version, "1.2.3");
        assert_eq!(shown.replaces.unwrap().symname, "kz.example.echo");
        assert_eq!(
            shown.replacing,
            Some(InstalledVersion {
                version: "1.0.0".to_owned(),
                origin: PluginOrigin::LocalFile,
            })
        );
        assert_eq!(
            shown.capabilities,
            [
                CapabilityLine::Keys,
                CapabilityLine::Files,
                CapabilityLine::Http(vec![
                    "https://a.kz/api/".to_owned(),
                    "https://b.kz:8443/".to_owned()
                ]),
                CapabilityLine::Origins(vec!["https://*.shop.kz".to_owned()]),
                CapabilityLine::HttpInsecure(vec!["http://local.shop.kz:8080/".to_owned()]),
                CapabilityLine::KeyFiles,
                CapabilityLine::PageFiles(vec!["cms".to_owned()]),
                CapabilityLine::Settings,
                CapabilityLine::Shared,
            ]
        );
        assert_eq!(shown.origin_kind, PluginOrigin::LocalFile);
        assert_eq!(shown.kind, RequestKind::Install);
    }

    /// Р11: a publisher's plugin replacing a port is asked as one, the port named.
    #[test]
    fn a_port_replacement_is_asked_as_one() {
        let request = InstallRequest {
            origin: None,
            name: name(),
            version: Version::new(2, 0, 0),
            replaces: None,
            replacing: None,
            capabilities: Capabilities::default(),
            operations: Vec::new(),
            origin_kind: acme(),
            replaces_port: Some((
                Localized {
                    ru: "Порт".to_owned(),
                    kk: "Порт".to_owned(),
                    en: "Port".to_owned(),
                },
                Version::new(1, 0, 0),
            )),
        };
        let shown = install_request(request, Box::new(|_| {}));
        assert_eq!(
            shown.kind,
            RequestKind::ReplacePort {
                port: LocalizedText {
                    ru: "Порт".to_owned(),
                    kk: "Порт".to_owned(),
                    en: "Port".to_owned(),
                },
                version: "1.0.0".to_owned(),
            }
        );
        assert_eq!(shown.origin_kind, acme_shown());
        assert_eq!(shown.replacing, None);
    }

    #[test]
    fn the_view_maps_to_the_window() {
        let generated = datetime!(2026-10-29 10:00 UTC);
        let view = ServiceView {
            catalog: CatalogView::Ready {
                channel: Channel::Beta,
                generated,
                checked: None,
                error: Some("timed out".to_owned()),
            },
            installed: vec![
                InstalledView {
                    id: "kz.a".to_owned(),
                    name: name(),
                    version: Version::new(1, 0, 0),
                    replaces: None,
                    origin: ReleaseOrigin::LocalFile,
                    state: PluginState::Error("broken".to_owned()),
                    pending_update: None,
                    replacement: Some(name()),
                },
                InstalledView {
                    id: "kz.b".to_owned(),
                    name: name(),
                    version: Version::new(2, 0, 0),
                    replaces: None,
                    origin: acme(),
                    state: PluginState::Withdrawn,
                    pending_update: Some(PendingView {
                        version: Version::new(2, 1, 0),
                        added: oncl_plugin::Added {
                            capabilities: Capabilities {
                                files: true,
                                ..Capabilities::default()
                            },
                            operations: Vec::new(),
                        },
                        operations: Vec::new(),
                        package_sha256: "ab".repeat(32),
                        origin: ReleaseOrigin::Project,
                    }),
                    replacement: None,
                },
            ],
            available: vec![
                AvailableView {
                    id: "kz.c".to_owned(),
                    name: name(),
                    version: Version::new(3, 0, 0),
                    replaces: None,
                    origin: acme(),
                    needed_by: Some(None),
                },
                AvailableView {
                    id: "kz.d".to_owned(),
                    name: name(),
                    version: Version::new(4, 0, 0),
                    replaces: None,
                    origin: ReleaseOrigin::Project,
                    needed_by: None,
                },
            ],
        };
        let shown = plugins_view(view);
        assert_eq!(
            shown.catalog,
            CatalogLine::Ready {
                channel: "beta".to_owned(),
                generated,
                error: Some("timed out".to_owned()),
            }
        );
        assert_eq!(shown.installed[0].origin, PluginOrigin::LocalFile);
        assert_eq!(
            shown.installed[0].state,
            PluginStatus::Error("broken".to_owned())
        );
        assert_eq!(shown.installed[1].origin, acme_shown());
        assert_eq!(shown.available[0].origin, acme_shown());
        assert_eq!(shown.available[1].origin, PluginOrigin::Project);
        assert_eq!(shown.installed[1].state, PluginStatus::Withdrawn);
        assert_eq!(shown.installed[0].pending_update, None);
        assert_eq!(shown.installed[0].replacement, Some(text(&name())));
        assert_eq!(shown.installed[1].replacement, None);
        assert_eq!(
            shown.installed[1].pending_update,
            Some(PendingUpdate {
                version: "2.1.0".to_owned(),
                added: vec![CapabilityLine::Files],
                operations: Vec::new(),
                package_sha256: "ab".repeat(32),
                origin: PluginOrigin::Project,
            })
        );
        assert!(shown.available[0].needed && shown.available[0].needed_by.is_none());
        assert!(!shown.available[1].needed);
        // Plugins that could not start: the window says why.
        let off = WindowServices(Err("access denied".to_owned()));
        assert_eq!(
            off.view().catalog,
            CatalogLine::Off("access denied".to_owned())
        );
        assert_eq!(
            off.remove("kz.a"),
            Err(PluginActionError::Failed("access denied".to_owned()))
        );
        assert_eq!(
            off.replace_port("kz.a"),
            Err(PluginActionError::Failed("access denied".to_owned()))
        );
    }
}
