//! «Установка плагина»: [`ask_install_plugin`] asks the user before a plugin is installed,
//! saying who asks (the page's origin as [`page_text`] cleans it), the installed plugin it
//! replaces, what it replaces of the original and what it may do, and warning about a
//! plugin that is not from the catalog. «Установить» is enabled only [`INSTALL_DELAY`]
//! after the window appears: a click or a key meant for another window does not install.
//! One window at a time; requests coming meanwhile wait their turn. Closing the window is
//! «Отмена». Its texts are composed here.
//!
//! A package that declares `[[operations]]` has each of them in the window as a trusted
//! block (the host's words, built from checked fields: the operation's identifier, the kind
//! of key use and the signing profile the core forces, the network, whether servers and the
//! CLI may use it and, for an update, what is new or wider) and, apart, an untrusted frame
//! with the plugin's own label ([`MAX_UNTRUSTED_LABEL`] characters, plain text). An update
//! held for consent ([`RequestKind::Update`]) is asked in the same window; its confirming
//! button says «Обновить», not «Установить». So is a publisher's plugin that replaces an
//! installed port ([`RequestKind::ReplacePort`], Р11): «Заменить» or «Не сейчас».

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oncl_flows::Locale;
use oncl_flows::capabilities::{
    CapabilityLine, OperationConsent, capability_text, is_operation_name,
};
use slint::{
    CloseRequestResponse, ComponentHandle, ModelRc, PlatformError, SharedString, VecModel,
};

use crate::about_view::open_source_link;
use crate::foreground;
use crate::plugins_view::{
    LocalizedText, PluginOrigin, ReplacedBundle, origin_texts, publisher_name,
};
use crate::prompter::select_desktop_language;
use crate::ui::{InstallPluginWindow, OperationBlock};
use crate::view::{page_text, page_text_upto};
use crate::windows::{self, Desktop};

/// How long after the window appears «Установить» is enabled.
pub const INSTALL_DELAY: Duration = Duration::from_millis(1500);

/// The most characters of a plugin's own label the window shows (then `…`): the manifest
/// allows 80, the frame a little less so that it stays a note, not a paragraph.
pub const MAX_UNTRUSTED_LABEL: usize = 60;

/// The most characters of a plugin's own XPath the frame shows (then `…`). The manifest's
/// limit is in bytes (`MAX_XPATH`); a character is at least one byte, so a valid XPath is
/// never shown cut. An XPath is part of what the user's signature
/// covers (it picks the signed element and where the signature goes), so a tail beyond a
/// shorter cut could change what is signed without being read.
pub const MAX_UNTRUSTED_XPATH: usize = oncl_plugin::operations::MAX_XPATH;

/// A plugin about to be installed, and what to do with the user's answer.
pub struct InstallPluginRequest {
    /// The page that asked for it, if one did.
    pub origin: Option<String>,
    pub name: LocalizedText,
    pub version: String,
    pub replaces: Option<ReplacedBundle>,
    /// The installed plugin of the same id it replaces, if any.
    pub replacing: Option<InstalledVersion>,
    /// What it may do.
    pub capabilities: Vec<CapabilityLine>,
    /// What its `[[operations]]` do, each a trusted block and an untrusted label.
    pub operations: Vec<OperationConsent>,
    /// A first install, an update held for consent, or a publisher's plugin replacing a
    /// port: the window says which.
    pub kind: RequestKind,
    /// The plugin window that asked (an update): its closing withdraws the request.
    pub window: Option<u64>,
    /// Who released it: the project, a publisher (named, with the source archive it was
    /// built from) or a file the user chose (warned about).
    pub origin_kind: PluginOrigin,
    /// Called once with the answer (`true`: install), on a thread of its own: it may take
    /// its time.
    pub decide: Decide,
}

/// What takes the user's answer.
pub type Decide = Box<dyn FnOnce(bool) + Send>;

/// What the user is asked to agree to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestKind {
    /// A plugin installed for the first time, or over another version of its own.
    Install,
    /// An update held for consent: «Обновить».
    Update,
    /// A publisher's plugin replacing the installed port `port` at `version` (Р11):
    /// «Заменить» removes the port and its settings, «Не сейчас» keeps it.
    ReplacePort {
        port: LocalizedText,
        version: String,
    },
}

/// An installed plugin a new one replaces: its version and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledVersion {
    pub version: String,
    /// Where it came from.
    pub origin: PluginOrigin,
}

/// The open window and the answer it waits for.
struct Open {
    window: Option<u64>,
    ui: InstallPluginWindow,
    decide: RefCell<Option<Decide>>,
}

thread_local! {
    static OPEN: RefCell<Option<Rc<Open>>> = const { RefCell::new(None) };
    static WAITING: RefCell<VecDeque<InstallPluginRequest>> = const { RefCell::new(VecDeque::new()) };
}

/// Whether the window is open.
pub(crate) fn is_open() -> bool {
    OPEN.with_borrow(Option::is_some)
}

/// Asks the user whether to install `request`'s plugin, in the windows' language; callable
/// from any thread, returns at once. Without the daemon's windows it is declined.
pub fn ask_install_plugin(request: InstallPluginRequest) {
    let slot = Arc::new(Mutex::new(Some(request)));
    let taken = Arc::clone(&slot);
    let asked = slint::invoke_from_event_loop(move || {
        if let Some(request) = take(&taken) {
            enqueue(request);
        }
    });
    if let Err(e) = asked {
        tracing::info!(error = %e, "no windows: the plugin is not installed");
        if let Some(request) = take(&slot) {
            answer_with(request.decide, false);
        }
    }
}

fn take(slot: &Mutex<Option<InstallPluginRequest>>) -> Option<InstallPluginRequest> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}

/// Shows `request` now, or once the window open is answered.
pub(crate) fn enqueue(request: InstallPluginRequest) {
    if windows::desktop().is_none() {
        tracing::info!("no windows: the plugin is not installed");
        answer_with(request.decide, false);
        return;
    }
    WAITING.with_borrow_mut(|waiting| waiting.push_back(request));
    if !is_open() {
        show_next();
    }
}

/// The plugin window `window` is closing: the requests it made are declined, the one on
/// screen too (its answer would have nobody to tell).
pub(crate) fn withdraw(window: u64) {
    let (kept, dropped): (Vec<_>, Vec<_>) = WAITING
        .with_borrow_mut(std::mem::take)
        .into_iter()
        .partition(|r| r.window != Some(window));
    WAITING.with_borrow_mut(|waiting| waiting.extend(kept));
    for request in dropped {
        answer_with(request.decide, false);
    }
    if OPEN.with_borrow(|open| open.as_ref().is_some_and(|o| o.window == Some(window))) {
        answer(false);
    }
}

/// Shows the next request waiting, if any.
fn show_next() {
    let Some(desktop) = windows::desktop() else {
        return;
    };
    while let Some(request) = WAITING.with_borrow_mut(VecDeque::pop_front) {
        match create(&desktop, request) {
            Ok(()) => return,
            Err(e) => tracing::error!(error = %e, "cannot show the plugin installation window"),
        }
    }
}

/// The window of `request`; a window that cannot be shown declines it.
fn create(desktop: &Rc<Desktop>, request: InstallPluginRequest) -> Result<(), PlatformError> {
    let ui = match InstallPluginWindow::new() {
        Ok(ui) => ui,
        Err(e) => {
            answer_with(request.decide, false);
            return Err(e);
        }
    };
    let l = desktop.locale.get();
    select_desktop_language(l);
    fill(&ui, &request, l);
    ui.on_answer(answer);
    ui.window().on_close_requested(|| {
        answer(false);
        CloseRequestResponse::HideWindow
    });
    let open = Rc::new(Open {
        window: request.window,
        ui: ui.clone_strong(),
        decide: RefCell::new(Some(request.decide)),
    });
    OPEN.set(Some(Rc::clone(&open)));
    if let Err(e) = ui.show() {
        OPEN.set(None);
        if let Some(decide) = open.decide.take() {
            answer_with(decide, false);
        }
        return Err(e);
    }
    foreground::take(&ui);
    let weak = ui.as_weak();
    slint::Timer::single_shot(INSTALL_DELAY, move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_can_install(true);
        }
    });
    Ok(())
}

/// Sets the window's texts for `request` in `l`, the source link included.
pub(crate) fn fill(ui: &InstallPluginWindow, request: &InstallPluginRequest, l: Locale) {
    let texts = texts(request, l);
    ui.set_asker(texts.asker.into());
    ui.set_intro(texts.intro.into());
    ui.set_plugin(texts.plugin.into());
    ui.set_replacing(texts.replacing.into());
    ui.set_replaces(texts.replaces.into());
    ui.set_may(texts.may.into());
    let lines: Vec<SharedString> = texts.capabilities.into_iter().map(Into::into).collect();
    ui.set_capabilities(ModelRc::new(VecModel::from(lines)));
    ui.set_window_title(texts.title.into());
    ui.set_confirm_text(texts.confirm.into());
    ui.set_cancel_text(texts.cancel.into());
    ui.set_operations_heading(texts.operations_heading.into());
    let blocks: Vec<OperationBlock> = texts
        .operations
        .into_iter()
        .map(|b| OperationBlock {
            heading: b.heading.into(),
            lines: ModelRc::new(VecModel::from(
                b.lines
                    .into_iter()
                    .map(SharedString::from)
                    .collect::<Vec<_>>(),
            )),
            calls: b.calls.into(),
            label: b.label.into(),
            plugin_lines: ModelRc::new(VecModel::from(
                b.plugin_lines
                    .into_iter()
                    .map(SharedString::from)
                    .collect::<Vec<_>>(),
            )),
        })
        .collect();
    ui.set_operations(ModelRc::new(VecModel::from(blocks)));
    ui.set_warning(texts.warning.into());
    ui.set_publisher(texts.origin.publisher.into());
    ui.set_publisher_note(texts.origin.note.into());
    ui.set_source(texts.origin.source.into());
    let url = texts.origin.url;
    let weak = ui.as_weak();
    ui.on_open_source(move || {
        // The browser must not open behind a window that stays on top.
        if let Some(ui) = weak.upgrade() {
            ui.set_on_top(false);
        }
        open_source_link(&url);
    });
}

/// «Установить» (`true`), «Отмена» or the close button: the window goes, the answer is
/// handed on, and the next request waiting is shown. «Установить» before
/// [`INSTALL_DELAY`] is over does nothing.
fn answer(yes: bool) {
    if yes && OPEN.with_borrow(|open| open.as_ref().is_some_and(|o| !o.ui.get_can_install())) {
        return;
    }
    let Some(open) = OPEN.take() else {
        return;
    };
    if let Err(e) = open.ui.hide() {
        tracing::warn!(error = %e, "cannot hide the plugin installation window");
    }
    if let Some(decide) = open.decide.take() {
        answer_with(decide, yes);
    }
    // This runs inside one of the window's callbacks: release the window after it.
    slint::Timer::single_shot(Duration::ZERO, move || drop(open));
    show_next();
}

/// Hands `yes` to `decide` on a thread of its own: installing a plugin loads it.
fn answer_with(decide: Box<dyn FnOnce(bool) + Send>, yes: bool) {
    let spawned = std::thread::Builder::new()
        .name("plugin-install".into())
        .spawn(move || decide(yes));
    if let Err(e) = spawned {
        tracing::error!(error = %e, "cannot start a thread: the plugin is not installed");
    }
}

/// The window's texts for `request` in `l`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowTexts {
    title: String,
    confirm: String,
    /// The declining button; empty: the window's own «Отмена».
    cancel: String,
    operations_heading: String,
    operations: Vec<BlockTexts>,
    asker: String,
    /// What a replacement of a port does, above everything else; or empty.
    intro: String,
    plugin: String,
    replacing: String,
    replaces: String,
    may: String,
    capabilities: Vec<String>,
    warning: String,
    /// The publisher, the note on a publisher's plugin and its source archive.
    origin: crate::plugins_view::OriginTexts,
}

/// One operation: `heading` and `lines` are the host's words (checked fields only), `calls`
/// and `label` the plugin's frame.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockTexts {
    heading: String,
    lines: Vec<String>,
    calls: String,
    label: String,
    /// More of the plugin's own text (its XPaths), each captioned.
    plugin_lines: Vec<String>,
}

/// A plugin's own text for the frame: control characters and bidirectional controls gone
/// ([`page_text`]), at most [`MAX_UNTRUSTED_LABEL`] characters, then `…`. Drawn as plain
/// text: there is no markup in a Slint `Text`.
pub(crate) fn untrusted_label(text: &str) -> String {
    cut(&page_text(text), MAX_UNTRUSTED_LABEL)
}

/// A plugin's own XPath for the frame: control and bidirectional characters gone, and shown
/// whole (at most [`MAX_UNTRUSTED_XPATH`] characters, which no valid XPath exceeds).
pub(crate) fn untrusted_xpath(text: &str) -> String {
    page_text_upto(text, MAX_UNTRUSTED_XPATH)
}

/// `text` of at most `max` characters, then `…` if it was longer.
pub(crate) fn cut(text: &str, max: usize) -> String {
    let mut chars = text.chars();
    let mut shown: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        shown.push('…');
    }
    shown
}

fn block(operation: &OperationConsent, l: Locale) -> BlockTexts {
    let t = Texts::of(l);
    BlockTexts {
        // The identifier was checked at parse and is checked again here: a name that is not
        // one (a caller that skipped the parse) is not drawn.
        heading: if is_operation_name(&operation.name) {
            t.operation.replace("{name}", &operation.name)
        } else {
            t.operation_invalid.to_owned()
        },
        lines: operation
            .lines
            .iter()
            .map(|c| capability_text(c, l))
            .collect(),
        calls: t.calls.to_owned(),
        label: untrusted_label(operation.label(l)),
        plugin_lines: operation
            .xpaths
            .iter()
            .map(|x| t.xpath.replace("{0}", &untrusted_xpath(x)))
            .chain(
                operation
                    .bindings
                    .iter()
                    .map(|b| t.binding.replace("{0}", &untrusted_xpath(b))),
            )
            .collect(),
    }
}

fn texts(request: &InstallPluginRequest, l: Locale) -> WindowTexts {
    let t = Texts::of(l);
    let (title, confirm_text, cancel, plugin, may) = match &request.kind {
        RequestKind::Install => (t.title_install, t.confirm_install, "", t.plugin, t.may),
        RequestKind::Update => (
            t.title_update,
            t.confirm_update,
            "",
            t.plugin_update,
            t.may_update,
        ),
        RequestKind::ReplacePort { .. } => (
            t.title_replace,
            t.confirm_replace,
            t.cancel_replace,
            t.plugin,
            t.may_replace,
        ),
    };
    WindowTexts {
        title: title.to_owned(),
        confirm: confirm_text.to_owned(),
        cancel: cancel.to_owned(),
        operations_heading: if request.operations.is_empty() {
            String::new()
        } else {
            t.operations.to_owned()
        },
        operations: request.operations.iter().map(|o| block(o, l)).collect(),
        asker: request
            .origin
            .as_ref()
            .map(|origin| t.asker.replace("{0}", &page_text(origin)))
            .unwrap_or_default(),
        intro: match &request.kind {
            // The port's name is its manifest's: quoted like any plugin's own name.
            RequestKind::ReplacePort { port, version } => t
                .replace_port
                .replace("{version}", version)
                .replace("{port}", &quoted_name(port.get(l))),
            RequestKind::Install | RequestKind::Update => String::new(),
        },
        plugin: plugin
            // The plugin's own name: cleaned, quoted and said to be the plugin's words, like
            // the label and the XPaths (the parse-time check is not the only defence).
            .replace("{version}", &request.version)
            .replace("{name}", &quoted_name(request.name.get(l))),
        replacing: request
            .replacing
            .as_ref()
            .map(|installed| {
                t.replacing
                    .replace("{version}", &installed.version)
                    .replace(
                        "{source}",
                        &match &installed.origin {
                            PluginOrigin::LocalFile => t.installed_local.to_owned(),
                            PluginOrigin::Project | PluginOrigin::Unknown => {
                                t.installed_catalog.to_owned()
                            }
                            PluginOrigin::Publisher(publisher) => t
                                .installed_publisher
                                .replace("{name}", &publisher_name(&publisher.display, l)),
                        },
                    )
            })
            .unwrap_or_default(),
        replaces: request
            .replaces
            .as_ref()
            .map(|r| {
                t.replaces
                    .replace("{symname}", &r.symname)
                    .replace("{version}", &r.version)
            })
            .unwrap_or_default(),
        may: if !request.capabilities.is_empty() {
            may.to_owned()
        } else if request.operations.is_empty() {
            t.nothing.to_owned()
        } else {
            String::new()
        },
        capabilities: request
            .capabilities
            .iter()
            .map(|c| capability_text(c, l))
            .collect(),
        warning: if request.origin_kind == PluginOrigin::LocalFile {
            t.local.to_owned()
        } else {
            String::new()
        },
        origin: origin_texts(&request.origin_kind, l),
    }
}

/// The plugin's own name for a line of the host's: cleaned like every plugin text, in double
/// quotes, with the quote and the backslash spelled out so that the name cannot close its own
/// quotes and pose as the host's words after them.
fn quoted_name(name: &str) -> String {
    let cleaned = untrusted_label(name);
    format!("\"{}\"", cleaned.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The caption of the frame that holds a plugin's own label, in `l`: whose words they are.
/// The Plugins page of the manual window puts the same frame under the same caption.
pub(crate) fn frame_caption(l: Locale) -> &'static str {
    Texts::of(l).calls
}

/// The caption of a plugin's own XPath in the frame, in `l`; `{0}` is the XPath.
pub(crate) fn frame_xpath(l: Locale) -> &'static str {
    Texts::of(l).xpath
}

/// The caption of a plugin's own namespace binding in the frame, in `l`; `{0}` is the
/// binding.
pub(crate) fn frame_binding(l: Locale) -> &'static str {
    Texts::of(l).binding
}

/// The texts of the window, in one language.
struct Texts {
    /// `{0}`: the page's origin.
    asker: &'static str,
    /// `{name}`, `{version}`.
    plugin: &'static str,
    /// `{name}`, `{version}`: an update.
    plugin_update: &'static str,
    title_install: &'static str,
    title_update: &'static str,
    confirm_install: &'static str,
    confirm_update: &'static str,
    may_update: &'static str,
    /// The heading of the operations.
    operations: &'static str,
    /// `{name}`: an operation's identifier.
    operation: &'static str,
    /// An operation whose name is not an identifier.
    operation_invalid: &'static str,
    /// `{0}`: the plugin's XPath.
    xpath: &'static str,
    /// `{0}`: `prefix = URI`, or `* = URI` for every other prefix.
    binding: &'static str,
    /// The frame of the plugin's own label.
    calls: &'static str,
    /// `{version}`, `{source}`: [`Texts::installed_local`] or [`Texts::installed_catalog`].
    replacing: &'static str,
    installed_local: &'static str,
    installed_catalog: &'static str,
    /// `{name}`: the publisher. The Kazakh one is a draft for the translator.
    installed_publisher: &'static str,
    /// `{symname}`, `{version}`.
    replaces: &'static str,
    may: &'static str,
    nothing: &'static str,
    local: &'static str,
    /// A publisher's plugin replacing a port (Р11); the Kazakh ones are drafts for the
    /// translator.
    title_replace: &'static str,
    confirm_replace: &'static str,
    cancel_replace: &'static str,
    /// `{port}`: the port's name, quoted; `{version}`: its version.
    replace_port: &'static str,
    may_replace: &'static str,
}

impl Texts {
    fn of(l: Locale) -> &'static Texts {
        match l {
            Locale::Kk => &Texts {
                asker: "{0} сайты плагинді орнатуды сұрайды",
                plugin: "{name} (плагиннің өз атауы), {version} нұсқасы",
                plugin_update: "{name} (плагиннің өз атауы), {version} нұсқасына жаңарту",
                title_install: "Плагинді орнату",
                title_update: "Плагинді жаңарту",
                confirm_install: "Орнату",
                confirm_update: "Жаңарту",
                may_update: "Жаңарту қосымша мыналарды істей алады:",
                operations: "Плагин қолмен жұмыс терезесінде мына әрекеттерді ұсынады (әрқайсысын бағдарлама сипаттайды):",
                operation: "Әрекет {name}",
                operation_invalid: "Атауы жарамсыз әрекет",
                xpath: "Плагиннің XPath мәтіні: {0}",
                binding: "Плагиннің XPath үшін аттар кеңістігі байланысы (* — кез келген басқа префикс): {0}",
                calls: "Плагин оны былай атайды (плагиннің өз сөзі, тексерілмеген):",
                replacing: "Орнатылған {version} нұсқасын ({source}) алмастырады",
                installed_local: "жергілікті, файлдан",
                installed_catalog: "каталогтан",
                installed_publisher: "{name} жариялаушысынан",
                replaces: "Түпнұсқа NCALayer-дің {symname} {version} бандлын алмастырады",
                may: "Плагин мыналарды істей алады:",
                nothing: "Плагин сайттардың сұрауларына ғана жауап береді.",
                local: "Бұл плагин OpenNCALayer каталогында жоқ, оны мейнтейнер тексерген жоқ. Плагиндерді тек сенімді көзден орнатыңыз.",
                title_replace: "Портты алмастыру",
                confirm_replace: "Алмастыру",
                cancel_replace: "Қазір емес",
                replace_port: "Жариялаушының плагині орнатылған {port} портын ({version} нұсқасы) алмастырады. Порт пен оның баптаулары жойылады.",
                may_replace: "Жаңа плагин мыналарды істей алады:",
            },
            Locale::Ru => &Texts {
                asker: "Сайт {0} просит установить плагин",
                plugin: "{name} (название от самого плагина), версия {version}",
                plugin_update: "{name} (название от самого плагина), обновление до версии {version}",
                title_install: "Установка плагина",
                title_update: "Обновление плагина",
                confirm_install: "Установить",
                confirm_update: "Обновить",
                may_update: "Обновление сможет ещё:",
                operations: "Плагин предлагает в окне ручных инструментов такие действия (каждое описывает программа):",
                operation: "Действие {name}",
                operation_invalid: "Действие с недопустимым именем",
                xpath: "XPath от плагина: {0}",
                binding: "Привязка пространства имён для XPath от плагина (* — любой другой префикс): {0}",
                calls: "Плагин называет его так (слова самого плагина, не проверены):",
                replacing: "Заменит установленную версию {version} ({source})",
                installed_local: "локальную, из файла",
                installed_catalog: "из каталога",
                installed_publisher: "от издателя {name}",
                replaces: "Заменяет {symname} {version} оригинального NCALayer",
                may: "Плагин сможет:",
                nothing: "Плагин будет только отвечать на запросы сайтов.",
                local: "Этого плагина нет в каталоге OpenNCALayer, его не проверял мейнтейнер. Устанавливайте только плагины из источника, которому доверяете.",
                title_replace: "Замена порта",
                confirm_replace: "Заменить",
                cancel_replace: "Не сейчас",
                replace_port: "Плагин издателя заменит установленный порт {port} (версия {version}). Порт и его настройки будут удалены.",
                may_replace: "Новый плагин сможет:",
            },
            Locale::En => &Texts {
                asker: "The site {0} asks to install a plugin",
                plugin: "{name} (the plugin's own name), version {version}",
                plugin_update: "{name} (the plugin's own name), update to version {version}",
                title_install: "Plugin installation",
                title_update: "Plugin update",
                confirm_install: "Install",
                confirm_update: "Update",
                may_update: "The update will also be able to:",
                operations: "The plugin offers these operations in the manual-tools window (the program describes each):",
                operation: "Operation {name}",
                operation_invalid: "An operation with an invalid name",
                xpath: "The plugin's XPath: {0}",
                binding: "The plugin's namespace binding for XPaths (* is every other prefix): {0}",
                calls: "The plugin calls it (the plugin's own words, not checked):",
                replacing: "Replaces the installed version {version} ({source})",
                installed_local: "local, from a file",
                installed_catalog: "from the catalog",
                installed_publisher: "from the publisher {name}",
                replaces: "Replaces {symname} {version} of the original NCALayer",
                may: "The plugin will be able to:",
                nothing: "The plugin will only answer the sites' requests.",
                local: "This plugin is not in the OpenNCALayer catalog; the maintainer has not reviewed it. Install plugins only from a source you trust.",
                title_replace: "Port replacement",
                confirm_replace: "Replace",
                cancel_replace: "Not now",
                replace_port: "A publisher's plugin will replace the installed port {port} (version {version}). The port and its settings will be removed.",
                may_replace: "The new plugin will be able to:",
            },
        }
    }
}

/// The window on the offscreen platform of the tests.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins_view::fakes::FakePlugins;
    use crate::settings_view::fakes::{FakeOriginal, services};
    use crate::windows::{DesktopWindows, set_desktop_windows};
    use crate::{AboutInfo, offscreen};
    use oncl_flows::capabilities::{AddedLine, KeyUseKind, NetworkLine, ProfileFact, TsaFamily};
    use slint::Model;
    use std::sync::mpsc::{Receiver, channel};

    const ALL: [Locale; 3] = [Locale::Ru, Locale::Kk, Locale::En];

    /// An operation as the host says it: a CMS signature, detached, with a time-stamp from
    /// the basics TSA, the PKI network, manual only. The label and the plugin's name below
    /// are marked texts the trusted lines must never contain.
    fn operation(name: &str, label: &str) -> OperationConsent {
        OperationConsent {
            name: name.to_owned(),
            lines: vec![
                CapabilityLine::KeyUse(KeyUseKind::Cms),
                CapabilityLine::KeyProfile(vec![
                    ProfileFact::Detached,
                    ProfileFact::Timestamp(TsaFamily::Basics),
                ]),
                CapabilityLine::OperationNetwork(NetworkLine::Pki),
                CapabilityLine::OperationServer(false),
            ],
            label: [label.to_owned(), label.to_owned(), label.to_owned()],
            xpaths: Vec::new(),
            bindings: Vec::new(),
        }
    }

    fn with_operations(operations: Vec<OperationConsent>, update: bool) -> InstallPluginRequest {
        let (mut request, _rx) = request(false, None);
        request.capabilities.clear();
        request.operations = operations;
        request.kind = if update {
            RequestKind::Update
        } else {
            RequestKind::Install
        };
        request
    }

    fn desktop(root: &std::path::Path, locale: Locale) {
        offscreen::install();
        set_desktop_windows(DesktopWindows {
            locale,
            settings: services(root, FakeOriginal::default()),
            about: AboutInfo::default(),
            tls: crate::tls_wizard::fakes::services(root, Vec::new(), None),
            plugins: Box::new(FakePlugins::default()),
            scale: oncl_desktop::UiScale::default(),
            on_saved: Box::new(|_: &oncl_desktop::Settings| {}),
        });
    }

    fn request(local: bool, origin: Option<&str>) -> (InstallPluginRequest, Receiver<bool>) {
        let (tx, rx) = channel();
        let request = InstallPluginRequest {
            origin: origin.map(str::to_owned),
            name: LocalizedText {
                ru: "Пример плагина".to_owned(),
                kk: "Плагин үлгісі".to_owned(),
                en: "Example plugin".to_owned(),
            },
            version: "0.1.0".to_owned(),
            replaces: Some(ReplacedBundle {
                symname: "kz.example.echo".to_owned(),
                version: "1.0.0".to_owned(),
            }),
            replacing: None,
            operations: Vec::new(),
            kind: RequestKind::Install,
            window: None,
            capabilities: vec![
                CapabilityLine::Keys,
                CapabilityLine::Dialogs,
                CapabilityLine::Files,
                CapabilityLine::Http(vec!["https://example.invalid/".to_owned()]),
            ],
            origin_kind: if local {
                PluginOrigin::LocalFile
            } else {
                PluginOrigin::Project
            },
            decide: Box::new(move |yes| tx.send(yes).unwrap()),
        };
        (request, rx)
    }

    fn the_window() -> InstallPluginWindow {
        OPEN.with_borrow(|open| open.as_ref().expect("the window is open").ui.clone_strong())
    }

    fn answered(rx: &Receiver<bool>) -> bool {
        rx.recv_timeout(Duration::from_secs(30)).expect("an answer")
    }

    /// Waits out [`INSTALL_DELAY`]: «Установить» works then, not before.
    fn armed(ui: &InstallPluginWindow) {
        assert!(!ui.get_can_install());
        ui.invoke_answer(true);
        assert!(is_open(), "«Установить» does nothing yet");
        std::thread::sleep(INSTALL_DELAY + Duration::from_millis(100));
        slint::platform::update_timers_and_animations();
        assert!(ui.get_can_install());
    }

    #[test]
    fn install_says_yes() {
        let dir = tempfile::tempdir().unwrap();
        desktop(dir.path(), Locale::Ru);
        let (request, rx) = request(false, Some("https://shop.kz"));
        enqueue(request);
        let ui = the_window();
        assert_eq!(
            ui.get_asker(),
            "Сайт https://shop.kz просит установить плагин"
        );
        assert_eq!(
            ui.get_plugin(),
            "\"Пример плагина\" (название от самого плагина), версия 0.1.0"
        );
        assert_eq!(
            ui.get_replaces(),
            "Заменяет kz.example.echo 1.0.0 оригинального NCALayer"
        );
        assert_eq!(ui.get_may(), "Плагин сможет:");
        let lines: Vec<String> = ui
            .get_capabilities()
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            lines,
            [
                "выбирать ваш ключ и подписывать им",
                "показывать окна",
                "открывать и сохранять файлы, которые вы выберете",
                "обращаться к https://example.invalid/",
            ]
        );
        assert_eq!(ui.get_warning(), "", "a catalog plugin is not warned about");
        assert_eq!(ui.get_replacing(), "");
        armed(&ui);
        ui.invoke_answer(true);
        assert!(answered(&rx));
        assert!(!is_open());
    }

    #[test]
    fn cancel_and_close_say_no() {
        let dir = tempfile::tempdir().unwrap();
        desktop(dir.path(), Locale::Ru);
        let (mut first, first_rx) = request(true, None);
        first.replacing = Some(InstalledVersion {
            version: "0.0.9".to_owned(),
            origin: PluginOrigin::Project,
        });
        let (second, second_rx) = request(false, None);
        enqueue(first);
        // Waits for the first.
        enqueue(second);
        let ui = the_window();
        assert_eq!(ui.get_asker(), "");
        assert!(
            ui.get_warning()
                .starts_with("Этого плагина нет в каталоге OpenNCALayer"),
            "{}",
            ui.get_warning()
        );
        assert_eq!(
            ui.get_replacing(),
            "Заменит установленную версию 0.0.9 (из каталога)"
        );
        // «Отмена» works at once.
        ui.invoke_answer(false);
        assert!(!answered(&first_rx));
        // The second is shown now; closing it is no.
        let ui = the_window();
        assert_eq!(ui.get_warning(), "");
        ui.window()
            .dispatch_event(slint::platform::WindowEvent::CloseRequested);
        assert!(!answered(&second_rx));
        assert!(!is_open());
    }

    #[test]
    fn texts_in_every_language() {
        for l in [Locale::Kk, Locale::En] {
            let (request, _rx) = request(true, Some("https://shop.kz"));
            let ours = texts(&request, l);
            let ru = texts(&request, Locale::Ru);
            assert!(ours.asker.contains("https://shop.kz"), "{l:?}");
            assert!(
                ours.plugin.contains(&quoted_name(request.name.get(l))),
                "{l:?}"
            );
            assert_ne!(ours.may, ru.may, "{l:?}");
            assert_ne!(ours.warning, ru.warning, "{l:?}");
            assert_eq!(ours.capabilities.len(), 4);
            assert!(ours.capabilities[3].contains("https://example.invalid/"));
            for (a, b) in ours.capabilities.iter().zip(&ru.capabilities) {
                assert_ne!(a, b, "{l:?}");
            }
        }
        let (mut request, _rx) = request(false, None);
        request.capabilities.clear();
        assert_eq!(
            texts(&request, Locale::Ru).may,
            "Плагин будет только отвечать на запросы сайтов."
        );
    }

    #[test]
    fn the_origin_is_cleaned_and_the_replaced_version_named() {
        let (mut request, _rx) = request(true, Some("https://shop.kz\u{202E}moc.live\n.kz"));
        let ru = texts(&request, Locale::Ru);
        assert_eq!(
            ru.asker,
            "Сайт https://shop.kzmoc.live.kz просит установить плагин"
        );
        assert_eq!(ru.replacing, "");
        let long = format!("https://{}.kz", "a".repeat(200));
        request.origin = Some(long);
        assert!(texts(&request, Locale::En).asker.contains('…'));
        request.replacing = Some(InstalledVersion {
            version: "0.0.9".to_owned(),
            origin: PluginOrigin::LocalFile,
        });
        assert_eq!(
            texts(&request, Locale::En).replacing,
            "Replaces the installed version 0.0.9 (local, from a file)"
        );
        assert_eq!(
            texts(&request, Locale::Ru).replacing,
            "Заменит установленную версию 0.0.9 (локальную, из файла)"
        );
        assert!(texts(&request, Locale::Kk).replacing.contains("0.0.9"));
    }

    #[test]
    fn without_operations_the_window_is_as_it_was() {
        for l in ALL {
            let (request, _rx) = request(false, None);
            let t = texts(&request, l);
            assert!(
                t.operations.is_empty() && t.operations_heading.is_empty(),
                "{l:?}"
            );
            assert_eq!(t.title, Texts::of(l).title_install);
            assert_eq!(t.confirm, Texts::of(l).confirm_install);
            assert_eq!(t.may, Texts::of(l).may);
            assert_eq!(t.plugin, texts(&request, l).plugin);
        }
        assert_eq!(
            texts(&with_operations(Vec::new(), false), Locale::En).may,
            "The plugin will only answer the sites' requests."
        );
    }

    #[test]
    fn a_signing_operation_is_said_in_the_hosts_words_in_every_language() {
        let request = with_operations(vec![operation("sign-file", "LABEL-ONE")], false);
        let en = texts(&request, Locale::En);
        assert_eq!(en.operations.len(), 1);
        assert_eq!(en.operations[0].heading, "Operation sign-file");
        assert_eq!(
            en.operations[0].lines,
            [
                "signs with your key: a CMS (PKCS#7) signature",
                "signature form (fixed by the core): detached (the content is not inside); \
                 time-stamp from the basics TSA",
                "network: the PKI servers of the core only",
                "the manual window only (not for servers or the CLI)",
            ]
        );
        assert_eq!(
            en.operations[0].calls,
            "The plugin calls it (the plugin's own words, not checked):"
        );
        assert_eq!(en.operations[0].label, "LABEL-ONE");
        assert_eq!(en.may, "", "no capabilities: no heading for them");
        let ru = texts(&request, Locale::Ru);
        assert_eq!(
            ru.operations[0].lines[0],
            "подписывает вашим ключом: подпись CMS (PKCS#7)"
        );
        let kk = texts(&request, Locale::Kk);
        for (a, b, c) in [(&ru.operations[0], &kk.operations[0], &en.operations[0])] {
            assert!(a.heading != b.heading && a.heading != c.heading && b.heading != c.heading);
            assert!(a.calls != b.calls && a.calls != c.calls && b.calls != c.calls);
            for ((x, y), z) in a.lines.iter().zip(&b.lines).zip(&c.lines) {
                assert!(x != y && x != z && y != z, "{x} | {y} | {z}");
            }
        }
    }

    #[test]
    fn every_window_text_exists_and_differs_in_every_language() {
        let all = |f: fn(&Texts) -> &'static str| {
            let ru = f(Texts::of(Locale::Ru));
            let kk = f(Texts::of(Locale::Kk));
            let en = f(Texts::of(Locale::En));
            assert!(!ru.is_empty() && !kk.is_empty() && !en.is_empty());
            assert!(ru != kk && ru != en && kk != en, "{ru} | {kk} | {en}");
        };
        all(|t| t.title_install);
        all(|t| t.title_update);
        all(|t| t.confirm_install);
        all(|t| t.confirm_update);
        all(|t| t.plugin_update);
        all(|t| t.may_update);
        all(|t| t.operations);
        all(|t| t.operation);
        all(|t| t.calls);
    }

    #[test]
    fn several_operations_each_have_their_own_block() {
        let request = with_operations(
            vec![operation("sign-a", "A"), operation("sign-b", "B")],
            false,
        );
        for l in ALL {
            let t = texts(&request, l);
            assert_eq!(t.operations.len(), 2);
            assert!(t.operations[0].heading.contains("sign-a"));
            assert!(t.operations[1].heading.contains("sign-b"));
            assert_eq!(t.operations[1].label, "B");
        }
    }

    #[test]
    fn an_update_names_what_is_new_or_wider_and_a_narrowing_says_nothing() {
        let mut wider = operation("fetch", "Fetch");
        wider
            .lines
            .insert(0, CapabilityLine::Added(AddedLine::Network));
        wider.lines[3] = CapabilityLine::OperationNetwork(NetworkLine::Urls(vec![
            "https://api.example.kz/".to_owned(),
        ]));
        let mut new_key = operation("sign", "Sign");
        new_key
            .lines
            .insert(0, CapabilityLine::Added(AddedLine::New));
        new_key
            .lines
            .insert(1, CapabilityLine::Added(AddedLine::KeyUse));
        let unchanged = operation("keep", "Keep");
        let request = with_operations(vec![wider, new_key, unchanged], true);
        for l in ALL {
            let t = texts(&request, l);
            let net = &t.operations[0].lines;
            assert_eq!(
                net[0],
                capability_text(&CapabilityLine::Added(AddedLine::Network), l)
            );
            assert!(
                net.iter().any(|x| x.contains("https://api.example.kz/")),
                "{net:?}"
            );
            assert_eq!(
                t.operations[1].lines[0],
                capability_text(&CapabilityLine::Added(AddedLine::New), l)
            );
            assert_eq!(
                t.operations[1].lines[1],
                capability_text(&CapabilityLine::Added(AddedLine::KeyUse), l)
            );
            // Narrowed or unchanged: no «new or wider» line.
            let marker = capability_text(&CapabilityLine::Added(AddedLine::New), l);
            let prefix = marker.split(':').next().unwrap().to_owned();
            assert!(
                t.operations[2]
                    .lines
                    .iter()
                    .all(|x| !x.starts_with(&prefix)),
                "{l:?}: {:?}",
                t.operations[2].lines
            );
        }
        let en = texts(&request, Locale::En);
        assert_eq!(en.title, "Plugin update");
        assert_eq!(en.confirm, "Update");
        assert_eq!(
            en.plugin,
            "\"Example plugin\" (the plugin's own name), update to version 0.1.0"
        );
    }

    #[test]
    fn the_plugins_words_never_reach_the_trusted_block() {
        let mut op = operation("sign-file", "UNTRUSTED-LABEL");
        op.label = [
            "РУ-МЕТКА-ПЛАГИНА".to_owned(),
            "КК-МЕТКА-ПЛАГИНА".to_owned(),
            "EN-LABEL-PLUGIN".to_owned(),
        ];
        let request = with_operations(vec![op], true);
        for l in ALL {
            let t = texts(&request, l);
            let block = &t.operations[0];
            let trusted = format!("{}\n{}", block.heading, block.lines.join("\n"));
            for secret in [
                request.name.get(l).to_owned(),
                request.name.ru.clone(),
                request.name.kk.clone(),
                request.name.en.clone(),
                "МЕТКА-ПЛАГИНА".to_owned(),
                "EN-LABEL-PLUGIN".to_owned(),
                "UNTRUSTED-LABEL".to_owned(),
            ] {
                assert!(!trusted.contains(&secret), "{l:?}: {secret} in {trusted}");
            }
            assert!(
                block.label.contains("МЕТКА-ПЛАГИНА") || block.label.contains("EN-LABEL"),
                "the label is in the frame: {}",
                block.label
            );
            assert_ne!(block.calls, "");
        }
    }

    /// The plugin's name is on a line of the host's: it is quoted, cleaned, and said to be the
    /// plugin's own, so it cannot pass for the host's words (mutation: the raw name fails).
    #[test]
    fn the_plugins_name_in_the_host_line_is_quoted_cleaned_and_marked() {
        let (mut request, _rx) = request(true, None);
        let crafted = "Core\u{202E} verified\n\" Allow everything \\";
        request.name = LocalizedText {
            ru: crafted.to_owned(),
            kk: crafted.to_owned(),
            en: crafted.to_owned(),
        };
        for l in ALL {
            let line = texts(&request, l).plugin;
            assert!(
                !line.contains('\u{202E}') && !line.contains('\n'),
                "{line:?}"
            );
            // The quote inside the name is escaped: the name cannot end its own quotes.
            assert!(line.contains("\\\" Allow everything"), "{l:?}: {line}");
            assert!(line.starts_with('"'), "{l:?}: {line}");
            assert!(
                line.contains("(the plugin's own name)")
                    || line.contains("(название от самого плагина)")
                    || line.contains("(плагиннің өз атауы)"),
                "{l:?}: {line}"
            );
        }
    }

    #[test]
    fn a_plugins_xpath_is_framed_whole_and_never_a_host_line() {
        // The longest the manifest allows (1024 bytes): shown to its last character, in the
        // plugin's frame, so no tail of what is signed stays unread.
        let head = "/a/Install / Allow / Core verified ";
        let crafted = format!(
            "{head}{}/TAIL",
            "x".repeat(oncl_plugin::operations::MAX_XPATH - head.len() - "/TAIL".len())
        );
        assert_eq!(crafted.len(), oncl_plugin::operations::MAX_XPATH);
        let mut op = operation("sign-file", "Sign");
        op.xpaths = vec![crafted.clone()];
        let request = with_operations(vec![op], false);
        for l in ALL {
            let b = &texts(&request, l).operations[0];
            let host = format!("{}\n{}", b.heading, b.lines.join("\n"));
            assert!(
                !host.contains("Core verified") && !host.contains("Allow"),
                "{host}"
            );
            assert_eq!(b.plugin_lines.len(), 1);
            assert!(b.plugin_lines[0].contains("Core verified"));
            assert!(b.plugin_lines[0].contains(&crafted), "{l:?}: cut");
            assert!(!b.plugin_lines[0].ends_with('…'));
        }
    }

    /// The transforms line (every kind, each in the language of the dialog) and the plugin's
    /// namespace bindings reach the install dialog: the line as the host's own words, the
    /// bindings in the plugin's frame.
    #[test]
    fn transforms_and_bindings_reach_the_install_dialog() {
        use oncl_flows::capabilities::TransformKind as K;
        let facts = vec![
            ProfileFact::XmlTransforms(vec![K::Enveloped, K::ExclusiveWithComments]),
            ProfileFact::XmlTransforms(vec![K::Inclusive]),
            ProfileFact::XmlTransforms(vec![K::InclusiveWithComments]),
            ProfileFact::XmlTransforms(vec![K::Exclusive]),
        ];
        let mut op = operation("sign-xml", "Sign");
        op.lines = facts
            .iter()
            .map(|f| CapabilityLine::KeyProfile(vec![f.clone()]))
            .collect();
        op.bindings = vec!["SOAP-ENV = urn:soap".to_owned(), "* = urn:dsig".to_owned()];
        let request = with_operations(vec![op], false);
        for l in ALL {
            let b = &texts(&request, l).operations[0];
            for f in &facts {
                let line = capability_text(&CapabilityLine::KeyProfile(vec![f.clone()]), l);
                assert!(b.lines.contains(&line), "{l:?}: {line}");
            }
            assert_eq!(b.plugin_lines.len(), 2, "{l:?}");
            assert!(b.plugin_lines[0].contains("SOAP-ENV = urn:soap"), "{l:?}");
            assert!(b.plugin_lines[1].contains("* = urn:dsig"), "{l:?}");
            let host = b.lines.join("\n");
            assert!(!host.contains("urn:dsig"), "{l:?}");
        }
    }

    #[test]
    fn a_name_that_is_not_an_identifier_is_not_drawn() {
        let request = with_operations(
            vec![
                operation("Sign: Install now\u{202E}", "x"),
                operation("sign-ok", "x"),
            ],
            false,
        );
        for l in ALL {
            let t = texts(&request, l);
            assert_eq!(t.operations[0].heading, Texts::of(l).operation_invalid);
            assert!(!t.operations[0].heading.contains("Install"));
            assert!(t.operations[1].heading.contains("sign-ok"));
        }
    }

    #[test]
    fn withdrawing_a_plugin_window_declines_its_requests_only() {
        let dir = tempfile::tempdir().unwrap();
        desktop(dir.path(), Locale::Ru);
        let (mut first, first_rx) = request(false, None);
        first.window = Some(7);
        let (mut second, second_rx) = request(false, None);
        second.window = Some(7);
        let (third, third_rx) = request(false, None);
        enqueue(first);
        enqueue(second);
        enqueue(third);
        withdraw(7);
        assert!(!answered(&first_rx));
        assert!(!answered(&second_rx));
        // The one that was not asked by that window is on screen now.
        assert!(is_open());
        assert!(third_rx.try_recv().is_err());
        the_window().invoke_answer(false);
        assert!(!answered(&third_rx));
    }

    #[test]
    fn the_untrusted_label_is_plain_clean_and_cut_with_an_ellipsis() {
        assert_eq!(untrusted_label("Sign a file"), "Sign a file");
        // Markup stays text; controls and bidi are gone.
        assert_eq!(untrusted_label("<b>x</b>\u{202E}\n\u{7}y"), "<b>x</b>y");
        let long = "я".repeat(MAX_UNTRUSTED_LABEL + 5);
        let shown = untrusted_label(&long);
        assert_eq!(shown.chars().count(), MAX_UNTRUSTED_LABEL + 1);
        assert!(shown.ends_with('…'));
        let exact = "я".repeat(MAX_UNTRUSTED_LABEL);
        assert_eq!(untrusted_label(&exact), exact);
    }

    #[test]
    fn the_confirming_button_names_its_action() {
        let dir = tempfile::tempdir().unwrap();
        desktop(dir.path(), Locale::Ru);
        let (request, _rx) = request(false, None);
        enqueue(request);
        let ui = the_window();
        assert_eq!(ui.get_confirm_text(), "Установить");
        assert_eq!(ui.get_window_title(), "Установка плагина");
        ui.invoke_answer(false);
        let mut update = with_operations(vec![operation("sign-file", "Sign")], true);
        update.kind = RequestKind::Update;
        enqueue(update);
        let ui = the_window();
        assert_eq!(ui.get_confirm_text(), "Обновить");
        assert_eq!(ui.get_window_title(), "Обновление плагина");
        assert_eq!(ui.get_operations().row_count(), 1);
        let block = ui.get_operations().row_data(0).unwrap();
        assert_eq!(block.heading, "Действие sign-file");
        assert_eq!(block.label, "Sign");
        assert_eq!(block.lines.row_count(), 4);
        ui.invoke_answer(false);
        for l in ALL {
            for update in [false, true] {
                let t = texts(&with_operations(Vec::new(), update), l);
                for plain in ["OK", "ОК", "Ok", "Ок", "Да", "Yes", "Иә"] {
                    assert_ne!(t.confirm, plain);
                }
            }
        }
    }

    #[test]
    fn without_windows_it_is_declined() {
        // A thread without the daemon's windows.
        std::thread::spawn(|| {
            let (request, rx) = request(false, None);
            enqueue(request);
            assert!(!answered(&rx));
        })
        .join()
        .unwrap();
    }

    /// A publisher's plugin whose release the catalog lists with its source archive.
    fn acme(url: &str) -> PluginOrigin {
        PluginOrigin::Publisher(crate::plugins_view::PublisherOrigin {
            display: LocalizedText {
                ru: "ТОО «Акме»".to_owned(),
                kk: "«Акме» ЖШС".to_owned(),
                en: "Acme LLP".to_owned(),
            },
            source: Some(crate::plugins_view::SourceArchive {
                file: "kz.acme.market-1.2.0.src.tar.gz".to_owned(),
                url: url.to_owned(),
                license: "Apache-2.0".to_owned(),
            }),
        })
    }

    const ACME_SOURCE: &str = concat!(
        env!("CARGO_PKG_REPOSITORY"),
        "/releases/download/pub-acme-0909090909090909090909090909090909090909090909090909090909090909/kz.acme.market-1.2.0.src.tar.gz"
    );

    /// Without the daemon's windows a port replacement is declined, as an install is: the
    /// daemon records it and offers it again from the port's row.
    #[test]
    fn without_windows_a_replacement_is_declined() {
        std::thread::spawn(|| {
            let (replace, rx) = replacement();
            enqueue(replace);
            assert!(!answered(&rx));
        })
        .join()
        .unwrap();
    }

    #[test]
    fn a_publishers_plugin_names_its_publisher_and_links_its_source() {
        let (mut request, _rx) = request(false, None);
        request.origin_kind = acme(ACME_SOURCE);
        let ru = texts(&request, Locale::Ru);
        assert_eq!(ru.origin.publisher, "Издатель: ТОО «Акме»");
        assert_eq!(
            ru.origin.note,
            "Плагин подписан издателем и собран OpenNCALayer из опубликованного исходного кода. Сам код OpenNCALayer не проверял."
        );
        assert_eq!(
            ru.origin.source,
            "Исходный код: kz.acme.market-1.2.0.src.tar.gz · Apache-2.0"
        );
        assert_eq!(ru.origin.url, ACME_SOURCE);
        assert_eq!(ru.warning, "", "a catalog plugin is not warned about");
        let en = texts(&request, Locale::En);
        assert_eq!(en.origin.publisher, "Publisher: Acme LLP");
        assert_eq!(
            en.origin.note,
            "The publisher signed this plugin, and OpenNCALayer built it from the published source code. OpenNCALayer did not review the code."
        );
        assert_eq!(
            en.origin.source,
            "Source code: kz.acme.market-1.2.0.src.tar.gz · Apache-2.0"
        );
        assert_eq!(
            texts(&request, Locale::Kk).origin.publisher,
            "Жариялаушы: «Акме» ЖШС"
        );
    }

    #[test]
    fn a_port_names_the_project_without_a_note_or_a_source() {
        let (request, _rx) = request(false, None);
        for l in ALL {
            let t = texts(&request, l);
            assert!(t.origin.publisher.ends_with(": OpenNCALayer"), "{l:?}");
            assert_eq!(t.origin.note, "", "{l:?}");
            assert_eq!(t.origin.source, "", "{l:?}");
            assert_eq!(t.origin.url, "", "{l:?}");
            assert_eq!(t.warning, "", "{l:?}");
        }
    }

    #[test]
    fn a_file_is_warned_about_and_names_no_publisher() {
        let (request, _rx) = request(true, None);
        for l in ALL {
            let t = texts(&request, l);
            assert_eq!(t.warning, Texts::of(l).local, "{l:?}");
            assert_eq!(
                t.origin,
                crate::plugins_view::OriginTexts::default(),
                "{l:?}"
            );
        }
    }

    /// Only a source archive of the project's Releases is linked: a URL from anywhere else
    /// (the publisher's own `fetch`, a lookalike) gets no link, and the publisher is still
    /// named.
    #[test]
    fn only_an_archive_in_the_projects_releases_is_linked() {
        for url in [
            "https://downloads.acme.kz/oncl/kz.acme.market-1.2.0.src.tar.gz",
            "https://github.com/arynyklas/OpenNCALayer.evil/releases/download/pub-acme-09/a-1.src.tar.gz",
            concat!(
                env!("CARGO_PKG_REPOSITORY"),
                "/releases/download/pub-acme-09/a-1.onclp"
            ),
            concat!(
                env!("CARGO_PKG_REPOSITORY"),
                "/releases/download/pub-acme-09/../x/a-1.src.tar.gz"
            ),
            concat!(
                env!("CARGO_PKG_REPOSITORY"),
                "/releases/download/pub-acme-09/a 1.src.tar.gz"
            ),
            concat!(
                env!("CARGO_PKG_REPOSITORY"),
                "/releases/download/pub-acme-09/a-1.src.tar.gz?x=1"
            ),
            concat!(
                env!("CARGO_PKG_REPOSITORY"),
                "/releases/download/pub-acme-09/a-1.src.tar.gz#x"
            ),
            concat!(
                env!("CARGO_PKG_REPOSITORY"),
                "/releases/download/pub-acme-09/a?.src.tar.gz"
            ),
            concat!(
                env!("CARGO_PKG_REPOSITORY"),
                "/releases/download/pub-acme-09/%2e%2e/a-1.src.tar.gz"
            ),
            concat!(
                env!("CARGO_PKG_REPOSITORY"),
                "/releases/download/pub-acme-09\\a-1.src.tar.gz"
            ),
            "https://user@github.com/arynyklas/OpenNCALayer/releases/download/pub-acme-09/a-1.src.tar.gz",
            "https://github.com/arynyklas/OpenNCALayer2/releases/download/pub-acme-09/a-1.src.tar.gz",
            "HTTPS://github.com/arynyklas/OpenNCALayer/releases/download/pub-acme-09/a-1.src.tar.gz",
            "http://github.com/arynyklas/OpenNCALayer/releases/download/pub-acme-09/a-1.src.tar.gz",
        ] {
            assert!(!crate::plugins_view::is_source_link(url), "{url}");
            let (mut request, _rx) = request(false, None);
            request.origin_kind = acme(url);
            let t = texts(&request, Locale::Ru);
            assert_eq!(
                (t.origin.source.as_str(), t.origin.url.as_str()),
                ("", ""),
                "{url}"
            );
            assert_eq!(t.origin.publisher, "Издатель: ТОО «Акме»");
        }
        assert!(crate::plugins_view::is_source_link(ACME_SOURCE));
    }

    #[test]
    fn replacing_a_publishers_plugin_names_its_publisher() {
        let (mut request, _rx) = request(false, None);
        request.replacing = Some(InstalledVersion {
            version: "1.1.0".to_owned(),
            origin: acme(ACME_SOURCE),
        });
        assert_eq!(
            texts(&request, Locale::Ru).replacing,
            "Заменит установленную версию 1.1.0 (от издателя ТОО «Акме»)"
        );
        assert_eq!(
            texts(&request, Locale::En).replacing,
            "Replaces the installed version 1.1.0 (from the publisher Acme LLP)"
        );
    }

    #[test]
    fn the_window_shows_the_publisher_and_its_source() {
        let dir = tempfile::tempdir().unwrap();
        desktop(dir.path(), Locale::Ru);
        let (mut request, rx) = request(false, None);
        request.origin_kind = acme(ACME_SOURCE);
        enqueue(request);
        let ui = the_window();
        assert_eq!(ui.get_publisher(), "Издатель: ТОО «Акме»");
        assert!(
            ui.get_publisher_note()
                .ends_with("Сам код OpenNCALayer не проверял.")
        );
        assert_eq!(
            ui.get_source(),
            "Исходный код: kz.acme.market-1.2.0.src.tar.gz · Apache-2.0"
        );
        assert_eq!(ui.get_warning(), "");
        ui.invoke_answer(false);
        assert!(!answered(&rx));
    }

    /// A publisher's name is shown without invisible characters (it cannot read as
    /// «OpenNCALayer»), whole up to the 128 characters `publishers.json` allows.
    #[test]
    fn a_publishers_name_is_shown_visible_and_whole() {
        let (mut request, _rx) = request(false, None);
        let named = |ru: &str| {
            PluginOrigin::Publisher(crate::plugins_view::PublisherOrigin {
                display: LocalizedText {
                    ru: ru.to_owned(),
                    kk: ru.to_owned(),
                    en: ru.to_owned(),
                },
                source: None,
            })
        };
        request.origin_kind = named("Open\u{200B}NCA\u{2060}Layer\u{200F}");
        // What it reads as is what is drawn; `publishers.json` refuses the name, the window
        // does not rely on it.
        assert_eq!(
            texts(&request, Locale::Ru).origin.publisher,
            "Издатель: OpenNCALayer"
        );
        let long = "А".repeat(128);
        request.origin_kind = named(&long);
        assert_eq!(
            texts(&request, Locale::Ru).origin.publisher,
            format!("Издатель: {long}")
        );
        request.origin_kind = named(&"А".repeat(129));
        assert!(texts(&request, Locale::Ru).origin.publisher.ends_with('…'));
    }

    /// A licence is shown whole: a cut could hide a trailing term.
    #[test]
    fn the_licence_is_shown_whole() {
        let licence = format!("Apache-2.0 AND {}", "LicenseRef-Acme-".repeat(14));
        let (mut request, _rx) = request(false, None);
        request.origin_kind = PluginOrigin::Publisher(crate::plugins_view::PublisherOrigin {
            display: LocalizedText::default(),
            source: Some(crate::plugins_view::SourceArchive {
                file: "kz.acme.market-1.2.0.src.tar.gz".to_owned(),
                url: ACME_SOURCE.to_owned(),
                license: format!("{licence}\u{200B}"),
            }),
        });
        assert!(
            texts(&request, Locale::En)
                .origin
                .source
                .ends_with(&format!("· {licence}"))
        );
    }

    /// A plugin of the catalog whose publisher is not known names nobody, never the project.
    #[test]
    fn an_unknown_publisher_names_nobody() {
        let (mut request, _rx) = request(false, None);
        request.origin_kind = PluginOrigin::Unknown;
        for l in ALL {
            let t = texts(&request, l);
            assert_eq!(
                t.origin,
                crate::plugins_view::OriginTexts::default(),
                "{l:?}"
            );
            assert_eq!(t.warning, "", "{l:?}");
        }
    }

    /// A publisher's plugin replacing the installed port `Порт`.
    fn replacement() -> (InstallPluginRequest, Receiver<bool>) {
        let (mut request, rx) = request(false, None);
        request.origin_kind = acme(ACME_SOURCE);
        request.kind = RequestKind::ReplacePort {
            port: LocalizedText {
                ru: "Порт".to_owned(),
                kk: "Порт кк".to_owned(),
                en: "Port".to_owned(),
            },
            version: "1.0.0".to_owned(),
        };
        (request, rx)
    }

    /// Р11: the port that goes is said above everything, the new plugin is named with its
    /// publisher, the note and the source link as in an install, its capabilities as the new
    /// plugin's; «Заменить» and «Не сейчас».
    #[test]
    fn a_port_replacement_names_the_port_the_publisher_and_what_the_plugin_may_do() {
        let (request, _rx) = replacement();
        let ru = texts(&request, Locale::Ru);
        assert_eq!(ru.title, "Замена порта");
        assert_eq!(ru.confirm, "Заменить");
        assert_eq!(ru.cancel, "Не сейчас");
        assert_eq!(
            ru.intro,
            "Плагин издателя заменит установленный порт \"Порт\" (версия 1.0.0). Порт и его настройки будут удалены."
        );
        assert_eq!(
            ru.plugin,
            "\"Пример плагина\" (название от самого плагина), версия 0.1.0"
        );
        assert_eq!(ru.origin.publisher, "Издатель: ТОО «Акме»");
        assert!(
            ru.origin
                .note
                .ends_with("Сам код OpenNCALayer не проверял.")
        );
        assert_eq!(
            ru.origin.source,
            "Исходный код: kz.acme.market-1.2.0.src.tar.gz · Apache-2.0"
        );
        assert_eq!(ru.may, "Новый плагин сможет:");
        assert_eq!(ru.capabilities.len(), 4);
        assert_eq!(ru.replacing, "");
        let en = texts(&request, Locale::En);
        assert_eq!(
            (en.title.as_str(), en.confirm.as_str(), en.cancel.as_str()),
            ("Port replacement", "Replace", "Not now")
        );
        assert_eq!(
            en.intro,
            "A publisher's plugin will replace the installed port \"Port\" (version 1.0.0). The port and its settings will be removed."
        );
        assert_eq!(en.origin.publisher, "Publisher: Acme LLP");
        let kk = texts(&request, Locale::Kk);
        assert!(kk.intro.contains("\"Порт кк\""), "{}", kk.intro);
        assert_eq!(kk.origin.publisher, "Жариялаушы: «Акме» ЖШС");
        // An install and an update keep the window's own «Отмена» and say nothing above.
        for l in ALL {
            for update in [false, true] {
                let t = texts(&with_operations(Vec::new(), update), l);
                assert_eq!((t.cancel.as_str(), t.intro.as_str()), ("", ""));
            }
        }
    }

    #[test]
    fn every_replacement_text_exists_and_differs_in_every_language() {
        let all = |f: fn(&Texts) -> &'static str| {
            let ru = f(Texts::of(Locale::Ru));
            let kk = f(Texts::of(Locale::Kk));
            let en = f(Texts::of(Locale::En));
            assert!(!ru.is_empty() && !kk.is_empty() && !en.is_empty());
            assert!(ru != kk && ru != en && kk != en, "{ru} | {kk} | {en}");
        };
        all(|t| t.title_replace);
        all(|t| t.confirm_replace);
        all(|t| t.cancel_replace);
        all(|t| t.replace_port);
        all(|t| t.may_replace);
    }

    /// The port's name is its manifest's: cleaned and quoted, it cannot pose as the host's
    /// words.
    #[test]
    fn the_ports_name_is_quoted_and_cleaned() {
        let (mut request, _rx) = replacement();
        request.kind = RequestKind::ReplacePort {
            port: LocalizedText {
                ru: "Порт\u{202E}\" одобрен".to_owned(),
                kk: String::new(),
                en: String::new(),
            },
            version: "1.0.0".to_owned(),
        };
        let ru = texts(&request, Locale::Ru);
        assert!(
            ru.intro.contains("порт \"Порт\\\" одобрен\" (версия"),
            "{}",
            ru.intro
        );
    }

    /// In the window: the buttons say «Заменить» and «Не сейчас»; «Не сейчас» declines.
    #[test]
    fn the_replacement_window_replaces_or_not() {
        let dir = tempfile::tempdir().unwrap();
        desktop(dir.path(), Locale::Ru);
        let (replace, rx) = replacement();
        enqueue(replace);
        let ui = the_window();
        assert_eq!(ui.get_window_title(), "Замена порта");
        assert_eq!(ui.get_confirm_text(), "Заменить");
        assert_eq!(ui.get_cancel_text(), "Не сейчас");
        assert!(ui.get_intro().starts_with("Плагин издателя заменит"));
        assert_eq!(ui.get_publisher(), "Издатель: ТОО «Акме»");
        ui.invoke_answer(false);
        assert!(!answered(&rx));
        let (replace, rx) = replacement();
        enqueue(replace);
        let ui = the_window();
        armed(&ui);
        ui.invoke_answer(true);
        assert!(answered(&rx));
        // An install after it has its own texts again.
        let (request, _rx) = request(false, None);
        enqueue(request);
        let ui = the_window();
        assert_eq!(ui.get_cancel_text(), "");
        assert_eq!(ui.get_intro(), "");
        ui.invoke_answer(false);
    }
}
