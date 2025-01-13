use crate::github::{create_github_issue, set_config, login_start, update_config_file, get_token};
use chrono::Utc;
use glib::subclass::Signal;
use glib::{Binding, Properties};
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::{glib, Box, Button, CheckButton, CompositeTemplate, Entry, Label, TextView};
use std::cell::RefCell;
use std::fs;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use github_auth::{Authenticator, Scope};


//use crate::vm_gobject::VMGObject; will be used in the future
use crate::settings_gobject::SettingsGObject;

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct Answers {
        pub issue: String,
        pub related: String,
        pub app: String,
    }

    #[derive(Default, CompositeTemplate, Properties)]
    #[properties(wrapper_type = super::BugReportSettingsPage)]
    #[template(resource = "/org/gnome/controlpanelgui/ui/bug_report_settings_page.ui")]
    pub struct BugReportSettingsPage {
        #[template_child]
        pub qbox_3: TemplateChild<Box>,
        #[template_child]
        pub entry_1: TemplateChild<Entry>,
        #[template_child]
        pub entry_2: TemplateChild<Entry>,
        #[template_child]
        pub entry_3: TemplateChild<Entry>,
        #[template_child]
        pub title: TemplateChild<Entry>,
        #[template_child]
        pub description: TemplateChild<TextView>,
        #[template_child]
        pub reporter: TemplateChild<Entry>,
        #[template_child]
        pub ghaf_version: TemplateChild<Entry>,
        #[template_child]
        pub email: TemplateChild<Entry>,
        #[template_child]
        pub other_1: TemplateChild<CheckButton>,
        #[template_child]
        pub other_2: TemplateChild<CheckButton>,
        #[template_child]
        pub other_3: TemplateChild<CheckButton>,
        #[template_child]
        pub required_issue: TemplateChild<Label>,
        #[template_child]
        pub required_related: TemplateChild<Label>,
        #[template_child]
        pub required_app: TemplateChild<Label>,
        #[template_child]
        pub required_title: TemplateChild<Label>,
        #[template_child]
        pub required_description: TemplateChild<Label>,
        #[template_child]
        pub required_reporter: TemplateChild<Label>,
        #[template_child]
        pub required_version: TemplateChild<Label>,
        #[template_child]
        pub required_email: TemplateChild<Label>,
        #[template_child]
        pub summary: TemplateChild<Label>,

        // Vector holding the bindings to properties of `Object`
        pub bindings: RefCell<Vec<Binding>>,
        #[property(name = "issue", get, set, type = String, member = issue)]
        #[property(name = "related", get, set, type = String, member = related)]
        #[property(name = "app", get, set, type = String, member = app)]
        pub answers: RefCell<Answers>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for BugReportSettingsPage {
        const NAME: &'static str = "BugReportSettingsPage";
        type Type = super::BugReportSettingsPage;
        type ParentType = gtk::Box;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.bind_template_callbacks();
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    #[gtk::template_callbacks]
    impl BugReportSettingsPage {
        #[template_callback]
        fn entry_1_focused(&self) {
            if !self.other_1.is_active() {
                self.other_1.set_active(true);
            };
        }
        #[template_callback]
        fn entry_2_focused(&self) {
            if !self.other_2.is_active() {
                self.other_2.set_active(true);
            };
        }
        #[template_callback]
        fn entry_3_focused(&self) {
            if !self.other_3.is_active() {
                self.other_3.set_active(true);
            };
        }
        #[template_callback]
        fn on_a1_toggled(&self, button: &CheckButton) {
            if button.is_active() {
                let label = button.label();

                match label.as_deref() {
                    None => self
                        .obj()
                        .set_property("issue", self.entry_1.text().to_string()),
                    Some(text) => self.obj().set_property("issue", text.to_string()),
                };
            }
        }
        #[template_callback]
        fn on_a2_toggled(&self, button: &CheckButton) {
            if button.is_active() {
                let label = button.label();
                match label.as_deref() {
                    Some("App") => {
                        self.qbox_3.set_visible(true);
                        self.obj().set_property("related", String::from("App"));
                    } // Show the application list
                    Some(text) => {
                        self.obj().set_property("related", text.to_string());
                        self.qbox_3.set_visible(false);
                    } // Hide the application list
                    _ => {
                        self.qbox_3.set_visible(false);
                    }
                };
            }
        }
        #[template_callback]
        fn on_a3_toggled(&self, button: &CheckButton) {
            if button.is_active() {
                let label = button.label();

                match label.as_deref() {
                    None => println!("No App"),
                    Some(text) => self.obj().set_property("app", text.to_string()),
                };
            }
        }
        #[template_callback]
        fn on_submit(&self, button: &Button) {
            let mut enable = true;
            let mac_address_path = "/tmp/MACAddress";
            let title = self.title.text().to_string();
            let description = self.description.buffer().to_string();
            let version = self.reporter.text().to_string();
            let reporter = self.ghaf_version.text().to_string();
            let email = self.email.text().to_string();

            let time = Utc::now().to_string();

            let issue = self.obj().property::<String>("issue");
            let related = self.obj().property::<String>("related");
            let app = self.obj().property::<String>("app");

            let mac = match self.get_mac_address(mac_address_path) {
                Some(mac) => mac,
                None => {
                    eprintln!("Can't get MAC Address");
                    String::from("")
                }
            };
            let sw = match self.get_sw_version() {
                Some(sw) => sw,
                None => {
                    eprintln!("Can't get SW Version");
                    String::from("")
                }
            };
            let system = self.get_system_version();

            if issue.is_empty() {
                enable = false;
                self.required_issue.set_visible(true);
                eprintln!("Issue is not selected");
            } else {
                self.required_issue.set_visible(false);
            }

            if related.is_empty() {
                enable = false;
                self.required_related.set_visible(true);
                eprintln!("Related is not selected");
            } else {
                self.required_related.set_visible(false);
            }

            if app.is_empty() {
                if related == "App" {
                    enable = false;
                    self.required_app.set_visible(true);
                }
                eprintln!("App is not selected");
            } else {
                self.required_app.set_visible(false);
            }

            if title.is_empty() {
                enable = false;
                self.required_title.set_visible(true);
                eprintln!("Title is empty");
            } else {
                self.required_title.set_visible(false);
            }

            if description.is_empty() {
                enable = false;
                self.required_description.set_visible(true);
                eprintln!("Description is empty");
            } else {
                self.required_description.set_visible(false);
            }

            if version.is_empty() {
                enable = false;
                self.required_reporter.set_visible(true);
                eprintln!("Version is empty");
            } else {
                self.required_reporter.set_visible(false);
            }

            if reporter.is_empty() {
                enable = false;
                self.required_version.set_visible(true);
                eprintln!("Reporter is empty");
            } else {
                self.required_version.set_visible(false);
            }

            if email.is_empty() {
                enable = false;
                self.required_email.set_visible(true);
                eprintln!("Email is empty");
            } else if !email.contains('@') {
                enable = false;
                self.required_email.set_visible(true);
                eprintln!("Please enter a valid email");
            } else {
                self.required_email.set_visible(false);
            }

            if true { //enable {
                let auth = Authenticator::builder("github_auth main example".into())
                .scope(Scope::PublicRepo)
                .build();

                let token = auth.auth().unwrap();
                println!("{:?}", token);

                let location = auth.location();
                println!("Token stored at: {:?}", location);

                match set_config() {
                    Ok(_) => println!("Config is set"),
                    Err(e) => eprintln!("{e}"),
                };

                match get_token() {
                    Some(t) => {

                        println!("Token: {}", t);
                        update_config_file(&t);
                        set_config().unwrap();},
                    _ => {
                        let mut code = String::new();
                        let login_rt = tokio::runtime::Runtime::new().unwrap();
                        match login_rt.block_on(login_start()){
                            Ok(c) => {code = c;},
                            Err(e) => {
                                self.summary.set_label("Github CLI failed to get auth code");
                                self.summary.add_css_class("required-text");
                                self.summary.remove_css_class("success-text");
                                self.summary.set_visible(true);
                            },
                        };
                        self.summary.set_label(format!("Github Code: {}",code));
                        self.summary.remove_css_class("required-text");
                        self.summary.add_css_class("success-text");
                        self.summary.set_visible(true);
                        // TODO: Copy to clipboard
                        std::process::Command::new("xdg-open").env("PATH", "/usr/bin").arg("https://github.com/login/device").output();
                        return;
                    }
                };

                // Prepare email content with optional attachment
                let mut email_body = format!(
                    "Time: {}\n\nBug Report\n\nFrom: {}\nEmail: {}\nMAC Address: {}\n SW Version: {}\nSystem Version: {}\n\nIssue: {}\nRelates to: {}\nApp: {}\n\nDescription:\n{}\nGhaf version: {}",
                    time, reporter, email, mac, sw, system, issue, related, app, description, version
                );
                let mut email_title = format!("{}: {}", issue, title);
                

                let rt = tokio::runtime::Runtime::new().unwrap();
                match rt.block_on(create_github_issue(&email_title, &email_body)) {
                    Ok(_) => {
                        self.summary.set_label("Report sent successfully");
                        self.summary.remove_css_class("required-text");
                        self.summary.add_css_class("success-text");
                        self.summary.set_visible(true);
                    }
                    Err(e) => {
                        if e.downcast_ref::<octocrab::Error>().is_none() {
                            self.summary.set_label(format!("Error when sending report: {}",e).as_str());
                        } else {
                            self.summary.set_label("Error when sending report");
                        }
                        
                        self.summary.remove_css_class("success-text");
                        self.summary.add_css_class("required-text");
                        self.summary.set_visible(true);
                        return;
                    }
                }
            }
        }

        #[inline]
        fn get_mac_address(&self, path: &str) -> Option<String> {
            match fs::read_to_string(path) {
                Ok(mac_address) => {
                    return Some(mac_address);
                }
                Err(_) => {
                    eprintln!("Failed to read: {}", path);
                }
            }
            None
        }

        #[inline]
        fn get_sw_version(&self) -> Option<String> {
            {
                let output = Command::new("ghaf-version")
                    .env("PATH", "/run/current-system/sw/bin")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output();

                match output {
                    Ok(output) => {
                        if output.status.success() {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            println!("ghaf-version: {}", stdout);
                            return Some(stdout.to_string());
                        } else {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            eprintln!("ghaf-version error: {}", stderr);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to execute ghaf-version: {}", e);
                    }
                }
                None
            }
        }

        #[inline]
        fn get_system_version(&self) -> String {
            let manufacturer: String;
            let version: String;
            let product: String;
            let sku: String;

            let output = Command::new("dmidecode")
                .arg("-s")
                .arg("system-manufacturer")
                .env("PATH", "/run/current-system/sw/bin")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output();

            match output {
                Ok(output) => {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        println!("system-manufacturer: {}", stdout);
                        manufacturer = stdout.to_string();
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        eprintln!("system-manufacturer: {}", stderr);
                        manufacturer = String::from("no-manufacturer");
                    }
                }
                Err(e) => {
                    eprintln!("Failed to execute dmidecode: {}", e);
                    manufacturer = String::from("manufacturer-failed");
                }
            }

            let output = Command::new("dmidecode")
                .arg("-s")
                .arg("system-version")
                .env("PATH", "/run/current-system/sw/bin")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output();

            match output {
                Ok(output) => {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        println!("system-version: {}", stdout);
                        version = stdout.to_string();
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        eprintln!("system-version: {}", stderr);
                        version = String::from("no-version");
                    }
                }
                Err(e) => {
                    eprintln!("Failed to execute dmidecode: {}", e);
                    version = String::from("version-failed");
                }
            }

            let output = Command::new("dmidecode")
                .arg("-s")
                .arg("system-product-name")
                .env("PATH", "/run/current-system/sw/bin")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output();

            match output {
                Ok(output) => {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        println!("product: {}", stdout);
                        product = stdout.to_string();
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        eprintln!("product: {}", stderr);
                        product = String::from("no-product");
                    }
                }
                Err(e) => {
                    eprintln!("Failed to execute dmidecode: {}", e);
                    product = String::from("product-failed");
                }
            }

            let output = Command::new("dmidecode")
                .arg("-s")
                .arg("system-sku-number")
                .env("PATH", "/run/current-system/sw/bin")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output();

            match output {
                Ok(output) => {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        println!("sku-number: {}", stdout);
                        sku = stdout.to_string();
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        eprintln!("sku-number: {}", stderr);
                        sku = String::from("no-sku-number");
                    }
                }
                Err(e) => {
                    eprintln!("Failed to execute dmidecode: {}", e);
                    sku = String::from("sku-number-failed");
                }
            }

            return format!("{} {} {} {}", manufacturer, version, product, sku);
        }
    } //end #[gtk::template_callbacks]

    #[glib::derived_properties]
    impl ObjectImpl for BugReportSettingsPage {
        fn constructed(&self) {
            // Call "constructed" on parent
            self.parent_constructed();

            // Setup
            let obj = self.obj();
            obj.init();
        }
        fn signals() -> &'static [Signal] {
            static SIGNALS: OnceLock<Vec<Signal>> = OnceLock::new();
            SIGNALS.get_or_init(|| {
                vec![
                    Signal::builder("toggled").build(),
                    Signal::builder("clicked").build(),
                ]
            })
        }
    }
    impl WidgetImpl for BugReportSettingsPage {}
    impl BoxImpl for BugReportSettingsPage {}
}

glib::wrapper! {
pub struct BugReportSettingsPage(ObjectSubclass<imp::BugReportSettingsPage>)
    @extends gtk::Widget, gtk::Box;
}

impl Default for BugReportSettingsPage {
    fn default() -> Self {
        Self::new()
    }
}

impl BugReportSettingsPage {
    pub fn new() -> Self {
        glib::Object::builder()
            .property("issue", "")
            .property("related", "")
            .property("app", "")
            .build()
    }

    pub fn init(&self) {
        let this = self.clone();
    }

    pub fn bind(&self, _settings_object: &SettingsGObject) {
        //unbind previous ones
        self.unbind();
        //make new
    }

    pub fn unbind(&self) {
        // Unbind all stored bindings
        for binding in self.imp().bindings.borrow_mut().drain(..) {
            binding.unbind();
        }
    }
}
