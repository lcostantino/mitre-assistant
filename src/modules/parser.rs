//use std::thread;
//use std::sync::{Arc};
use std::collections::HashSet;
use std::sync::mpsc;
//use std::borrow::Cow;

use serde_derive::{Deserialize, Serialize};
use serde_json;

#[path = "../utils/fshandler.rs"]
mod fshandler;
use fshandler::FileHandler;

#[path = "../utils/regexes.rs"]
mod regexes;
use regexes::RegexPatternManager;

#[path = "../structs/enterprise.rs"]
mod enterprise;
use enterprise::{
    EnterpriseMatrixStatistics,
    EnterpriseTechnique,
    EnterpriseTechniquesByTactic,
    EnterpriseTechniquesByPlatform,
    EnterpriseSubtechniquesByPlatform,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct EnterpriseMatrixBreakdown {
    pub tactics: HashSet<String>,
    pub platforms: HashSet<String>,
    pub datasources: Vec<String>,
    pub revoked_techniques: HashSet<(String, String)>,
    pub deprecated_techniques: HashSet<(String, String)>,
    pub breakdown_techniques: EnterpriseTechniquesByPlatform,
    pub breakdown_subtechniques: EnterpriseSubtechniquesByPlatform,
    pub uniques_techniques: Vec<String>,
    pub uniques_subtechniques: Vec<String>,
    pub rollup_techniques: Vec<EnterpriseTechniquesByTactic>,
    pub rollup_subtechniques: Vec<EnterpriseTechniquesByTactic>,
    pub stats: EnterpriseMatrixStatistics,
}
impl EnterpriseMatrixBreakdown {
    pub fn new() -> Self {
        EnterpriseMatrixBreakdown {
            tactics: HashSet::new(),
            platforms: HashSet::new(),
            datasources: Vec::new(),
            revoked_techniques: HashSet::new(),
            deprecated_techniques: HashSet::new(),
            breakdown_techniques: EnterpriseTechniquesByPlatform::new(),
            breakdown_subtechniques: EnterpriseSubtechniquesByPlatform::new(),
            uniques_techniques: vec![],
            uniques_subtechniques: vec![],
            rollup_techniques: vec![],
            rollup_subtechniques: vec![],
            stats: EnterpriseMatrixStatistics::new(),
        }
    }
}
#[derive(Debug, Deserialize, Serialize)]
pub struct EnterpriseMatrixParser {
    pub techniques: HashSet<String>,
    pub subtechniques: HashSet<String>,
    pub details: EnterpriseMatrixBreakdown,
}
impl EnterpriseMatrixParser {
    pub fn new() -> EnterpriseMatrixParser {
        EnterpriseMatrixParser {
            techniques: HashSet::new(),
            subtechniques: HashSet::new(),
            details: EnterpriseMatrixBreakdown::new(),
        }
    }
    pub fn baseline(&mut self, matrix_type: &str) -> Result<(), Box<dyn std::error::Error>> {
        if FileHandler::check_for_config_folder().unwrap() {
            match matrix_type {
                "enterprise" => self.baseline_enterprise()?,
                _ => (),
            }
        }
        Ok(())
    }
    /// # Baseline
    /// Private method used to read, parse the CTI matrix of choice
    /// and create the custom `json` database used by this program.
    /// ```rust
    /// // Assumes you already downloaded the enterprise matrix
    /// // Gets invoked by the `baseline()` method.
    ///
    /// self.baseline_enterprise()?
    /// ```
    fn baseline_enterprise(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let _bufr = FileHandler::load_resource("matrixes", "enterprise.json");
        let _json: serde_json::Value = serde_json::from_reader(_bufr).unwrap();
        let _scanner = RegexPatternManager::load_subtechnique();
        let mut _is_subtechnique = false;
        for _t in _json["objects"].as_array().unwrap().iter() {
            let _s = _t["type"].as_str().unwrap();
            let _x = serde_json::to_string(_t).unwrap();
            if _s == "attack-pattern" && _x.contains("x_mitre_deprecated") {
                self.extract_deprecated_techniques(_t);
            }
            else if _s == "attack-pattern" && _x.contains("revoked") {
                self.extract_revoked_techniques(_t);
            }
            else if _s == "attack-pattern" && !_x.contains("revoked") {
                if _scanner.pattern.is_match(&_x) {
                    _is_subtechnique = true;
                    self.extract_techniques_and_tactics(_t, _is_subtechnique);
                } else {
                    _is_subtechnique = false;
                    self.extract_techniques_and_tactics(_t, _is_subtechnique);
                }
                self.extract_tactics(_t);
                if _x.contains("x_mitre_data_sources") {
                    self.extract_datasources(_t);
                }
            }
            else if _s == "malware" {
                self.details.stats.count_malwares += 1;
            }
            else if _s == "intrusion-set" {
                self.details.stats.count_adversaries += 1;
            }
            else if _s == "tool" {
                self.details.stats.count_tools += 1;
            }
        }
        /*
            identity                // ? NFC
            intrusion-set           // Adversary
            malware                 // Malware
            marking-definition      // ? NFC
            relationship            // ? NFC
            Revoked Techniques      // ? NFC
            tool                    // ? NFC
            x-mitre-matrix
            x-mitre-tactic
        */
        Ok(())
    }
    /// # Extract Revoked Techniques
    /// Private method.
    /// Once the baseline starts, techniques are checked for the
    /// `revoked key` provided by Mitre in their CTI JSON.
    fn extract_revoked_techniques(
        &mut self,
        items: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if items["revoked"].as_bool().unwrap() {
            let _tid = items["external_references"]
                .as_array()
                .expect("Problem With External References");
            let _tid = _tid[0]["external_id"]
                .as_str()
                .expect("Problem With External ID");
            let _tname = items["name"].as_str().expect("Problem With Technique Name");
            self.details
                .revoked_techniques
                .insert((_tid.to_string(), _tname.to_string()));
            self.details.stats.count_revoked_techniques = self.details.revoked_techniques.len();
        } else {
            self.extract_techniques_and_tactics(items, false);
        }

        Ok(())
    }
    fn extract_deprecated_techniques(
        &mut self,
        items: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if items["x_mitre_deprecated"].as_bool().unwrap() {
            let _tid = items["external_references"]
                .as_array()
                .expect("Problem With External References");
            let _tid = _tid[0]["external_id"]
                .as_str()
                .expect("Problem With External ID");
            let _tname = items["name"].as_str().expect("Problem With Technique Name");
            self.details
                .deprecated_techniques
                .insert((_tid.to_string(), _tname.to_string()));
            self.details.stats.count_deprecated_techniques = self.details.deprecated_techniques.len();
        } else {
            self.extract_techniques_and_tactics(items, false);
        }

        Ok(())
    }    
    /// # Extract Datasources
    /// Private method.
    /// Once the baseline starts, this function is dedicated to inspecting
    /// the techniques for the presence of the key called `x_mitre_datasources`.
    ///
    /// After it finds it, it creates a Vector of unique datasource strings.
    fn extract_datasources(
        &mut self,
        items: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for _item in items["x_mitre_data_sources"].as_array().unwrap().iter() {
            self.details
                .datasources
                .push(_item.as_str().unwrap().to_lowercase().replace(" ", "-"));
        }
        self.details.datasources.sort();
        self.details.datasources.dedup();
        self.details.stats.count_datasources = self.details.datasources.len();
        Ok(())
    }
    fn extract_techniques_and_tactics(
        &mut self,
        items: &serde_json::Value,
        is_subtechnique: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _tid = items["external_references"]
            .as_array()
            .expect("Problem With External References");
        let _tid = _tid[0]["external_id"]
            .as_str()
            .expect("Problem With External ID");
        let _tname = items["name"].as_str().expect("Problem With Technique Name");
        let mut _platforms = String::from("");
        for _os in items["x_mitre_platforms"].as_array().unwrap().iter() {
            let _x = _os.as_str().unwrap().to_lowercase().replace(" ", "-");
            &_platforms.push_str(_x.as_str());
            &_platforms.push_str("|");
            self.details.platforms.insert(_x);
        }
        _platforms.pop();

        for _item in items["kill_chain_phases"].as_array().unwrap().iter() {
            let _tactic = &_item["phase_name"]
                .as_str()
                .expect("Problem With Killchain Phase");
            let mut _et = EnterpriseTechnique::new();
            _et.platform = _platforms.clone();
            _et.tid = _tid.to_string();
            _et.tactic = _tactic.to_string();
            _et.technique = _tname.to_string();
            let _d = items
                .as_object()
                .expect("Unable to Deserialize into String");
            // Extract Data Sources
            // Normalize the Data Source
            if _d.contains_key("x_mitre_data_sources") {
                let mut _data_sources = String::from("");
                for _ds in items["x_mitre_data_sources"]
                    .as_array()
                    .expect("Deserializing Data Sources Issue")
                {
                    _data_sources.push_str(
                        _ds.as_str()
                            .unwrap()
                            .to_lowercase()
                            .replace(" ", "-")
                            .replace("/", "-")
                            .as_str(),
                    );
                    _data_sources.push_str("|");
                }
                _data_sources.pop();
                _et.datasources = _data_sources;
                if is_subtechnique {
                    self.subtechniques.insert(_tid.to_string());
                    self.details.breakdown_subtechniques.platforms.push(_et);
                    self.details.uniques_subtechniques.push(_tid.to_string());
                } else {
                    self.techniques.insert(_tid.to_string());
                    self.details.breakdown_techniques.platforms.push(_et);
                    self.details.uniques_techniques.push(_tid.to_string());
                }
            } else {
                // When The Enterpise JSON Does not have a Datasources Key, add the technique
                // Reference:  https://github.com/mitre/cti/issues/101#issuecomment-671639284
                if is_subtechnique {
                    _et.datasources = "none".to_string();
                    self.subtechniques.insert(_tid.to_string());
                    self.details.breakdown_subtechniques.platforms.push(_et);
                    self.details.uniques_subtechniques.push(_tid.to_string());
                } else {
                    _et.datasources = "none".to_string();
                    self.techniques.insert(_tid.to_string());
                    self.details.breakdown_techniques.platforms.push(_et);
                    self.details.uniques_techniques.push(_tid.to_string());
                }
            }
        }
        // now Correlate Subtechniques
        for _record in &mut self.details.breakdown_techniques.platforms {
            for _subtechnique in &self.details.uniques_subtechniques {
                if _subtechnique.contains(&_record.tid) {
                    _record.subtechniques.push(_subtechnique.to_string());
                }
            }
            if _record.subtechniques.len() > 0usize {
                _record.has_subtechniques = true;
                _record.subtechniques.sort();
                _record.subtechniques.dedup();
            }
            _record.update();
        }
        self.details.stats.count_platforms = self.details.platforms.len();
        self.details.stats.count_active_uniq_techniques = self.techniques.len();
        self.details.stats.count_active_uniq_subtechniques = self.subtechniques.len();
        self.details.uniques_techniques.sort();
        self.details.uniques_techniques.dedup();
        self.details.uniques_subtechniques.sort();
        self.details.uniques_subtechniques.dedup();
        self.details.breakdown_subtechniques.update_count();
        self.details.breakdown_techniques.update_count();
        self.extract_stats_techniques_by_totals();
        self.extract_stats_techniques_by_platforms(false);
        self.extract_stats_techniques_by_platforms(true);
        self.extract_stats_techniques_by_killchain(false);
        self.extract_stats_techniques_by_killchain(true);
        Ok(())
    }
    fn extract_tactics(
        &mut self,
        items: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for _item in items["kill_chain_phases"].as_array().unwrap().iter() {
            self.details
                .tactics
                .insert(_item["phase_name"].as_str().unwrap().to_string());
        }
        self.details.stats.count_tactics = self.details.tactics.len();
        Ok(())
    }
    pub fn to_string(&self) -> String {
        serde_json::to_string_pretty(&self.details).unwrap()
    }
    pub fn save_baseline(&self) {
        FileHandler::write_baseline("baseline-enterprise.json", &self.to_string());
    }
    /// # **Stats Functions**
    /// The functions in this code section baseline specific queries to offer
    /// pre-canned responses commonly needed when working with the enterprise
    /// matrix.
    ///
    /// The data processed is stored as subkeys to the `stats` key of the
    /// `EnterpriseMatrixBreakdown` struct.
    ///
    ///
    fn get_percentage(&self, total: usize, actual: usize) -> String
    {
        let _high = total as f64;
        let _low = actual as f64;
        let _percent = (_low / _high) * 100f64;
        format!("{}{}", _percent.floor().to_string(), "%")
    }
    fn extract_stats_techniques_by_totals(&mut self )
    {
        let mut _total_techniques: HashSet<String> = HashSet::new();
        let mut _total_subtechniques: HashSet<String> = HashSet::new();
        let mut _stub = String::from("");
        for _technique in self.details.breakdown_techniques.platforms.iter() {
            _stub = format!("{}:{}",_technique.tid, _technique.tactic);
            _total_techniques.insert(_stub);
        }
        for _technique in self.details.breakdown_subtechniques.platforms.iter() {
            _stub = format!("{}:{}",_technique.tid, _technique.tactic);
            _total_subtechniques.insert(_stub);
        }
        self.details.stats.count_active_total_techniques = _total_techniques.len();
        self.details.stats.count_active_total_subtechniques = _total_subtechniques.len();          
    }
    fn extract_stats_techniques_by_platforms(&mut self, _wants_subtechniques: bool)
    {
        // Tactics or KillChains
        let mut _windows:    HashSet<String> = HashSet::new();
        let mut _macos:      HashSet<String> = HashSet::new();
        let mut _linux:      HashSet<String> = HashSet::new();
        let mut _azure_ad:   HashSet<String> = HashSet::new();
        let mut _azure:      HashSet<String> = HashSet::new();
        let mut _aws:        HashSet<String> = HashSet::new();
        let mut _gcp:        HashSet<String> = HashSet::new();
        let mut _office365:  HashSet<String> = HashSet::new();
        let mut _saas:       HashSet<String> = HashSet::new();
        // Setup the Iterables that has techniques by Type
        let mut _iterable: &Vec<EnterpriseTechnique>;
        if _wants_subtechniques {
            _iterable = &self.details.breakdown_subtechniques.platforms;
        } else {
            _iterable = &self.details.breakdown_techniques.platforms;
        }
        // Setup The Stub
        let mut _stub: String = String::from("");
        // Iterate through platforms first
        for _platform in self.details.platforms.iter() {
            let _os = _platform.as_str();
            // Now for each platform find the techniques
            for _technique in _iterable.iter() {
                if _technique.platform.contains(_os) {
                    _stub = format!("{}:{}", _technique.tid, _technique.tactic);
                    if _os == "aws" {
                        _aws.insert(_stub);
                    } else if _os == "azure-ad" {
                        _azure_ad.insert(_stub);
                    } else if _os == "azure" {
                        _azure.insert(_stub);
                    } else if _os == "gcp" {
                        _gcp.insert(_stub);
                    } else if _os == "linux" {
                        _linux.insert(_stub);
                    } else if _os == "macos" {
                        _macos.insert(_stub);
                    } else if _os == "office-365" {
                        _office365.insert(_stub);
                    } else if _os == "saas" {
                        _saas.insert(_stub);
                    } else if _os == "windows" {
                        _windows.insert(_stub);
                    }
                }
            }
        }
        if _wants_subtechniques {
            let _total = self.details.stats.count_active_total_subtechniques;
            self.details.stats.count_subtechniques_aws = _aws.len();
            self.details.stats.count_subtechniques_azure = _azure.len();
            self.details.stats.count_subtechniques_azure_ad = _azure_ad.len();
            self.details.stats.count_subtechniques_gcp = _gcp.len();
            self.details.stats.count_subtechniques_linux = _linux.len();
            self.details.stats.count_subtechniques_macos = _macos.len();
            self.details.stats.count_subtechniques_office365 = _office365.len();
            self.details.stats.count_subtechniques_saas = _saas.len();
            self.details.stats.count_subtechniques_windows = _windows.len();
            // Percentages
            self.details.stats.percent_subtechniques_aws = self.get_percentage(_total, _aws.len());
            self.details.stats.percent_subtechniques_azure = self.get_percentage(_total, _azure.len());
            self.details.stats.percent_subtechniques_azure_ad = self.get_percentage(_total, _azure_ad.len());
            self.details.stats.percent_subtechniques_gcp = self.get_percentage(_total,_gcp.len());
            self.details.stats.percent_subtechniques_linux = self.get_percentage(_total,_linux.len());
            self.details.stats.percent_subtechniques_macos = self.get_percentage(_total, _macos.len());
            self.details.stats.percent_subtechniques_office365 = self.get_percentage(_total, _office365.len());
            self.details.stats.percent_subtechniques_saas = self.get_percentage(_total, _saas.len());
            self.details.stats.percent_subtechniques_windows = self.get_percentage(_total, _windows.len());
        } else {
            let _total = self.details.stats.count_active_total_techniques;
            self.details.stats.count_techniques_aws = _aws.len();
            self.details.stats.count_techniques_azure = _azure.len();
            self.details.stats.count_techniques_azure_ad = _azure_ad.len();
            self.details.stats.count_techniques_gcp = _gcp.len();
            self.details.stats.count_techniques_linux = _linux.len();
            self.details.stats.count_techniques_macos = _macos.len();
            self.details.stats.count_techniques_office365 = _office365.len();
            self.details.stats.count_techniques_saas = _saas.len();
            self.details.stats.count_techniques_windows = _windows.len();
            // Percentages
            self.details.stats.percent_techniques_aws = self.get_percentage(_total, _aws.len());
            self.details.stats.percent_techniques_azure = self.get_percentage(_total, _azure.len());
            self.details.stats.percent_techniques_azure_ad = self.get_percentage(_total, _azure_ad.len());
            self.details.stats.percent_techniques_gcp = self.get_percentage(_total,_gcp.len());
            self.details.stats.percent_techniques_linux = self.get_percentage(_total,_linux.len());
            self.details.stats.percent_techniques_macos = self.get_percentage(_total, _macos.len());
            self.details.stats.percent_techniques_office365 = self.get_percentage(_total, _office365.len());
            self.details.stats.percent_techniques_saas = self.get_percentage(_total, _saas.len());
            self.details.stats.percent_techniques_windows = self.get_percentage(_total, _windows.len());                        
        }
    }
    ///
    /// 
    /// 
    /// 
    fn extract_stats_techniques_by_killchain(&mut self, _wants_subtechniques: bool)
    {
        // Setup Tactics Hashsets for UNIQ
        // items. then take length of each.
        let mut _initial_access:        HashSet<String>  = HashSet::new();
        let mut _execution:             HashSet<String>  = HashSet::new();
        let mut _persistence:           HashSet<String>  = HashSet::new();
        let mut _priv_escalation:       HashSet<String>  = HashSet::new();
        let mut _defense_evasion:       HashSet<String>  = HashSet::new();
        let mut _credential_access:     HashSet<String>  = HashSet::new();
        let mut _collection:            HashSet<String>  = HashSet::new();
        let mut _discovery:             HashSet<String>  = HashSet::new();
        let mut _lateral_movement:      HashSet<String>  = HashSet::new();
        let mut _command_and_control:   HashSet<String>  = HashSet::new();
        let mut _exfiltration:          HashSet<String>  = HashSet::new();
        let mut _impact:                HashSet<String>  = HashSet::new();
        let mut _iterable: &Vec<EnterpriseTechnique>;
        let mut _rollup: Vec<EnterpriseTechniquesByTactic> = vec![];
        // Validate if user wants Subtechniques
        // Then, load the list of subtechniques
        if _wants_subtechniques {
            _iterable = &self.details.breakdown_subtechniques.platforms;
        } else {
            _iterable = &self.details.breakdown_techniques.platforms;
        }
        // Setup the stub
        let mut _stub: String = String::from("");
        for _tactic in self.details.tactics.iter() {
            let _kc = _tactic.as_str();
            let mut _kill_chain = EnterpriseTechniquesByTactic::new(_kc);
            for _technique in _iterable.iter() {
                if _technique.tactic.contains(_kc) {
                    _stub = format!("{}:{}", _technique.tid, _technique.tactic);
                    _kill_chain.tactic.items.push(_stub.clone());
                    // Validate which Tactic
                    // Insert Technique into Tactic Hashset
                    if _kc == "initial-access" {
                        _initial_access.insert(_stub);
                    }
                    else if _kc == "execution" {
                        _execution.insert(_stub);
                    }
                    else if _kc == "persistence" {
                        _persistence.insert(_stub);
                    }
                    else if _kc == "privilege-escalation" {
                        _priv_escalation.insert(_stub);
                    }
                    else if _kc == "defense-evasion" {
                        _defense_evasion.insert(_stub);
                    }
                    else if _kc == "credential-access" {
                        _credential_access.insert(_stub);
                    }
                    else if _kc == "collection" {
                        _collection.insert(_stub);
                    }
                    else if _kc == "discovery" {
                        _discovery.insert(_stub);
                    }
                    else if _kc == "lateral-movement" {
                        _lateral_movement.insert(_stub);
                    }
                    else if _kc == "command-and-control" {
                        _command_and_control.insert(_stub);
                    }
                    else if _kc == "exfiltration" {
                        _exfiltration.insert(_stub);
                    }
                    else if _kc == "impact" {
                        _impact.insert(_stub);
                    }
                }
            }
            _kill_chain.tactic.items.sort();
            _kill_chain.tactic.items.dedup();
            _kill_chain.tactic.items.sort();
            _kill_chain.count = _kill_chain.tactic.items.len();
            _rollup.push(_kill_chain);
        }
        if _wants_subtechniques {
            // Subtechniques
            let _total = self.details.stats.count_active_total_subtechniques;
            self.details.stats.count_subtechniques_initial_access = _initial_access.len();
            self.details.stats.count_subtechniques_execution = _execution.len();
            self.details.stats.count_subtechniques_persistence = _persistence.len();
            self.details.stats.count_subtechniques_privilege_escalation = _priv_escalation.len();
            self.details.stats.count_subtechniques_defense_evasion = _defense_evasion.len();
            self.details.stats.count_subtechniques_credential_access = _credential_access.len();
            self.details.stats.count_subtechniques_collection = _collection.len();
            self.details.stats.count_subtechniques_discovery = _discovery.len();
            self.details.stats.count_subtechniques_lateral_movement = _lateral_movement.len();
            self.details.stats.count_subtechniques_command_and_control = _command_and_control.len();
            self.details.stats.count_subtechniques_exfiltration = _exfiltration.len();
            self.details.stats.count_subtechniques_impact = _impact.len();
            // Percentages
            self.details.stats.percent_subtechniques_initial_access = self.get_percentage(_total, _initial_access.len());
            self.details.stats.percent_subtechniques_execution = self.get_percentage(_total, _execution.len());
            self.details.stats.percent_subtechniques_persistence = self.get_percentage(_total, _persistence.len());
            self.details.stats.percent_subtechniques_privilege_escalation = self.get_percentage(_total, _priv_escalation.len());
            self.details.stats.percent_subtechniques_defense_evasion = self.get_percentage(_total, _defense_evasion.len());
            self.details.stats.percent_subtechniques_credential_access = self.get_percentage(_total, _credential_access.len());
            self.details.stats.percent_subtechniques_collection = self.get_percentage(_total, _collection.len());
            self.details.stats.percent_subtechniques_discovery = self.get_percentage(_total, _discovery.len());
            self.details.stats.percent_subtechniques_lateral_movement = self.get_percentage(_total, _lateral_movement.len());
            self.details.stats.percent_subtechniques_command_and_control = self.get_percentage(_total, _command_and_control.len());
            self.details.stats.percent_subtechniques_exfiltration = self.get_percentage(_total, _exfiltration.len());
            self.details.stats.percent_subtechniques_impact = self.get_percentage(_total, _impact.len());            
            // Rollup
            self.details.rollup_subtechniques = _rollup; 
        } else {
            // Techniques
            let _total = self.details.stats.count_active_total_techniques;
            self.details.stats.count_techniques_initial_access = _initial_access.len();
            self.details.stats.count_techniques_execution = _execution.len();
            self.details.stats.count_techniques_persistence = _persistence.len();
            self.details.stats.count_techniques_privilege_escalation = _priv_escalation.len();
            self.details.stats.count_techniques_defense_evasion = _defense_evasion.len();
            self.details.stats.count_techniques_credential_access = _credential_access.len();
            self.details.stats.count_techniques_collection = _collection.len();
            self.details.stats.count_techniques_discovery = _discovery.len();
            self.details.stats.count_techniques_lateral_movement = _lateral_movement.len();
            self.details.stats.count_techniques_command_and_control = _command_and_control.len();
            self.details.stats.count_techniques_exfiltration = _exfiltration.len();
            self.details.stats.count_techniques_impact = _impact.len();
            // Percentages
            self.details.stats.percent_techniques_initial_access = self.get_percentage(_total, _initial_access.len());
            self.details.stats.percent_techniques_execution = self.get_percentage(_total, _execution.len());
            self.details.stats.percent_techniques_persistence = self.get_percentage(_total, _persistence.len());
            self.details.stats.percent_techniques_privilege_escalation = self.get_percentage(_total, _priv_escalation.len());
            self.details.stats.percent_techniques_defense_evasion = self.get_percentage(_total, _defense_evasion.len());
            self.details.stats.percent_techniques_credential_access = self.get_percentage(_total, _credential_access.len());
            self.details.stats.percent_techniques_collection = self.get_percentage(_total, _collection.len());
            self.details.stats.percent_techniques_discovery = self.get_percentage(_total, _discovery.len());
            self.details.stats.percent_techniques_lateral_movement = self.get_percentage(_total, _lateral_movement.len());
            self.details.stats.percent_techniques_command_and_control = self.get_percentage(_total, _command_and_control.len());
            self.details.stats.percent_techniques_exfiltration = self.get_percentage(_total, _exfiltration.len());
            self.details.stats.percent_techniques_impact = self.get_percentage(_total, _impact.len());
            // rollup            
            self.details.rollup_techniques = _rollup; 
        }

    }
}
