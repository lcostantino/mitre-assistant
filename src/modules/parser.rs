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
    EnterpriseAdversary,
    EnterpriseAdversaryProfile,
    EnterpriseProfileEntry,
    EnterpriseMalware,
    EnterpriseMalwareProfile,
    EnterpriseMatrixStatistics,
    EnterpriseRelationship,
    EnterpriseRelationships,
    EnterpriseTool,
    EnterpriseToolProfile,
    EnterpriseTechnique,
    EnterpriseTechniquesByTactic,
    EnterpriseTechniquesByPlatform,
    EnterpriseSubtechniquesByPlatform,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct EnterpriseMatrixBreakdown {
    pub adversaries:                Vec<String>,
    pub malware:                    Vec<String>,
    pub tools:                      Vec<String>,
    pub tactics:                    HashSet<String>,
    pub platforms:                  HashSet<String>,
    pub datasources:                Vec<String>,
    pub revoked_techniques:         HashSet<(String, String)>,
    pub deprecated_techniques:      HashSet<(String, String)>,
    pub breakdown_adversaries:      Vec<EnterpriseAdversary>,
    pub breakdown_malware:          Vec<EnterpriseMalware>,
    pub breakdown_tools:            Vec<EnterpriseTool>,
    pub breakdown_techniques:       EnterpriseTechniquesByPlatform,
    pub breakdown_subtechniques:    EnterpriseSubtechniquesByPlatform,
    pub uniques_techniques:         Vec<String>,
    pub uniques_subtechniques:      Vec<String>,
    pub rollup_techniques:          Vec<EnterpriseTechniquesByTactic>,
    pub rollup_subtechniques:       Vec<EnterpriseTechniquesByTactic>,
    pub stats:                      EnterpriseMatrixStatistics,
}
impl EnterpriseMatrixBreakdown {
    pub fn new() -> Self {
        EnterpriseMatrixBreakdown {
            adversaries: vec![],
            malware: vec![],
            tools: vec![],
            tactics: HashSet::new(),
            platforms: HashSet::new(),
            datasources: Vec::new(),
            revoked_techniques: HashSet::new(),
            deprecated_techniques: HashSet::new(),
            breakdown_adversaries: vec![],
            breakdown_malware: vec![],
            breakdown_tools: vec![],
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
    pub relationships: EnterpriseRelationships,
    pub details: EnterpriseMatrixBreakdown,
}
impl EnterpriseMatrixParser {
    pub fn new() -> EnterpriseMatrixParser {
        EnterpriseMatrixParser {
            techniques: HashSet::new(),
            subtechniques: HashSet::new(),
            relationships: EnterpriseRelationships::new(),
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
                self.extract_malware(_t);
            }
            else if _s == "intrusion-set" {
                self.details.stats.count_adversaries += 1;
                self.extract_adversaries(_t);
            }
            else if _s == "tool" {
                self.details.stats.count_tools += 1;
                self.extract_tools(_t);
            }
            else if _s == "relationship" {
                self.extract_relationshsip(_t);
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
        // Now Correlate Relationships
        self.correlate_relationships();
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
        let _id  = items["id"].as_str().expect("Problem With Technique UID");
        let _id  = _id.to_string();
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
            _et.id = _id.clone();
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
                    _et.id = _id.clone();
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
                    }
                    else if _os == "azure-ad" {
                        _azure_ad.insert(_stub);
                    }
                    else if _os == "azure" {
                        _azure.insert(_stub);
                    }
                    else if _os == "gcp" {
                        _gcp.insert(_stub);
                    }
                    else if _os == "linux" {
                        _linux.insert(_stub);
                    }
                    else if _os == "macos" {
                        _macos.insert(_stub);
                    }
                    else if _os == "office-365" {
                        _office365.insert(_stub);
                    }
                    else if _os == "saas" {
                        _saas.insert(_stub);
                    }
                    else if _os == "windows" {
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
    fn extract_malware(&mut self,
        items: &serde_json::Value   
    ) -> Result<(), Box<dyn std::error::Error>>
    {
        let mut _is_revoked: bool = false;
        let _malware = items.as_object().expect("Malware: Proble Convert Into Oject");
        if _malware.contains_key("revoked") {
            if _malware["revoked"].as_bool().expect("Malaware: Problem Is Revoked Check") {
                _is_revoked = true;
            }
        }
        let _malware_id = items["external_references"].as_array().expect("Malware: Problem With External References");
        let _malware_id = _malware_id[0]["external_id"].as_str().expect("Malware: Problem With External ID");
        let _malware_id = _malware_id.to_string();
        let _id = items["id"].as_str().expect("Malware: Problem With UID");
        let _id = _id.to_string();
        let _name = items["name"].as_str().expect("Malware: Problem With Malware Name");
        let _name = _name.to_string();
        let mut _platforms = String::from("");
        let mut _revoked_malware: usize = 0;
        if _is_revoked {
            _revoked_malware += 1;
        }
        if _malware.contains_key("x_mitre_platforms") {
            for _os in items["x_mitre_platforms"].as_array().unwrap().iter() {
                let _x = _os.as_str().unwrap().to_lowercase().replace(" ", "-");
                &_platforms.push_str(_x.as_str());
                &_platforms.push_str("|");
            }
            _platforms.pop();
        } else {
            &_platforms.push_str("none");
        }
        let mut _aliases = String::from("");
        if _malware.contains_key("aliases") {
            for _alias in items["aliases"].as_array().unwrap().iter() {
                let _x = _alias.as_str().unwrap().to_lowercase().replace(" ", "-");
                &_aliases.push_str(_x.as_str());
                &_aliases.push_str("|");
            }
            _aliases.pop();
        } else {
            _aliases.push_str("none");
        }
        self.details.malware.push(_name.clone());
        let _em = EnterpriseMalware {
            id:         _id,
            name:       _name,
            aliases:    _aliases,
            platforms:  _platforms,
            malware_id: _malware_id,
            is_revoked: _is_revoked,
            profile:    EnterpriseMalwareProfile::new()
        };
        self.details.breakdown_malware.push(_em);
        self.details.malware.sort();
        self.details.malware.dedup();
        self.details.malware.sort();                        
        Ok(())
    }
    fn extract_tools(&mut self,
        items: &serde_json::Value   
    ) -> Result<(), Box<dyn std::error::Error>>
    {
        let mut _is_revoked: bool = false;
        let _tools = items.as_object().expect("Tools: Proble Convert Into Oject");
        if _tools.contains_key("revoked") {
            if _tools["revoked"].as_bool().expect("Tools: Problem Is Revoked Check") {
                _is_revoked = true;
            }
        }
        let _tool_id = items["external_references"].as_array().expect("Tools: Problem With External References");
        let _tool_id = _tool_id[0]["external_id"].as_str().expect("Tools: Problem With External ID");
        let _tool_id = _tool_id.to_string();
        let _id = items["id"].as_str().expect("Tools: Problem With UID");
        let _id = _id.to_string();
        let _name = items["name"].as_str().expect("Tools: Problem With Malware Name");
        let _name = _name.to_string();
        let mut _platforms = String::from("");
        let mut _revoked_tools: usize = 0;
        if _is_revoked {
            _revoked_tools += 1;
        }
        if _tools.contains_key("x_mitre_platforms") {
            for _os in items["x_mitre_platforms"].as_array().unwrap().iter() {
                let _x = _os.as_str().unwrap().to_lowercase().replace(" ", "-");
                &_platforms.push_str(_x.as_str());
                &_platforms.push_str("|");
            }
            _platforms.pop();
        } else {
            &_platforms.push_str("none");
        }
        let mut _aliases = String::from("");
        if _tools.contains_key("aliases") {
            for _alias in items["aliases"].as_array().unwrap().iter() {
                let _x = _alias.as_str().unwrap().to_lowercase().replace(" ", "-");
                &_aliases.push_str(_x.as_str());
                &_aliases.push_str("|");
            }
            _aliases.pop();
        } else {
            _aliases.push_str("none");
        }
        self.details.tools.push(_name.clone());
        let _et = EnterpriseTool {
            id:         _id,
            name:       _name,
            aliases:    _aliases,
            platforms:  _platforms,
            tool_id:    _tool_id,
            is_revoked: _is_revoked,
            profile:    EnterpriseToolProfile::new()
        };
        self.details.breakdown_tools.push(_et);
        self.details.tools.sort();
        self.details.tools.dedup();
        self.details.tools.sort();                        
        Ok(())
    }    
    fn extract_adversaries(&mut self,
        items: &serde_json::Value   
    ) -> Result<(), Box<dyn std::error::Error>>
    {
        let mut _is_revoked: bool = false;
        let _adversary = items.as_object().expect("Adversary: Proble Convert Into Oject");
        if _adversary.contains_key("revoked") {
            if _adversary["revoked"].as_bool().expect("Adversary: Problem Is Revoked Check") {
                _is_revoked = true;
            }
        }
        let _gid = items["external_references"].as_array().expect("Adversary: Problem With External References");
        let _gid = _gid[0]["external_id"].as_str().expect("Adversary: Problem With External ID");
        let _gid = _gid.to_string();
        let _id = items["id"].as_str().expect("Adversary: Problem With UID");
        let _id = _id.to_string();
        let _gname = items["name"].as_str().expect("Adversary: Problem With Technique Name");
        let _gname = _gname.to_string();
        let mut _aliases = String::from("");
        let mut _revoked_adversaries: usize = 0;
        if _is_revoked {
            _revoked_adversaries += 1;
        } else {
            for _alias in items["aliases"].as_array().unwrap().iter() {
                let _x = _alias.as_str().unwrap().to_lowercase().replace(" ", "-");
                &_aliases.push_str(_x.as_str());
                &_aliases.push_str("|");
                self.details.adversaries.push(_x.to_string());
            }
            _aliases.pop();
        }
        let _ea = EnterpriseAdversary {
            id:         _id,
            name:       _gname,
            aliases:    _aliases,
            group_id:   _gid,
            is_revoked: _is_revoked,
            profile:    EnterpriseAdversaryProfile::new()
        };
        self.details.breakdown_adversaries.push(_ea);
        self.details.adversaries.sort();
        self.details.adversaries.dedup();
        self.details.adversaries.sort();
        Ok(())
    }
    fn extract_relationshsip(&mut self,
        items: &serde_json::Value   
    ) -> Result<(), Box<dyn std::error::Error>>
    {
        let _relationship = items.as_object().expect("Relationship Problem, Convert To Object");
        let mut _er = EnterpriseRelationship::new();
        _er.id = _relationship["id"].as_str().unwrap().to_string();
        let _sr: &str = _relationship["source_ref"].as_str().expect("Relationship Problem, Convert Source Ref");
        let _sr = _sr.to_string();
        let _tr: &str = _relationship["target_ref"].as_str().expect("Relationship Problem, Convert Target Ref");
        let _tr = _tr.to_string();
        _er.source = _sr;
        _er.target = _tr;
        if _relationship["relationship_type"] == "uses" {
            _er.relation_type = "uses".to_string();
            // Map relationships
            // adversary <---> technique
            if _er.source.starts_with("intrusion-set") && _er.target.starts_with("attack-pattern") {
                self.relationships.adversary_to_techniques.insert(_er);
            }
            // adversary <---> weapon/malware
            else if _er.source.starts_with("intrusion-set") && _er.target.starts_with("malware") {
                self.relationships.adversary_to_malware.insert(_er);
            }
            // adversary <---> weapon/non-malware
            else if _er.source.starts_with("intrusion-set") && _er.target.starts_with("tool") {
                self.relationships.adversary_to_tools.insert(_er);
            }
            // weapon/malware <---> technique
            else if _er.source.starts_with("malware") && _er.target.starts_with("attack-pattern") {
                self.relationships.malware_to_techniques.insert(_er);
            }
            // weapon/non-malware <---> technique
            else if _er.source.starts_with("tool") && _er.target.starts_with("attack-pattern") {
                self.relationships.tool_to_techniques.insert(_er);
            }            
        }
        Ok(())
    }
    fn correlate_relationships(&mut self)
    {
        // Adversaries to Malware
        for _adversary in self.details.breakdown_adversaries.iter_mut() {
            // Correlate Adversary to Malware
            for _weapon in self.relationships.adversary_to_malware.iter() {
                if _adversary.id.as_str() == _weapon.source.as_str() {
                    // Now correlate the name of the weapon
                    // and update the adversary
                    for _malware in self.details.breakdown_malware.iter() {
                        if _weapon.target.as_str() == _malware.id.as_str() {
                            _adversary.profile.malware.items.push(_malware.name.clone());
                        }
                    }
                }
            }
            _adversary.profile.update();
            // Correlate Adversary to Tools
            for _weapon in self.relationships.adversary_to_tools.iter() {
                if _adversary.id.as_str() == _weapon.source.as_str() {
                    for _tool in self.details.breakdown_tools.iter() {
                        if _weapon.target.as_str() == _tool.id.as_str() {
                            _adversary.profile.tools.items.push(_tool.name.clone());
                        }
                    }
                }
            }
            // Correlate Adversary to Techniques & Subtechniques
            for _behavior in self.relationships.adversary_to_techniques.iter() {
                if _adversary.id.as_str() == _behavior.source.as_str() {
                    for _technique in self.details.breakdown_techniques.platforms.iter() {
                        if _behavior.target.as_str() == _technique.id.as_str() {
                            _adversary.profile.techniques.items.push(_technique.tid.clone())
                        }
                    }
                    for _subtechnique in self.details.breakdown_subtechniques.platforms.iter() {
                        if _behavior.target.as_str() == _subtechnique.id.as_str() {
                            _adversary.profile.subtechniques.items.push(_subtechnique.tid.clone())
                        }
                    }
                }
            }
        }
        // Malware to Techniques & Subtechniques
        for _malware in self.details.breakdown_malware.iter_mut() {
            for _weapon in self.relationships.malware_to_techniques.iter() {
                if _malware.id.as_str() == _weapon.source.as_str() {
                    for _technique in self.details.breakdown_techniques.platforms.iter() {
                        if _weapon.target.as_str() == _technique.id.as_str() {
                            _malware.profile.techniques.items.push(_technique.tid.clone())
                        }
                    }
                    for _subtechnique in self.details.breakdown_subtechniques.platforms.iter() {
                        if _weapon.target.as_str() == _subtechnique.id.as_str() {
                            _malware.profile.subtechniques.items.push(_subtechnique.tid.clone())
                        }
                    }
                }
            }
            _malware.profile.update();
        }
        // Tools to Techniques and Subtechniques
        for _tool in self.details.breakdown_tools.iter_mut() {
            for _weapon in self.relationships.tool_to_techniques.iter() {
                if _tool.id.as_str() == _weapon.source.as_str() {
                    for _technique in self.details.breakdown_techniques.platforms.iter() {
                        if _weapon.target.as_str() == _technique.id.as_str() {
                            _tool.profile.techniques.items.push(_technique.tid.clone())
                        }
                    }
                    for _subtechnique in self.details.breakdown_subtechniques.platforms.iter() {
                        if _weapon.target.as_str() == _subtechnique.id.as_str() {
                            _tool.profile.subtechniques.items.push(_subtechnique.tid.clone())
                        }
                    }
                }
            }
            _tool.profile.update();
        }
    }
}