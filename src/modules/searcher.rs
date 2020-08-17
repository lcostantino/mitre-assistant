use serde_json;
use prettytable::{Table, Row, Cell};


#[path = "./parser.rs"]
mod parser;
use parser::EnterpriseMatrixBreakdown;


#[path = "../structs/enterprise.rs"]
mod enterprise;
use enterprise::{EnterpriseTechnique, EnterpriseMatrixStatistics};


#[path = "../utils/fshandler.rs"]
mod fshandler;
use fshandler::FileHandler;


#[path = "../utils/regexes.rs"]
mod regexes;
use regexes::RegexPatternManager;


pub struct EnterpriseMatrixSearcher{
    matrix:     String,
    content:    Vec<u8> 
}
impl EnterpriseMatrixSearcher {
    pub fn new(matrix_type: &str) -> Self
    {
        let _input = matrix_type.to_lowercase();
        let mut _content: Vec<u8> = vec![];
        if _input == "enterprise".to_string() {
            _content = FileHandler::load_baseline("baselines", "baseline-enterprise.json");
        }
        EnterpriseMatrixSearcher {
            matrix:  _input,
            content: _content
        } 
    }
    pub fn search(&self, search_term: &str, _wants_subtechniques: bool)
    {
        let mut _results: Vec<String> = vec![];
        let mut _valid: Vec<(&str, usize)> = vec![];
        let _st = search_term.to_lowercase();
        let _st = _st.as_str();
        let _scanner = RegexPatternManager::load_search_term_patterns();
        // Special Flags
        //      Easier to search this way without flooding the user with parameters
        //      These flags are commonly placed in both the query and render functions 
        let mut _wants_stats: bool = false;                         // Returns The Stats Key
        let mut _wants_nosub: bool = false;                         // Returns Techniques That Don't Have Subtechniques
        let mut _wants_revoked: bool = false;                       // Returns Techniques Revoked By Mitre
        let mut _wants_tactics: bool = false;                       // Returns The Tactics Key
        let mut _wants_platforms: bool = false;                     // Returns The Platforms Key
        let mut _wants_deprecated: bool = false;                    // Returns The Deprecated Techniques
        let mut _wants_datasources: bool = false;                   // Returns The Data Sources Key
        let mut _wants_xref_datasources_tactics: bool = false;      // Returns The Stats Count XREF of Datasoources By Tactic
        let mut _wants_xref_datasources_platforms: bool = false;    // Return The Stats Count XREF of Datasources By Platform
        // Parse the search term explicitly
        //      We are not using partial matches on search term keywords
        //      We keep a simple incrementing usize by search term
        if _st == "revoked" {
            _valid.push((_st, 3usize));
            _wants_revoked = true;
        }
        else if _st == "stats" {
            _valid.push((_st, 4usize));
            _wants_stats = true;
        }
        else if _st == "nosub" {
            _valid.push((_st, 5usize));
            _wants_nosub = true;
        }
        else if _st == "techniques" {
            _valid.push((_st, 6usize)); 
        }
        else if _st == "subtechniques" {
            _valid.push((_st, 7usize));     
        }
        else if _st == "datasources" {
            _valid.push((_st, 8usize));     
            _wants_datasources = true;
        }
        else if _st == "platforms" {
            _valid.push((_st, 9usize));     
            _wants_platforms = true;
        }
        else if _st == "nodatasources" {
            _valid.push((_st, 10usize));
        }
        else if _st == "tactics" {
            _valid.push((_st, 11usize));
            _wants_tactics = true;
        }
        else if _st == "deprecated" {
            _valid.push((_st, 12usize));
            _wants_deprecated = true;
        }
        else if _st == "initial-access" {
            _valid.push((_st, 13usize));
        }
        else if _st == "execution" {
            _valid.push((_st, 14usize));
        }
        else if _st == "persistence" {
            _valid.push((_st, 15usize));
        }
        else if _st == "privilege-escalation" {
            _valid.push((_st, 16usize));
        }
        else if _st == "defense-evasion" {
            _valid.push((_st, 17usize));
        }
        else if _st == "credential-access" {
            _valid.push((_st, 18usize));
        }   
        else if _st == "discovery" {
            _valid.push((_st, 19usize));
        }
        else if _st == "lateral-movement" {
            _valid.push((_st, 20usize));
        }
        else if _st == "collection" {
            _valid.push((_st, 21usize));
        }
        else if _st == "command-and-control" {
            _valid.push((_st, 22usize));
        }
        else if _st == "exfiltration" {
            _valid.push((_st, 23usize));
        }
        else if _st == "impact" {
            _valid.push((_st, 24usize));
        }
        else if _st == "aws" {
            _valid.push((_st, 25usize));
        }
        else if _st == "azure" {
            _valid.push((_st, 26usize));
        }
        else if _st == "azure-ad" {
            _valid.push((_st, 27usize));
        }
        else if _st == "gcp" {
            _valid.push((_st, 28usize));
        }
        else if _st == "linux" {
            _valid.push((_st, 29usize));
        }
        else if _st == "macos" {
            _valid.push((_st, 30usize));
        }
        else if _st == "office-365" {
            _valid.push((_st, 31usize));
        }
        else if _st == "saas" {
            _valid.push((_st, 32usize));
        }
        else if _st == "windows" {
            _valid.push((_st, 33usize));
        }
        else if _st == "overlap" {
            _valid.push((_st, 34usize));
        }
        else if _st == "xref:datasources:platforms" {
            _valid.push((_st, 35usize));
            _wants_xref_datasources_platforms = true;
        }
        else if _st == "xref:datasources:tactics" {
            _valid.push((_st, 36usize));
            _wants_xref_datasources_tactics = true;
        }                                                                                          
        else if !_st.contains(",") {
            if _scanner.pattern.is_match(_st) {
                let _idx: Vec<usize> = _scanner.pattern.matches(_st).into_iter().collect();
                _valid.push((_st, _idx[0]));  // Search Term 0usize
            }
        }
        else if _st.contains(",") {
            let _terms: Vec<&str> = _st.split(',').collect();
            _valid = _terms.iter()
                        .filter(|_x| _scanner.pattern.is_match(_x))
                        .map(|_x| {
                            let _idx: Vec<_> = _scanner.pattern.matches(_x).into_iter().collect();
                            (*_x, _idx[0]) // Search Term 1usize
                        })
                        .collect();
        }        
        // Query
        // —————
        // Once a full match is valid and a pattern is assigned
        // let's redirect the pattern to the relevant query function
        //      Notice:     Based on the pattern usize, a specific function is called.
        //                  Any query function must return a Stringified Vector from
        //                  the `EnterpriseMatrixBreakdown` struct.
        if _valid.len() >= 1 {
            for (_term, _pattern) in _valid.iter() {
                if _pattern == &0usize {
                    _results.push(self.enterprise_by_id(_term, _wants_subtechniques));
                }
                else if _pattern == &1usize {
                    _results.push(self.enterprise_by_subtechnique_id(_term));
                }
                else if _pattern == &2usize {
                    _results.push(self.enterprise_by_name(_term));
                }
                else if _pattern == &3usize {
                    _results.push(self.enterprise_revoked());
                }
                else if _pattern == &4usize {
                    _results.push(self.enterprise_stats());
                }
                else if _pattern == &5usize {
                    _results.push(self.enterprise_by_nosubtechniques());
                }
                else if _pattern == &6usize {
                    _results.push(self.enterprise_all_techniques());
                }
                else if _pattern == &7usize {
                    _results.push(self.enterprise_all_subtechniques());
                }
                else if _pattern == &8usize {
                    _results.push(self.enterprise_all_datasources());
                }
                else if _pattern == &9usize {
                    _results.push(self.enterprise_all_platforms());
                }
                else if _pattern == &10usize {
                    _results.push(self.enterprise_by_no_datasources());
                }
                else if _pattern == &11usize {
                    _results.push(self.enterprise_all_tactics());
                }
                else if _pattern == &12usize {
                    _results.push(self.enterprise_by_deprecated());
                }
                else if _pattern == &13usize {
                    _results.push(self.enterprise_by_tactic(_term, _wants_subtechniques));
                }
                else if _pattern == &14usize {
                    _results.push(self.enterprise_by_tactic(_term, _wants_subtechniques));
                }
                else if _pattern == &15usize {
                    _results.push(self.enterprise_by_tactic(_term, _wants_subtechniques));
                } 
                else if _pattern == &16usize {
                    _results.push(self.enterprise_by_tactic(_term, _wants_subtechniques));
                }
                else if _pattern == &17usize {
                    _results.push(self.enterprise_by_tactic(_term, _wants_subtechniques));
                }
                else if _pattern == &18usize {
                    _results.push(self.enterprise_by_tactic(_term, _wants_subtechniques));
                }
                else if _pattern == &19usize {
                    _results.push(self.enterprise_by_tactic(_term, _wants_subtechniques));
                }
                else if _pattern == &20usize {
                    _results.push(self.enterprise_by_tactic(_term, _wants_subtechniques));
                }
                else if _pattern == &21usize {
                    _results.push(self.enterprise_by_tactic(_term , _wants_subtechniques));
                }
                else if _pattern == &22usize {
                    _results.push(self.enterprise_by_tactic(_term, _wants_subtechniques));
                }
                else if _pattern == &23usize {
                    _results.push(self.enterprise_by_tactic(_term, _wants_subtechniques));
                }
                else if _pattern == &24usize {
                    _results.push(self.enterprise_by_tactic(_term, _wants_subtechniques));
                }
                else if _pattern == &25usize {
                    _results.push(self.enterprise_by_platform("aws", _wants_subtechniques));
                }
                else if _pattern == &26usize {
                    _results.push(self.enterprise_by_platform("azure", _wants_subtechniques));
                }
                else if _pattern == &27usize {
                    _results.push(self.enterprise_by_platform("azure-ad", _wants_subtechniques));
                }
                else if _pattern == &28usize {
                    _results.push(self.enterprise_by_platform("gcp", _wants_subtechniques));
                }
                else if _pattern == &29usize {
                    _results.push(self.enterprise_by_platform("linux", _wants_subtechniques));
                }
                else if _pattern == &30usize {
                    _results.push(self.enterprise_by_platform("macos", _wants_subtechniques));
                }
                else if _pattern == &31usize {
                    _results.push(self.enterprise_by_platform("office-365", _wants_subtechniques));
                }
                else if _pattern == &32usize {
                    _results.push(self.enterprise_by_platform("saas", _wants_subtechniques));
                }
                else if _pattern == &33usize {
                    _results.push(self.enterprise_by_platform("windows", _wants_subtechniques));
                }
                else if _pattern == &34usize {
                    _results.push(self.enterprise_all_overlapped());
                }
                else if _pattern == &35usize {
                    _results.push(self.enterprise_stats_datasources_and_platforms());
                }
                else if _pattern == &36usize {
                    _results.push(self.enterprise_stats_datasources_and_tactics());
                }                                                                                                                                                                                                                                                                                                                                                                                                  
            }
            // Render Query Results
            // --------------------
            // Upon getting search query results, apply a renderer to present results.
            // By default, pretty tables are used to render results.
            //
            //      Note:   Transforming results into CSV, JSON should be done within
            //              the renderer functions.
            //    
            if _wants_revoked {
                self.render_enterprise_revoked_table(&_results);
            }
            else if _wants_stats {
                self.render_enterprise_stats(&_results);
            }
            else if _wants_datasources {
                self.render_enterprise_datasources_table(&_results);
            }
            else if _wants_platforms {
                self.render_enterprise_platforms_table(&_results);
            }
            else if _wants_tactics {
                self.render_enterprise_tactics_table(&_results);
            }
            else if _wants_deprecated {
                self.render_enterprise_deprecated_table(&_results);
            }
            else if _wants_xref_datasources_platforms {
                self.render_enterprise_stats_xref_datasource_platforms(&_results);
            }
            else if _wants_xref_datasources_tactics {
                self.render_enterprise_stats_xref_datasource_tactics(&_results);
            }
            else {
                self.render_enterprise_table(&_results);
            }
        } else {
            println!(r#"[ "Results": {}, "SearchTerm": {} ]"#, "None Found", search_term);
        }
    }
    /// # **Query Functions**
    ///
    /// All of the functions from this source code section are for the queries provided by
    /// the end-user.
    ///
    /// Query functions must return a Stringified version of a JSON object - i.e., Vec<EnterpriseTechnique>
    ///
    /// The searcher uses the `serde_json::to_string` method for the conversion of objects to provide the
    /// Stringified version of the JSON object.
    ///
    ///
    /// ## **Query Functions Are Private**
    ///
    /// All of the functions are **private functions** that are not exposed to the end-user.  They are only accessible
    /// from the module itself, and specifically, when invoked by the `self.search()` method.
    ///
    fn enterprise_by_platform(&self, platform: &str, _wants_subtechniques: bool) -> String
    {
        let mut _results = vec![];
        let _msg = format!("(?) Error: Unable To Deserialize String of All Techniques by Platform: {}", platform);
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).expect(_msg.as_str());
        for _item in _json.breakdown_techniques.platforms.iter() {
            if _item.platform.contains(platform) {
                let mut _modified = EnterpriseTechnique::new();
                _modified.tid = _item.tid.clone();
                _modified.technique = _item.technique.clone();
                _modified.tactic = _item.tactic.clone();
                _modified.datasources = _item.datasources.clone();
                _modified.has_subtechniques = _item.has_subtechniques.clone();
                _modified.subtechniques = _item.subtechniques.clone();
                _modified.platform = platform.to_string();
                _results.push(_modified);
            }
        }
        if _wants_subtechniques {
            for _item in _json.breakdown_subtechniques.platforms.iter() {
                if _item.platform.contains(platform) {
                    let mut _modified = EnterpriseTechnique::new();
                    _modified.tid = _item.tid.clone();
                    _modified.technique = _item.technique.clone();
                    _modified.tactic = _item.tactic.clone();
                    _modified.datasources = _item.datasources.clone();
                    _modified.has_subtechniques = _item.has_subtechniques.clone();
                    _modified.subtechniques = _item.subtechniques.clone();
                    _modified.platform = platform.to_string();
                    _results.push(_modified);
                }
            }
        }
        let _msg = format!("(?) Error: Unable To Convert String of All Techniques by Platform: {}", platform);
        serde_json::to_string(&_results).expect(_msg.as_str())    
    }
    /// # Query By Tactics
    ///
    /// Allows the user to get all techniques by specifying a tactic.
    ///
    /// ```ignore
    /// self.enterprise_by_tactic("initial-access", false)
    /// ```
    fn enterprise_by_tactic(&self, tactic: &str, _wants_subtechniques: bool) -> String
    {
        let mut _results = vec![];
        let _msg = format!("(?) Error: Unable To Deserialize String of All Techniques by Tactic: {}", tactic);
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).expect(_msg.as_str());
        for _item in _json.breakdown_techniques.platforms.iter() {
            if _item.tactic.contains(tactic) {
                _results.push(_item);
            }
        }
        if _wants_subtechniques {
            for _item in _json.breakdown_subtechniques.platforms.iter() {
                if _item.tactic.contains(tactic) {
                    _results.push(_item);
                }
            }
        }
        let _msg = format!("(?) Error: Unable To Convert String of All Techniques by Tactic: {}", tactic);
        serde_json::to_string(&_results).expect(_msg.as_str())
    }
    /// # Query By Deprecated Techniques
    ///
    /// Allows the user to get all deprecated techniques.
    ///
    /// ```ignore
    /// self.deprecated();
    /// ```
    fn enterprise_by_deprecated(&self) -> String
    {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).expect("(?) Error: Unable to Deserialize All Deprecated Techniques");
        for _item in _json.deprecated_techniques {
            _results.push(_item)
        }
        _results.sort();
        serde_json::to_string(&_results).expect("(?) Error: Unable To Deserialize String Of All Deprecated Techniques")        
    }
    /// # Query To Get All Active Tactics
    ///
    /// Allows the user to get all of the Active Tactics.
    ///
    /// ```ignore
    /// self.enterprise_all_tactics();
    /// ```
    fn enterprise_all_tactics(&self) -> String
    {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).expect("(?) Error: Unable to Deserialize All Tactics");
        for _item in _json.tactics {
            _results.push(_item)
        }
        _results.sort();
        serde_json::to_string(&_results).expect("(?) Error: Unable To Deserialize All Tactics")
    }
    /// # Query To Get All Overlapped Techniques
    ///
    /// Allows the user to get all of the techniques considered to have an overlap.
    /// Overlap occurs when a technique is spread across more than one tactic/killchain.
    ///
    /// ```ignore
    /// self.enterprise_all_overlapped();
    /// ```
    fn enterprise_all_overlapped(&self) -> String
    {
        use std::collections::HashSet;
        
        let mut _results = vec![];
        let mut _targets = HashSet::new();
        let _msg = "(?) Error: Unable to Deserialize All Overlapped Techniques";
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).expect(_msg);
        // Iterate the Unique Techniques Key
        // Find the Techniques with Overlap by Tactic
        for _technique in _json.uniques_techniques.iter() {
            let mut _overlap: usize = 0;
            for _item in _json.breakdown_techniques.platforms.iter() {
                if _item.tid.as_str() == _technique.as_str() {
                    _overlap += 1;
                    if _overlap > 1usize {
                        _targets.insert(_technique);
                    }
                }
            }
        }
        // Now get all the overlapped techniques
        for _target in _targets {
            let mut _modified = EnterpriseTechnique::new();
            for _technique in _json.breakdown_techniques.platforms.iter() {
                if _technique.tid.as_str() == _target.as_str() {
                    _results.push(_technique);
                }
            }
        }
        let _msg = "(?) Error: Unable to Convert All Overlapped Techniques";
        serde_json::to_string(&_results).expect(_msg)
    }
    /// # Query All Active Techniques
    ///
    /// Allows the user to get all of the Active Techniques.
    ///
    /// ```ignore
    /// self.enterprise_all_techniques();
    /// ```
    fn enterprise_all_techniques(&self) -> String
    {
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        serde_json::to_string(&_json.breakdown_techniques.platforms).expect("(?) Error: Unable To Deserialize All Techniques")
    }
    /// # Query All Active Subtechniques
    ///
    /// Allows the user to get all of the Active Subtechniques.
    ///
    /// ```ignore
    /// self.enterprise_all_subtechniques();
    /// ```
    fn enterprise_all_subtechniques(&self) -> String
    {
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        serde_json::to_string(&_json.breakdown_subtechniques.platforms).expect("(?) Error: Unable To Deserialize All Techniques")
    }
    /// # Query All Platforms
    ///
    /// Allows the user to get all the platforms.
    ///
    /// ```ignore
    /// self.enterprise_all_platforms();
    /// ```
    fn enterprise_all_platforms(&self) -> String
    {
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        serde_json::to_string(&_json.platforms).expect("(?) Error: Unable To Deserialize All Platforms")
    }
    fn enterprise_all_datasources(&self) -> String
    {
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        serde_json::to_string(&_json.datasources).expect("(?) Error: Unable To Deserialize All Datasources")
    }
    fn enterprise_by_no_datasources(&self) -> String
    {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).expect("(?) Error: Unable to Deserialize By No Datasources");
        for _item in _json.breakdown_techniques.platforms.iter() {
            if _item.datasources.as_str() == "none" {
                _results.push(_item);
            }
        }
        for _item in _json.breakdown_subtechniques.platforms.iter() {
            if _item.datasources.as_str() == "none" {
                _results.push(_item);
            }
        }
        serde_json::to_string(&_results).expect("(?) Error: Unable To Serialize By No Datasources")
    }
    fn enterprise_by_name(&self, technique_name: &str) -> String
    {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        for _item in _json.breakdown_techniques.platforms.iter() {
            if _item.technique.to_lowercase().as_str() == technique_name.to_lowercase().as_str() {
                _results.push(_item);
            } else if _item.technique.to_lowercase().as_str().contains(technique_name.to_lowercase().as_str()) {
               _results.push(_item);
            }
        }
        // Now Search Subtechniques
        for _item in _json.breakdown_subtechniques.platforms.iter() {
            if _item.technique.to_lowercase().as_str() == technique_name.to_lowercase().as_str() {
                _results.push(_item);
            } else if _item.technique.to_lowercase().as_str().contains(technique_name.to_lowercase().as_str()) {
               _results.push(_item);
            }
        }        
        serde_json::to_string_pretty(&_results).expect("(?) Error:  Unable To Deserialize Search Results By Technique Name")
    }
    fn enterprise_by_id(&self, technique_id: &str, _wants_subtechniques: bool) -> String
    {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).expect("HERE");
        for _item in _json.breakdown_techniques.platforms.iter() {
            if _item.tid.to_lowercase().as_str() == technique_id.to_lowercase().as_str() {
                if _wants_subtechniques {
                    if _item.has_subtechniques {
                        _results.push(_item);
                        for _subtechnique in _json.breakdown_subtechniques.platforms.iter() {
                            if _subtechnique.tid.contains(&_item.tid) {
                                _results.push(_subtechnique);
                            }
                        }
                    }
                } else {
                    _results.push(_item);
                }
            }
        }
        if _results.len() == 0usize {
            // If no results then we want to search for a two conditions
            //      1. When the user wants subtechniques, then get them
            //      2. Or, when there are revoked techniques, let's add these
            //          to save time for users writing more queries
            //      3. Or, when there are deprecated techniques,get them too
            if _wants_subtechniques {
                for _subtechnique in _json.breakdown_subtechniques.platforms.iter() {
                    if _subtechnique.tid.contains(technique_id.to_uppercase().as_str()) {
                        _results.push(_subtechnique);
                    }
                }
            }
            // Check & Get From Revoked Techniques
            let mut _results = vec![];
            for _revoked in _json.revoked_techniques.iter() {
                if _revoked.0.to_lowercase().as_str() == technique_id.to_lowercase().as_str() {
                    let mut _modified = EnterpriseTechnique::new();
                    _modified.tid = _revoked.0.clone();
                    _modified.technique = _revoked.1.clone();
                    _modified.is_revoked = true;
                    _results.push(_modified);
                }
            }
            // Check & Get From Deprecated Techniques
            for _deprecated in _json.deprecated_techniques.iter() {
                if _deprecated.0.to_lowercase().as_str() == technique_id.to_lowercase().as_str() {
                    let mut _modified = EnterpriseTechnique::new();
                    _modified.tid = _deprecated.0.clone();
                    _modified.technique = _deprecated.1.clone();
                    _modified.is_deprecated = true;
                    _results.push(_modified);
                }                
            }
            serde_json::to_string_pretty(&_results).expect("(?) Error:  Unable To Deserialize Search Results By Revoked Technique ID")
        } else {
            serde_json::to_string_pretty(&_results).expect("(?) Error:  Unable To Deserialize Search Results By Technique ID")
        }
    }
    fn enterprise_by_subtechnique_id(&self, technique_id: &str) -> String
    {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        for _item in _json.breakdown_subtechniques.platforms.iter() {
            if _item.tid.to_lowercase().as_str() == technique_id.to_lowercase().as_str() {
                _results.push(_item);
            }
        }
        serde_json::to_string_pretty(&_results).expect("(?) Error:  Unable To Deserialize Search Results By Subtechnique ID")
    }
    fn enterprise_revoked(&self) -> String
    {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        for _item in _json.revoked_techniques.iter() {
            _results.push(_item);
        }
        serde_json::to_string_pretty(&_results).expect("(?) Error:  Unable To Deserialize Search Results By Revoked Techniques")
    }
    fn enterprise_stats(&self) -> String
    {
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        serde_json::to_string_pretty(&_json.stats).expect("(?) Error:  Unable To Deserialize Search Results By Enterprise Stats")
    }
    fn enterprise_by_nosubtechniques(&self) -> String {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        for _item in _json.breakdown_techniques.platforms.iter() {
            if !_item.has_subtechniques {
                _results.push(_item);
            }
        }
        serde_json::to_string_pretty(&_results).expect("(?) Error: Unable To Deserialize Search Results By HAS_NO_SUBTECHNIQUES")
    }
    fn enterprise_stats_datasources_and_platforms(&self) -> String
    {
        use std::collections::HashMap;
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        let mut _ds: HashMap<String, HashMap<String, usize>> = HashMap::new();
        let mut _results: Vec<HashMap<String, HashMap<String, usize>>> = vec![];
        for _datasource in _json.datasources.iter() {
            let mut _os: HashMap<String, usize> = HashMap::new();
            
            for _platform in _json.platforms.iter() {
                _os.insert(_platform.clone(), 0usize);
                for _technique in _json.breakdown_techniques.platforms.iter() {
                    if _technique.datasources.contains(_datasource)
                        && _technique.platform.contains(_platform) {
                            let _value = _os.get_mut(_platform.as_str()).unwrap();
                            *_value += 1usize;
                        }
                }   
            }
            _ds.insert(_datasource.clone(), _os);
        }
        _results.push(_ds);
        serde_json::to_string_pretty(&_results).expect("(?) Error: Unable To Deserialize STATS For Datasources & Platforms")
    }
    fn enterprise_stats_datasources_and_tactics(&self) -> String
    {
        use std::collections::HashMap;
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        let mut _ds: HashMap<String, HashMap<String, usize>> = HashMap::new();
        let mut _results: Vec<HashMap<String, HashMap<String, usize>>> = vec![];
        for _datasource in _json.datasources.iter() {
            let mut _tactics: HashMap<String, usize> = HashMap::new();
        
            for _tactic in _json.tactics.iter() {
                _tactics.insert(_tactic.clone(), 0usize);
                for _technique in _json.breakdown_techniques.platforms.iter() {
                    if _technique.datasources.contains(_datasource)
                        && _technique.tactic.contains(_tactic) {
                            let _value = _tactics.get_mut(_tactic.as_str()).unwrap();
                            *_value += 1usize;
                        }
                }   
            }
            _ds.insert(_datasource.clone(), _tactics);
        }
        _results.push(_ds);
        serde_json::to_string_pretty(&_results).expect("(?) Error: Unable To Deserialize STATS For Datasources & Tactics")
    }    
    /// # **Rendering Functions**
    /// This section of the source code is for functions that render queery results
    /// or render information to the end-user.
    ///
    fn render_enterprise_tactics_table(&self, results: &Vec<String>) {
        let mut _table = Table::new();
        _table.add_row(Row::new(vec![
            Cell::new("INDEX").style_spec("FW"),
            Cell::new("TACTICS").style_spec("FW"),
        ]));
        let _json: Vec<String> = serde_json::from_str(results[0].as_str()).expect("(?) Error: Unable To Deserialize Search Results By Tactics");
        for (_idx, _row) in _json.iter().enumerate() {
            _table.add_row(Row::new(vec![
                Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                Cell::new(_row.as_str()).style_spec("FW"),
            ]));
        }
        println!("{}", "\n\n");
        _table.printstd();
        println!("{}", "\n\n");           
    }
    fn render_enterprise_platforms_table(&self, results: &Vec<String>)
    {
        let mut _table = Table::new();
        _table.add_row(Row::new(vec![
            Cell::new("INDEX").style_spec("FW"),
            Cell::new("PLATFORMS").style_spec("FW"),
        ]));
        let _json: Vec<String> = serde_json::from_str(results[0].as_str()).expect("(?) Error: Unable To Deserialize Search Results By DataSources");
        for (_idx, _row) in _json.iter().enumerate() {
            _table.add_row(Row::new(vec![
                Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                Cell::new(_row.as_str()).style_spec("FW"),
            ]));
        }
        println!("{}", "\n\n");
        _table.printstd();
        println!("{}", "\n\n");
    } 
    fn render_enterprise_datasources_table(&self, results: &Vec<String>)
    {
        let mut _table = Table::new();
        _table.add_row(Row::new(vec![
            Cell::new("INDEX").style_spec("FW"),
            Cell::new("DATASOURCE").style_spec("FW"),
        ]));
        let _json: Vec<String> = serde_json::from_str(results[0].as_str()).expect("(?) Error: Unable To Deserialize Search Results By DataSources");
        for (_idx, _row) in _json.iter().enumerate() {
            _table.add_row(Row::new(vec![
                Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                Cell::new(_row.as_str()).style_spec("FW"),
            ]));
        }
        println!("{}", "\n\n");
        _table.printstd();
        println!("{}", "\n\n");
    } 
    fn render_enterprise_table(&self, results: &Vec<String>)
    {
        let mut _table = Table::new();
        _table.add_row(Row::new(vec![
            Cell::new("INDEX"),
            Cell::new("STATUS"),
            Cell::new("PLATFORMS"),
            Cell::new("TACTIC"),
            Cell::new("TID").style_spec("FG"),
            Cell::new("TECHNIQUE"),
            Cell::new("SUBTECHNIQUES"),
            Cell::new("DATA SOURCES")
        ]));
        // When we get to CSV Exports, put an if statement to build
        // the table cells without the `\n` terminators
        // because that will likely break CSV output
        let mut _sorted_index: Vec<(String, usize, usize)> = vec![];
        for (_ridx, _item) in results.iter().enumerate() {
            let _json: Vec<EnterpriseTechnique> = serde_json::from_str(results[_ridx].as_str()).expect("(?) Error: Render Table Deserialization");
            for (_jidx, _record) in _json.iter().enumerate() {
                _sorted_index.push((_record.tid.clone(), _jidx, _ridx));
            }
        }
        _sorted_index.sort();
        let mut _st = String::from("");
        let mut _idx: usize = 0;
        // Iterate through the sorted index
        // Pay attention to:
        //      `_jidx` => JSON index
        //      `_ridx` => Root index
        for (_technique, _jidx, _ridx) in _sorted_index {
            let _json: Vec<EnterpriseTechnique> = serde_json::from_str(results[_ridx].as_str()).expect("(?) Error: Render Table Deserialization");
            let _row = &_json[_jidx];
            if _row.has_subtechniques {
                _row.subtechniques.iter()
                    .map(|x| { _st.push_str(x.as_str()); _st.push_str("|") }).collect::<Vec<_>>();
            } else {
                _st.push_str("n_a");
            }
            // When a deprecated Technique is part of the result
            // then create a row for the deprecated technique
            if _row.is_deprecated {
                _table.add_row(
                    Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()),
                        Cell::new("Deprecated").style_spec("FY"),
                        Cell::new(_row.platform.replace("|", "\n").as_str()),
                        Cell::new(_row.tactic.as_str()),
                        Cell::new(_row.tid.as_str()).style_spec("FY"),
                        Cell::new(_row.technique.as_str()).style_spec("FW"),
                        Cell::new(_st.replace("|", "\n").as_str()).style_spec("FW"),
                        Cell::new(_row.datasources.replace("|", "\n").as_str())
                    ])
                ); 
            }
            // When a revoked Technique is part of the result
            // then create a row for the revoked technique
            else if _row.is_revoked {
                _table.add_row(
                    Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()),
                        Cell::new("Revoked").style_spec("FR"),
                        Cell::new(_row.platform.replace("|", "\n").as_str()),
                        Cell::new(_row.tactic.as_str()),
                        Cell::new(_row.tid.as_str()).style_spec("FR"),
                        Cell::new(_row.technique.as_str()).style_spec("FW"),
                        Cell::new(_st.replace("|", "\n").as_str()).style_spec("FW"),
                        Cell::new(_row.datasources.replace("|", "\n").as_str())
                    ])
                ); 
            } else {
                _table.add_row(
                    Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()),
                        Cell::new("Active"),
                        Cell::new(_row.platform.replace("|", "\n").as_str()),
                        Cell::new(_row.tactic.as_str()),
                        Cell::new(_row.tid.as_str()).style_spec("FG"),
                        Cell::new(_row.technique.as_str()).style_spec("FW"),
                        Cell::new(_st.replace("|", "\n").as_str()).style_spec("FW"),
                        Cell::new(_row.datasources.replace("|", "\n").as_str())
                    ])
                ); 
            }
            _st.clear();
            _idx += 1;            
        }
        println!("{}", "\n\n");
        _table.printstd();
        println!("{}", "\n\n");
    }
    fn render_enterprise_revoked_table(&self, results: &Vec<String>)
    {
        let mut _table = Table::new();
        _table.add_row(Row::new(vec![
            Cell::new("INDEX").style_spec("FW"),
            Cell::new("STATUS").style_spec("FR"),
            Cell::new("TID").style_spec("FR"),
            Cell::new("TECHNIQUE"),
        ]));
        let mut _idx: usize = 0;
        for _item in results.iter() {
            let mut _json: Vec<(&str, &str)> = serde_json::from_str(_item.as_str()).expect("(?) Error:  Render Table Deserialization For Revoked");
            _json.sort();
            for (_tid, _technique) in _json.iter() {
                _table.add_row(
                    Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()),
                        Cell::new("Revoked"),
                        Cell::new(_tid).style_spec("FR"),
                        Cell::new(_technique).style_spec("FW")
                    ])
                );
                _idx += 1;
            }
        }
        println!("{}", "\n\n");
        _table.printstd();
        println!("{}", "\n\n");
    }
    fn render_enterprise_deprecated_table(&self, results: &Vec<String>)
    {
        let mut _table = Table::new();
        _table.add_row(Row::new(vec![
            Cell::new("INDEX").style_spec("FW"),
            Cell::new("STATUS").style_spec("FY"),
            Cell::new("TID").style_spec("FY"),
            Cell::new("TECHNIQUE"),
        ]));
        let mut _idx: usize = 0;
        for _item in results.iter() {
            let mut _json: Vec<(&str, &str)> = serde_json::from_str(_item.as_str()).expect("(?) Error:  Render Table Deserialization For Revoked");
            _json.sort();
            for (_tid, _technique) in _json.iter() {
                _table.add_row(
                    Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()),
                        Cell::new("Deprecated"),
                        Cell::new(_tid).style_spec("FY"),
                        Cell::new(_technique).style_spec("FW")
                    ])
                );
                _idx += 1;
            }
        }
        println!("{}", "\n\n");
        _table.printstd();
        println!("{}", "\n\n");
    }
    fn render_enterprise_stats_xref_datasource_platforms(&self, results: &Vec<String>)
    {
        let mut _table = Table::new();
        _table.add_row(Row::new(vec![
            Cell::new("DATASOURCE").style_spec("FY"),
            Cell::new("AWS").style_spec("FW"),
            Cell::new("AZURE").style_spec("FW"),
            Cell::new("AZURE-AD").style_spec("FW"),
            Cell::new("GCP").style_spec("FW"),
            Cell::new("LINUX").style_spec("FW"),
            Cell::new("MACOS").style_spec("FW"),
            Cell::new("OFFICE-365").style_spec("FW"),
            Cell::new("SAAS").style_spec("FW"),
            Cell::new("WINDOWS").style_spec("FW"),
        ]));
        let _data: serde_json::Value = serde_json::from_str(results[0].as_str()).unwrap();
        let _data = _data.as_array().unwrap();
        let _data = _data[0].as_object().unwrap();

        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        for _datasource in _json.datasources.iter() {
            _table.add_row(Row::new(vec![
                Cell::new(_datasource.as_str()).style_spec("FW"),
                Cell::new(&_data[_datasource]["aws"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["azure"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["azure-ad"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["gcp"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["linux"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["macos"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["office-365"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["saas"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["windows"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
            ])); 
        }
        println!("{}", "\n\n");
        _table.printstd();
        println!("{}", "\n\n");
    }   
    fn render_enterprise_stats_xref_datasource_tactics(&self, results: &Vec<String>)
    {
        let mut _table = Table::new();
        _table.add_row(Row::new(vec![
            Cell::new("DATASOURCE").style_spec("FY"),
            Cell::new("INITIAL ACCESS").style_spec("FW"),
            Cell::new("EXECUTION").style_spec("FW"),
            Cell::new("PERSISTENCE").style_spec("FW"),
            Cell::new("PRIVILEGE ESCALATION").style_spec("FW"),
            Cell::new("DEFENSE EVASION").style_spec("FW"),
            Cell::new("CREDENTIAL ACCESS").style_spec("FW"),
            Cell::new("DISCOVERY").style_spec("FW"),
            Cell::new("LATERAL MOVEMENT").style_spec("FW"),
            Cell::new("COLLECTION").style_spec("FW"),
            Cell::new("COMMAND AND CONTROL").style_spec("FW"),
            Cell::new("EXFILTRATION").style_spec("FW"),
            Cell::new("IMPACT").style_spec("FW"),

        ]));
        let _data: serde_json::Value = serde_json::from_str(results[0].as_str()).unwrap();
        let _data = _data.as_array().unwrap();
        let _data = _data[0].as_object().unwrap();

        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        for _datasource in _json.datasources.iter() {
            _table.add_row(Row::new(vec![
                Cell::new(_datasource.as_str()).style_spec("FW"),
                Cell::new(&_data[_datasource]["initial-access"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["execution"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["persistence"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["privilege-escalation"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["defense-evasion"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["credential-access"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["discovery"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["lateral-movement"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["collection"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["command-and-control"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["exfiltration"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
                Cell::new(&_data[_datasource]["impact"].as_i64().unwrap().to_string().as_str()).style_spec("cFW"),
            ])); 
        }
        println!("{}", "\n\n");
        _table.printstd();
        println!("{}", "\n\n");
    }    
    fn render_enterprise_stats(&self, results: &Vec<String>)
    {
        let mut _table = Table::new();
        _table.add_row(Row::new(vec![
            Cell::new("CATEGORY"),
            Cell::new("COUNTS"),
            Cell::new("PERCENT %")
        ]));
        let _item = &results[0];
        let _json: EnterpriseMatrixStatistics = serde_json::from_str(_item.as_str()).expect("(?) Error:  Render Table Deserialization For Stats");
        // Uniques - Overview Section
        // Describes the uniq number of techniques
        // by platform only - no tactics are included
        _table.add_row(
            Row::new(vec![
                Cell::new("By Uniques").style_spec("FY"),
                Cell::new(""),
                Cell::new(""),
            ])
        );  
        _table.add_row(
            Row::new(vec![
                Cell::new("Active Techniques"),
                Cell::new(_json.count_active_uniq_techniques.to_string().as_str()),
                Cell::new(""),
            ])                                                                                                                                
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Active Subtechniques"),
                Cell::new(_json.count_active_uniq_subtechniques.to_string().as_str()),
                Cell::new(""),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Active Platforms"),
                Cell::new(_json.count_platforms.to_string().as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Active Tactics"),
                Cell::new(_json.count_tactics.to_string().as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Active Data Sources"),
                Cell::new(_json.count_datasources.to_string().as_str()),
                Cell::new(""),
            ])
        );
        // Totals - Overview Section
        // Describes the total number of techniques & subtechniques
        // by active, revoked - no tactics are included
        _table.add_empty_row();
        _table.add_row(
            Row::new(vec![
                Cell::new("By Totals").style_spec("FY"),
                Cell::new(""),
                Cell::new(""),
            ])
        );  
        _table.add_row(
            Row::new(vec![
                Cell::new("Deprecated Techniques"),
                Cell::new(_json.count_deprecated_techniques.to_string().as_str()),
                Cell::new(""),
            ])
        );  
        _table.add_row(
            Row::new(vec![
                Cell::new("Revoked Techniques"),
                Cell::new(_json.count_revoked_techniques.to_string().as_str()),
                Cell::new(""),
            ])
        );         
        _table.add_row(
            Row::new(vec![
                Cell::new("Active Techniques"),
                Cell::new(_json.count_active_total_techniques.to_string().as_str()),
                Cell::new(""),
        ]));
        _table.add_row(
            Row::new(vec![
                Cell::new("Active Subtechniques"),
                Cell::new(_json.count_active_total_subtechniques.to_string().as_str()),
                Cell::new(""),
        ]));
        // Totals - Techniques Section
        // Describes the total number of techniques
        // by platform only - no tactics are included
        _table.add_empty_row();        
        _table.add_row(
            Row::new(vec![
                Cell::new("Totals - Techniques By Platform").style_spec("FY"),
                Cell::new(""),
                Cell::new(""),
            ])
        );        
        _table.add_row(
            Row::new(vec![
                Cell::new("AWS"),
                Cell::new(_json.count_techniques_aws.to_string().as_str()),
                Cell::new(_json.percent_techniques_aws.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("AZURE"),
                Cell::new(_json.count_techniques_azure.to_string().as_str()),
                Cell::new(_json.percent_techniques_azure.as_str()),
            ])
        ); 
        _table.add_row(
            Row::new(vec![
                Cell::new("AZURE-AD"),
                Cell::new(_json.count_techniques_azure_ad.to_string().as_str()),
                Cell::new(_json.percent_techniques_azure_ad.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("GCP"),
                Cell::new(_json.count_techniques_gcp.to_string().as_str()),
                Cell::new(_json.percent_techniques_gcp.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("LINUX"),
                Cell::new(_json.count_techniques_linux.to_string().as_str()),
                Cell::new(_json.percent_techniques_linux.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("MAC-OS"),
                Cell::new(_json.count_techniques_macos.to_string().as_str()),
                Cell::new(_json.percent_techniques_macos.as_str())
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("OFFICE-365"),
                Cell::new(_json.count_techniques_office365.to_string().as_str()),
                Cell::new(_json.percent_techniques_office365.as_str())
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("SAAS"),
                Cell::new(_json.count_techniques_saas.to_string().as_str()),
                Cell::new(_json.percent_techniques_saas.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("WINDOWS"),
                Cell::new(_json.count_techniques_windows.to_string().as_str()),
                Cell::new(_json.percent_techniques_windows.as_str()),
            ])
        );                                                        
        // Totals - Subtechniques Section
        // Describes the total number of techniques
        // by platform only - no tactics are included
        _table.add_empty_row();
        _table.add_row(
            Row::new(vec![
                Cell::new("Total - Subtechniques By Platform").style_spec("FY"),
                Cell::new(""),
                Cell::new(""),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("AWS"),
                Cell::new(_json.count_subtechniques_aws.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_aws.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("AZURE"),
                Cell::new(_json.count_subtechniques_azure.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_azure.as_str()),
            ])
        ); 
        _table.add_row(
            Row::new(vec![
                Cell::new("AZURE-AD"),
                Cell::new(_json.count_subtechniques_azure_ad.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_azure_ad.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("GCP"),
                Cell::new(_json.count_subtechniques_gcp.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_gcp.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("LINUX"),
                Cell::new(_json.count_subtechniques_linux.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_linux.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("MAC-OS"),
                Cell::new(_json.count_subtechniques_macos.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_macos.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("OFFICE-365"),
                Cell::new(_json.count_subtechniques_office365.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_office365.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("SAAS"),
                Cell::new(_json.count_subtechniques_saas.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_saas.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("WINDOWS"),
                Cell::new(_json.count_subtechniques_windows.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_windows.as_str()),
            ])
        );
        // Tactics/KillChain Sections
        // Techniques By Killchain
        _table.add_empty_row();
        _table.add_row(
            Row::new(vec![
                Cell::new("Totals - Techniques By Tactic/KillChain").style_spec("FY"),
                Cell::new(""),
                Cell::new(""),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Initial Access"),
                Cell::new(_json.count_techniques_initial_access.to_string().as_str()),
                Cell::new(_json.percent_techniques_initial_access.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Execution"),
                Cell::new(_json.count_techniques_execution.to_string().as_str()),
                Cell::new(_json.percent_techniques_execution.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Persistence"),
                Cell::new(_json.count_techniques_persistence.to_string().as_str()),
                Cell::new(_json.percent_techniques_persistence.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Privilege Escalation"),
                Cell::new(_json.count_techniques_privilege_escalation.to_string().as_str()),
                Cell::new(_json.percent_techniques_privilege_escalation.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Defense Evasion"),
                Cell::new(_json.count_techniques_defense_evasion.to_string().as_str()),
                Cell::new(_json.percent_techniques_defense_evasion.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Credential Access"),
                Cell::new(_json.count_techniques_credential_access.to_string().as_str()),
                Cell::new(_json.percent_techniques_credential_access.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Discovery"),
                Cell::new(_json.count_techniques_discovery.to_string().as_str()),
                Cell::new(_json.percent_techniques_discovery.as_str()),
            ])
        );          
        _table.add_row(
            Row::new(vec![
                Cell::new("Lateral Movement"),
                Cell::new(_json.count_techniques_lateral_movement.to_string().as_str()),
                Cell::new(_json.percent_techniques_lateral_movement.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Collection"),
                Cell::new(_json.count_techniques_collection.to_string().as_str()),
                Cell::new(_json.percent_techniques_collection.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Command and Control"),
                Cell::new(_json.count_techniques_command_and_control.to_string().as_str()),
                Cell::new(_json.percent_techniques_command_and_control.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Exfiltration"),
                Cell::new(_json.count_techniques_exfiltration.to_string().as_str()),
                Cell::new(_json.percent_techniques_exfiltration.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Impact"),
                Cell::new(_json.count_techniques_impact.to_string().as_str()),
                Cell::new(_json.percent_techniques_impact.as_str()),
            ])
        );
        //
        // Subtechniques By Killchain
        _table.add_empty_row();
        _table.add_row(
            Row::new(vec![
                Cell::new("Totals - Subtechniques By Tactic/KillChain").style_spec("FY"),
                Cell::new(""),
                Cell::new(""),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Initial Access"),
                Cell::new(_json.count_subtechniques_initial_access.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_initial_access.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Execution"),
                Cell::new(_json.count_subtechniques_execution.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_execution.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Persistence"),
                Cell::new(_json.count_subtechniques_persistence.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_persistence.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Privilege Escalation"),
                Cell::new(_json.count_subtechniques_privilege_escalation.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_privilege_escalation.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Defense Evasion"),
                Cell::new(_json.count_subtechniques_defense_evasion.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_defense_evasion.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Credential Access"),
                Cell::new(_json.count_subtechniques_credential_access.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_credential_access.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Discovery"),
                Cell::new(_json.count_subtechniques_discovery.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_discovery.as_str()),
            ])
        );          
        _table.add_row(
            Row::new(vec![
                Cell::new("Lateral Movement"),
                Cell::new(_json.count_subtechniques_lateral_movement.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_lateral_movement.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Collection"),
                Cell::new(_json.count_subtechniques_collection.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_collection.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Command and Control"),
                Cell::new(_json.count_subtechniques_command_and_control.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_command_and_control.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Exfiltration"),
                Cell::new(_json.count_subtechniques_exfiltration.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_exfiltration.as_str()),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Impact"),
                Cell::new(_json.count_subtechniques_impact.to_string().as_str()),
                Cell::new(_json.percent_subtechniques_impact.as_str()),
            ])
        );                                                                                                                                                                                              
        // General Section
        // Used for placeholders if items (objects) not yet analyzed
        // These are TODOs
        _table.add_empty_row();
        _table.add_row(
            Row::new(vec![
                Cell::new("General - Pending Analysis").style_spec("FY"),
                Cell::new(""),
                Cell::new(""),
            ])
        );        
        _table.add_row(
            Row::new(vec![
                Cell::new("Records For Malware"),
                Cell::new(_json.count_malwares.to_string().as_str()),
                Cell::new(""),
            ])
        );
        _table.add_row(
            Row::new(vec![
                Cell::new("Records For Adversaries"),
                Cell::new(_json.count_adversaries.to_string().as_str()),
                Cell::new(""),
            ])
        ); 
        _table.add_row(
            Row::new(vec![
                Cell::new("Records For Tools"),
                Cell::new(_json.count_tools.to_string().as_str()),
                Cell::new(""),
            ])
        );
        println!("\n\n");        
        _table.printstd();
        println!("\n\n");    
    }
}