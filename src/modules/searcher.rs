use prettytable::{Cell, Row, Table};
use serde_json;

use std::collections::HashSet;

#[path = "./parser.rs"]
mod parser;
use parser::EnterpriseMatrixBreakdown;

#[path = "../structs/navigator.rs"]
mod navigator;
use navigator::{V2Navigator};

#[path = "../structs/enterprise.rs"]
mod enterprise;
use enterprise::{
    EnterpriseAdversary,
    EnterpriseMalware,
    EnterpriseMatrixStatistics,
    EnterpriseTool,
    EnterpriseTechnique,
    EnterpriseRevokedItem,
    EnterpriseRevokedTechniques,
    EnterpriseStatistics,
    EnterpriseStatistic
};

#[path = "../utils/fshandler.rs"]
mod fshandler;
use fshandler::FileHandler;

#[path = "../utils/regexes.rs"]
mod regexes;
use regexes::PatternManager;

pub struct EnterpriseMatrixSearcher {
    matrix: String,
    content: Vec<u8>,
}
impl EnterpriseMatrixSearcher {
    pub fn new(matrix_type: &str, navigator_path: &str) -> Self {
        let _input = matrix_type.to_lowercase();
        
        let mut _content: Vec<u8> = vec![];
        if _input.as_str() == "enterprise" && navigator_path == "None" {
            _content = FileHandler::load_baseline("baselines", "baseline-enterprise.json");
        }
        else if _input.as_str() == "enterprise-legacy" && navigator_path == "None" {
            _content = FileHandler::load_baseline("baselines", "baseline-enterprise-legacy.json");
        }
        else if _input.as_str() == "enterprise" && navigator_path != "None"
	  || _input.as_str() == "enterprise-legacy" && navigator_path != "None"
	{
            let _fp = FileHandler::open(navigator_path, "r");
            _content = _fp.read_as_vecbytes(_fp.size).unwrap();
        }
        EnterpriseMatrixSearcher {
            matrix: _input,
            content: _content,
        }
    }
    ///
    ///
    ///
    pub fn save_csv_export(&self, _wants_outfile: &str, _table: &Table) {
        let mut _outfile: &str = "";
        if _wants_outfile == "None" {
            _outfile = "mitre-assistant.csv";
        } else {
            _outfile = _wants_outfile;
        }
        let _fp = FileHandler::open(_outfile, "crw");
        _table
            .to_csv(_fp.handle)
            .expect("(?) Error: Unable to Save CSV Output File");
    }
    ///
    ///
    ///
    pub fn inspect_navigator(
        &mut self,
        _wants_export: &str,
        _wants_outfile: &str
    )
    {
        let _err = "(?) Error: Unable to Serialize Navigator";
        let _json: V2Navigator = serde_json::from_slice(&self.content[..]).expect(_err);

        let mut _content: Vec<u8> = vec![];
	    if self.matrix.as_str() == "enterprise" {
            _content = FileHandler::load_baseline("baselines", "baseline-enterprise.json");
        }
        else if self.matrix.as_str() == "enterprise-legacy" {
            _content = FileHandler::load_baseline("baselines", "baseline-enterprise-legacy.json");
        }
	    self.content = _content;
	    let _err = "(?) Error: Unable to Serialize Matrix Breakdown For Navigator";
	    let _baseline: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).expect(_err);
	    
	    let mut _results: Vec<crate::args::searcher::parser::enterprise::EnterpriseTechnique> = vec![];
	    
	    for _record in _json.techniques.iter() {
	        if _record.technique_id.contains(".") {
	            for _bst in _baseline.breakdown_subtechniques.platforms.iter() {
	                if _record.technique_id.to_lowercase().as_str() == _bst.tid.to_lowercase().as_str()
    	                && _record.tactic.to_lowercase().as_str() == _bst.tactic.to_lowercase().as_str()
			{
    	                	_results.push(_bst.clone());
			}
	            }
	        } else {
    	        for _bt in _baseline.breakdown_techniques.platforms.iter() {
    	            if _record.technique_id.to_lowercase().as_str() == _bt.tid.to_lowercase().as_str()
    	                && _record.tactic.to_lowercase().as_str() == _bt.tactic.to_lowercase().as_str() {
    	                _results.push(_bt.clone());
    	            }
    	        }
    	    }
	    }
	    _results.sort();
	    _results.dedup();
	    _results.sort();
	    let _results: String = serde_json::to_string_pretty(&_results).expect(_err);
	    let _data: Vec<String> = vec![_results];
	    self.render_techniques_details_table(&_data, _wants_export, _wants_outfile);
    }
    ///
    ///
    ///
    pub fn search(
        &self,
        search_term: &str,
        _wants_subtechniques: bool,
        _wants_export: &str,
        _wants_outfile: &str,
        _wants_correlation: bool
    ) {
        let search_term = search_term.trim_end();
        let mut _results: Vec<String> = vec![];
        let mut _valid: Vec<(&str, usize)> = vec![];
        let _st = search_term.to_lowercase();
        let _st = _st.as_str();
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        let _scanner = PatternManager::load_search_term_patterns();
        let _scanner_ad = PatternManager::load_search_adversaries(&_json.adversaries);
        //let _scanner_mw = PatternManager::load_search_malware(&_json.malware);
        let _scanner_mw = PatternManager::load_search_malware(&_json.malware, &_json.adversaries);
        let _scanner_pl = PatternManager::load_search_platforms(&_json.platforms);
        let _scanner_ta = PatternManager::load_search_tactics(&_json.tactics);
        let _scanner_to = PatternManager::load_search_tools(&_json.tools);
        let _scanner_ds = PatternManager::load_search_datasources(&_json.datasources, &_json.platforms);
        // Special Flags
        //      Easier to search this way without flooding the user with parameters
        //      These flags are commonly placed in both the query and render functions
        //
        let mut _matches_many: Vec<usize> = vec![];
        //
        //
        let mut _wants_summary: bool = false; // Signals that it wants a "stats:{object} query"
        let mut _wants_stats: bool = false; // Returns The Stats Key
        let mut _wants_nosub: bool = false; // Returns Techniques That Don't Have Subtechniques
        let mut _wants_revoked: bool = false; // Returns Techniques Revoked By Mitre
        let mut _wants_tactics: bool = false; // Returns The Tactics Key
        let mut _wants_platforms: bool = false; // Returns The Platforms Key
        let mut _wants_deprecated: bool = false; // Returns The Deprecated Techniques
        let mut _wants_datasources: bool = false; // Returns The Data Sources Key
        let mut _wants_adversary: bool = false;
        let mut _wants_malware: bool = false;
        let mut _wants_tool: bool = false;
        let mut _wants_all_techniques: bool = false;
        let mut _wants_all_subtechniques: bool = false;
        let mut _wants_all_adversaries: bool = false;
        let mut _wants_all_malware: bool = false;
        let mut _wants_all_tools: bool = false;
        let mut _wants_xref_datasources_tactics: bool = false; // Returns The Stats Count XREF of Datasoources By Tactic
        let mut _wants_xref_datasources_platforms: bool = false; // Return The Stats Count XREF of Datasources By Platform

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
        else if _st == "stats:datasources" {
            _valid.push((_st, 8usize));
            _wants_datasources = true;
            _wants_summary = true;
        }
        else if _st == "stats:platforms" {
            _valid.push((_st, 9usize));
            _wants_platforms = true;
            _wants_summary = true;
        }
        else if _st == "nodatasources" {
            _valid.push((_st, 10usize));
        }
        else if _st == "stats:tactics" {
            _valid.push((_st, 11usize));
            _wants_tactics = true;
        }
        else if _st == "deprecated" {
            _valid.push((_st, 12usize));
            _wants_deprecated = true;
        }
        else if _st == "stats:techniques" {
            _matches_many = _scanner_ta.pattern.matches(_st).into_iter().collect();
            _valid.push((_st, 13usize));
            _wants_all_techniques = true;
            _wants_summary = true;
        }
        else if _st == "stats:subtechniques" {
            _matches_many = _scanner_ta.pattern.matches(_st).into_iter().collect();
            _valid.push((_st, 14usize));
            _wants_all_subtechniques = true;
            _wants_summary = true;
        }
        else if _st == "stats:adversaries" {
            _matches_many = _scanner_ta.pattern.matches(_st).into_iter().collect();
            _valid.push((_st, 15usize));
            _wants_all_adversaries = true;
            _wants_summary = true;
        }
        else if _st == "stats:malware" {
            _matches_many = _scanner_ta.pattern.matches(_st).into_iter().collect();
            _valid.push((_st, 16usize));
            _wants_all_malware = true;
            _wants_summary = true;
        }
        else if _st == "stats:tools" {
            _matches_many = _scanner_ta.pattern.matches(_st).into_iter().collect();
            _valid.push((_st, 17usize));
            _wants_all_tools = true;
            _wants_summary = true;
        }
        else if _scanner_ta.pattern.is_match(_st) {
            _matches_many = _scanner_ta.pattern.matches(_st).into_iter().collect();
            _valid.push((_st, 44usize));
        }
        else if _scanner_ds.pattern.is_match(_st) {
            _matches_many = _scanner_ds.pattern.matches(_st).into_iter().collect();
            _valid.push((_st, 37usize));
        }
        else if _scanner_pl.pattern.is_match(_st) && !_st.contains("-") {
            _matches_many = _scanner_pl.pattern.matches(_st).into_iter().collect();
            _valid.push((_st, 45usize));
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
        // Adversaries
        else if _scanner_ad.pattern.is_match(_st) {
            _matches_many = _scanner_ad.pattern.matches(_st).into_iter().collect();
            _valid.push((_st, 38usize));
            _wants_adversary = true;
        }
        // Malware
        else if _scanner_mw.pattern.is_match(_st) {
            _matches_many = _scanner_mw.pattern.matches(_st).into_iter().collect();
            _valid.push((_st, 39usize));
            _wants_malware = true;
        }
        // Tools
        else if _scanner_to.pattern.is_match(_st) {
            _matches_many = _scanner_to.pattern.matches(_st).into_iter().collect();
            _valid.push((_st, 40usize));
            _wants_tool = true;
        }
        else if _st == "adversaries" {
            _valid.push((_st, 41usize));
            _wants_all_adversaries = true;
        }
        else if _st == "malware" {
            _valid.push((_st, 42usize));
            _wants_all_malware = true;
        }
        else if _st == "tools" {
            _valid.push((_st, 43usize));
            _wants_all_tools = true;
        }
        else if !_st.contains(",") {
            if _scanner.pattern.is_match(_st) {
                let _idx: Vec<usize> = _scanner.pattern.matches(_st).into_iter().collect();
                _valid.push((_st, _idx[0])); // Search Term 0usize
            }
        }
        else if _st.contains(",") {
            let mut _terms: Vec<&str> = _st.split(',').collect();
            _terms.sort();
            _terms.dedup();
            _valid = _terms
                .iter()
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
                    _results.push(self.search_by_id(_term, _wants_subtechniques));
                }
                else if _pattern == &1usize {
                    _results.push(self.search_by_subtechnique_id(_term));
                }
                else if _pattern == &2usize {
                    _results.push(self.search_by_name(_term));
                }
                else if _pattern == &3usize {
                    _results.push(self.search_revoked());
                }
                else if _pattern == &4usize {
                    _results.push(self.search_stats());
                }
                else if _pattern == &5usize {
                    _results.push(self.search_by_no_subtechniques());
                }
                else if _pattern == &6usize {
                    _results.push(self.search_all_techniques());
                }
                else if _pattern == &7usize {
                    _results.push(self.search_all_subtechniques());
                }
                else if _pattern == &8usize {
                    _results.push(self.search_stats_by_datasources());
                }
                else if _pattern == &9usize {
                    _results.push(self.search_stats_by_platforms());
                }
                else if _pattern == &10usize {
                    _results.push(self.search_by_no_datasources());
                }
                else if _pattern == &11usize {
                    _results.push(self.search_stats_by_tactics());
                }
                else if _pattern == &12usize {
                    _results.push(self.search_by_deprecated());
                }
                else if _pattern == &13usize { 
                    _results.push(self.search_stats_by_techniques());
                }
                else if _pattern == &14usize { 
                    _results.push(self.search_stats_by_subtechniques());
                }
                else if _pattern == &15usize { 
                    _results.push(self.search_stats_by_adversaries());
                }
                else if _pattern == &16usize {
                    _results.push(self.search_stats_by_malware()); 
                }
                else if _pattern == &17usize {
                    _results.push(self.search_stats_by_tools()); 
                }
                else if _pattern == &34usize {
                    _results.push(self.search_all_overlapped());
                }
                else if _pattern == &35usize {
                    _results.push(self.search_stats_datasources_and_platforms());
                }
                else if _pattern == &36usize {
                    _results.push(self.search_stats_datasources_and_tactics());
                }
                else if _pattern == &37usize {
                    _results.push(self.search_by_datasource(_term, _wants_subtechniques, _matches_many.clone()));
                }
                else if _pattern == &38usize {
                    _results.push(self.search_by_adversary(_term, _matches_many.clone(), _wants_correlation));
                }
                else if _pattern == &39usize {
                    _results.push(self.search_by_malware(_term, _matches_many.clone(), _wants_correlation));
                }
                else if _pattern == &40usize {
                    _results.push(self.search_by_tool(_term, _matches_many.clone()));
                }
                else if _pattern == &41usize {
                    _results.push(self.search_all_adversaries());
                }
                else if _pattern == &42usize {
                    _results.push(self.search_all_malware());
                }
                else if _pattern == &43usize {
                    _results.push(self.search_all_tools());
                }
                else if _pattern == &44usize {
                    _results.push(self.search_by_tactic(_term, _wants_subtechniques, _matches_many.clone()));
                }
                else if _pattern == &45usize {
                    _results.push(self.search_by_platform(_term, _wants_subtechniques, _matches_many.clone()));
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
            if _wants_all_techniques {
                if _wants_summary {
                    self.render_techniques_table(&_results, _wants_export, _wants_outfile);
                } else {
                    self.render_techniques_details_table(&_results, _wants_export, _wants_outfile)
                }
            }
            else if _wants_all_subtechniques {
                if _wants_summary {
                    self.render_subtechniques_table(&_results, _wants_export, _wants_outfile);
                }
            }
            else if _wants_all_adversaries {
                if _wants_summary {
                    self.render_adversaries_table(&_results, _wants_export, _wants_outfile);
                } else {
                    self.render_adversaries_profile_table(&_results, _wants_export, _wants_outfile, _wants_correlation);
                }
            }
            else if _wants_adversary {
                self.render_adversaries_profile_table(&_results, _wants_export, _wants_outfile, _wants_correlation);
            }
            else if _wants_all_malware {
                if _wants_summary {
                    self.render_malware_table(&_results, _wants_export, _wants_outfile);
                } else {
                    self.render_malware_profile_table(&_results, _wants_export, _wants_outfile, _wants_correlation);
                }
            }
            else if _wants_malware {
                self.render_malware_profile_table(&_results, _wants_export, _wants_outfile, _wants_correlation);
            }
            else if _wants_all_tools {
                if _wants_summary {
                    self.render_tools_table(&_results, _wants_export, _wants_outfile);
                } else {
                    self.render_tools_profile_table(&_results, _wants_export, _wants_outfile);
                }
            }
            else if _wants_tool {
                self.render_tools_profile_table(&_results, _wants_export, _wants_outfile);
            }
            else if _wants_revoked {
                self.render_revoked_table(&_results, _wants_export, _wants_outfile);
            }
            else if _wants_stats {
                self.render_stats(&_results, _wants_export, _wants_outfile);
            }
            else if _wants_datasources {
                self.render_datasources_table(&_results, _wants_export, _wants_outfile);
            }
            else if _wants_platforms {
                self.render_platforms_table(&_results, _wants_export, _wants_outfile);
            }
            else if _wants_tactics {
                self.render_tactics_table(&_results, _wants_export, _wants_outfile);
            }
            else if _wants_deprecated {
                self.render_deprecated_table(&_results, _wants_export, _wants_outfile);
            }
            else if _wants_xref_datasources_platforms {
                self.render_stats_xref_datasource_platforms(
                    &_results,
                    _wants_export,
                    _wants_outfile,
                );
            }
            else if _wants_xref_datasources_tactics {
                self.render_stats_xref_datasource_tactics(
                    &_results,
                    _wants_export,
                    _wants_outfile,
                );
            } else {
                self.render_techniques_details_table(&_results, _wants_export, _wants_outfile);
            }
        } else {
            println!(
                r#"[ "Results": {}, "SearchTerm": {} ]"#,
                "None Found", search_term
            );
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
    ///
    fn correlate_malware(
        &self,
        target: &str,
        _results: &mut Vec<crate::args::searcher::parser::enterprise::EnterpriseTechnique>
    )
    {
        let _err = format!(
            "(?) Error: Unable To Deserialize Correlation String of All Techniques by: {}",
            target
        );
        let mut _temp_holder: Vec<(String, String, String, String)> = vec![];
        let mut _temp_results: Vec<crate::args::searcher::parser::enterprise::EnterpriseTechnique> = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..])
                                                          .expect(_err.as_str());
        // Obtain the techniques listed by the malware
        for _item in _json.breakdown_malware.iter() {
            if _item.name.to_lowercase().as_str() == target {
                for _x in _item.profile.techniques.items.iter() {
                    for _technique in _json.breakdown_techniques.platforms.iter() {
                        if _technique.tid.as_str() == _x {
                            let mut _et = _technique.clone();
                            _et.correlation_malware = _item.name.clone();
                            _temp_results.push(_et);
                        }
                    }
                }
                for _x in _item.profile.subtechniques.items.iter() {
                    for _subtechnique in _json.breakdown_subtechniques.platforms.iter() {
                        if _subtechnique.tid == _x.as_str() {
                            let mut _et = _subtechnique.clone();
                            _et.correlation_malware = _item.name.clone();
                            _temp_results.push(_et);
                        }
                    }
                }
            }
        }
        _temp_results.sort();
        _temp_results.dedup();
        _temp_results.sort();
        //println!("{:#?}", _temp_results);
        for _result in _temp_results {
            _results.push(_result);
        }
    }    
    ///
    ///
    ///
    fn correlate_adversary(
        &self,
        target: &str,
        _results: &mut Vec<crate::args::searcher::parser::enterprise::EnterpriseTechnique>
    )
    {
        let _err = format!(
            "(?) Error: Unable To Deserialize Correlation String of All Techniques by: {}",
            target
        );
        let mut _temp_holder: Vec<(String, String, String, String)> = vec![];
        let mut _temp_results: Vec<crate::args::searcher::parser::enterprise::EnterpriseTechnique> = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..])
                                                          .expect(_err.as_str());
        let mut _group_id = String::from("none");
        for _item in _json.breakdown_adversaries.iter() {
            if _item.name.to_lowercase().as_str() == target {
                for _x in _item.profile.techniques.items.iter() {
                    for _technique in _json.breakdown_techniques.platforms.iter() {
                        if _technique.tid.as_str() == _x {
                            let mut _et = _technique.clone();
                            _et.correlation_adversary = _item.name.clone();
                            
                            // Add GID To ET Here
                           
                            if _group_id.as_str() == "none" {
                                _group_id = _item.group_id.clone();
                            }
                            _et.correlation_gid = _group_id.clone();
                            for _malware in &_json.breakdown_malware {
                                for _mt in _malware.profile.adversaries.items.iter() {
                                    if _mt.as_str() == target {
                                        for _behavior in _malware.profile.techniques.items.iter() {
                                            if _technique.tid.as_str() == _behavior.as_str() {
                                                _et.correlation_malware = _malware.name.clone();
                                                
                                                // Add MID to ET Here
                                                _et.correlation_mid = _malware.malware_id.clone();
                                            }
                                        }
                                    }
                                }
                            }
                            _temp_results.push(_et);
                        }
                    }
                }
                for _x in _item.profile.subtechniques.items.iter() {
                    for _subtechnique in _json.breakdown_subtechniques.platforms.iter() {
                        if _subtechnique.tid.as_str() == _x {
                            let mut _et = _subtechnique.clone();
                            _et.correlation_adversary = _item.name.clone();
                            
                            // Add GID To ET Here
                            _et.correlation_gid = _group_id.clone();
                            //_et.correlation_gid = _item.group_id.clone();
                            //
                            
                            for _malware in &_json.breakdown_malware {
                                for _mt in _malware.profile.adversaries.items.iter() {
                                    if _mt.as_str() == target {
                                        for _behavior in _malware.profile.techniques.items.iter() {
                                            if _subtechnique.tid.as_str() == _behavior.as_str() {
                                                _et.correlation_malware = _malware.name.clone();
                                                // Add MID to ET Here
                                                _et.correlation_mid = _malware.malware_id.clone();
                                            }
                                        }
                                    }
                                }
                            }
                            _temp_results.push(_et);
                        }
                    }
                }
            }
        }
        // Now go get the techniques & subtechniques from Every Malware
        // Where the actor is cited
        for _malware in &_json.breakdown_malware {
            for _ma in _malware.profile.adversaries.items.iter() {
                if target == _ma.as_str() {
                    // Techniques
                    for _mt in _malware.profile.techniques.items.iter() {
                        for _technique in _json.breakdown_techniques.platforms.iter() {
                            if _technique.tid.as_str() == _mt.as_str() {
                                let mut _et = _technique.clone();
                                _et.correlation_adversary = target.to_string();
                                _et.correlation_malware = _malware.name.clone();
                                _et.correlation_gid = _group_id.clone();
                                _et.correlation_mid = _malware.malware_id.clone();
                                _temp_results.push(_et);
                            }
                        }
                    }
                    // Subtechniques
                    for _mt in _malware.profile.subtechniques.items.iter() {
                        for _subtechnique in _json.breakdown_subtechniques.platforms.iter() {
                            if _subtechnique.tid.as_str() == _mt.as_str() {
                                let mut _et = _subtechnique.clone();
                                _et.correlation_adversary = target.to_string();
                                _et.correlation_malware = _malware.name.clone();
                                _et.correlation_gid = _group_id.clone();
                                _et.correlation_mid = _malware.malware_id.clone();
                                _temp_results.push(_et);
                            }
                        }
                    }
                }
            }
        }
        // Now go get the techniques & subtechniques from Every `Tool`
        // Where the actor is cited
        for _tool in &_json.breakdown_tools {
            for _ma in _tool.profile.adversaries.items.iter() {
                if target == _ma.as_str() {
                    for _mt in _tool.profile.techniques.items.iter() {
                        for _technique in _json.breakdown_techniques.platforms.iter() {
                            if _technique.tid.as_str() == _mt.as_str() {
                                let mut _et = _technique.clone();
                                _et.correlation_adversary = target.to_string();
                                _et.correlation_tool= _tool.name.clone();
                                _et.correlation_gid = _group_id.clone();
                                _et.correlation_mid = _tool.tool_id.clone();
                                _temp_results.push(_et);
                            }
                        }
                    }
                    for _mt in _tool.profile.subtechniques.items.iter() {
                        for _subtechnique in _json.breakdown_subtechniques.platforms.iter() {
                            if _subtechnique.tid.as_str() == _mt.as_str() {
                                let mut _et = _subtechnique.clone();
                                _et.correlation_adversary = target.to_string();
                                _et.correlation_tool = _tool.name.clone();
                                _et.correlation_gid = _group_id.clone();
                                _et.correlation_mid = _tool.tool_id.clone();
                                _temp_results.push(_et);
                            }
                        }
                    }                    
                }
            }
        }
        _temp_results.sort();
        _temp_results.dedup();
        _temp_results.sort();
        // Iterate through the techniques attributed
        // to the adversary
        let mut _count: usize = 0;
        let mut _tools_strings: Vec<String> = vec![];
        let mut _malware_strings: Vec<String> = vec![];
        let mut _duplicates: Vec<_> = vec![];
        let mut _malware_string: String = "none".to_string();
        let mut _tool_string: String = "none".to_string();
        let mut _copy_results = _temp_results.clone();
        for (_idx,_result) in _temp_results.iter().enumerate() {
            let mut _target_result = _result.clone();
            for _copy in _copy_results.iter() {
                if _result.tid.as_str() == _copy.tid.as_str()
                    && _result.tactic.as_str() == _copy.tactic.as_str()
                    && _result.correlation_malware.as_str() != _copy.correlation_malware.as_str()
                {
                    if &_malware_strings.len() == &0usize {
                        _malware_strings.push(_result.correlation_malware.clone());
                        _malware_strings.push(_copy.correlation_malware.clone());
                    } else if &_malware_strings.len() > &1usize && !&_malware_strings.contains(&_copy.correlation_malware) {
                        _malware_strings.push(_copy.correlation_malware.clone());
                    }
                    _count += 1;
                }
                if _result.tid.as_str() == _copy.tid.as_str()
                    && _result.tactic.as_str() == _copy.tactic.as_str()
                    && _result.correlation_tool.as_str() != _copy.correlation_tool.as_str()
                {
                    if &_tools_strings.len() == &0usize {
                        _tools_strings.push(_result.correlation_tool.clone());
                        _tools_strings.push(_copy.correlation_tool.clone());
                    } else if &_tools_strings.len() > &1usize && !&_tools_strings.contains(&_copy.correlation_tool) {
                        _tools_strings.push(_copy.correlation_tool.clone());
                    }
                    _count += 1;
                }
            }
            if _count == 0 {
                _results.push(_target_result.clone());
            }
            else if _count > 1 {
                _malware_strings.sort();
                _malware_strings.dedup();
                _malware_strings.sort();
                _tools_strings.sort();
                _tools_strings.dedup();
                _tools_strings.sort();
                for _string in &_malware_strings {
                    let _string = _string.replace("none","");
                    if _string.as_str() != "none" || _string.as_str() != ""
                    {
                        _malware_string.push_str(format!("{}|", _string.as_str()).as_str());
                    }
                }
                for _string in &_tools_strings {
                    let _string = _string.replace("none","");
                    if _string.as_str() != "none" || _string.as_str() != ""
                    {
                        let _string = _string.replace("none","");
                        _tool_string.push_str(format!("{}|", _string.as_str()).as_str());
                    }
                }
                _target_result.correlation_malware = _malware_string.clone();
                _target_result.correlation_tool = _tool_string.clone();
                _duplicates.push(_target_result.clone());
            }
            _malware_string.clear();
            _tool_string.clear();
            _malware_strings.clear();
            _tools_strings.clear();
            _count = 0;
        }
        // Finalize Results
        _duplicates.sort();
        _duplicates.dedup();
        _duplicates.sort();
        for _item in _temp_results.iter() {
            for _duplicate in _duplicates.iter() {
                if _item.tid.as_str() == _duplicate.tid.as_str()
                    && _item.tactic.as_str() == _duplicate.tactic.as_str()
                {
                    //if _item.correlation_malware.as_str() == "none"
                    _results.push(_duplicate.clone());
                }
            }
        }
        _results.sort();
        _results.dedup();
        _results.sort();
    }
    fn search_by_adversary(
        &self, 
        adversary: &str,
        many: Vec<usize>,
        _wants_correlation: bool
    ) -> String {
        let mut _results_correlation: Vec<crate::args::searcher::parser::enterprise::EnterpriseTechnique> = vec![];
        let mut _results_adversaries: Vec<_> = vec![];
        let adversary = adversary.to_lowercase();
        let adversary = adversary.as_str();
        let _err = format!(
            "(?) Error: Unable To Deserialize String of All Techniques by Adversary: {}",
            adversary
        );
        let _json: EnterpriseMatrixBreakdown =
            serde_json::from_slice(&self.content[..]).expect(_err.as_str());
        if many.len() == 1 {
            if _wants_correlation {
                self.correlate_adversary(adversary, &mut _results_correlation);
            } else {
                for _item in _json.breakdown_adversaries.iter() {
                    if _item.name.to_lowercase().as_str() == adversary {
                        _results_adversaries.push(_item);
                    } else {
                        let _terms: Vec<_> = _item.aliases.split(‘|’).collect();
                        //if _item.aliases.contains(adversary) {
                        for _term in _terms {
                            if _term.as_str() == adversary {
                                _results_adversaries.push(_item);
                            }
                        }
                    }
                }
            }
        } else if many.len() > 1 {
            if adversary.contains(",") {
                let _terms: Vec<_> = adversary.split(',').collect();
                for _term in _terms {
                    for _item in _json.breakdown_adversaries.iter() {
                        if _item.name.to_lowercase().as_str() == _term
                        {
                            if _wants_correlation {
                                self.correlate_adversary(_term, &mut _results_correlation);
                            } else {
                                _results_adversaries.push(_item);
                            }
                        } else {
                            let _aliases: Vec<_> = _item.aliases.split(‘|’).collect();
                            for _alias in _aliases{
                                if _alias == _term {
                                    _results_adversaries.push(_item);
                                }
                            }
                        }
                    }
                }
            }
        }
        let _err = format!(
            "(?) Error: Unable To Convert String of All Techniques by Adversary: {}",
            adversary
        );

        if _wants_correlation {
            serde_json::to_string(&_results_correlation).expect(_err.as_str())
        } else {
            serde_json::to_string(&_results_adversaries).expect(_err.as_str())
        }
    }
    ///
    ///
    ///
    ///
    fn search_by_malware(
        &self,
        malware: &str,
        many: Vec<usize>,
        _wants_correlation: bool
    ) -> String {
        let mut _results_correlation: Vec<crate::args::searcher::parser::enterprise::EnterpriseTechnique> = vec![];
        let mut _results = vec![];
        let malware = malware.to_lowercase();
        let malware = malware.replace("_","");
        let malware = malware.as_str();
        let _err = format!(
            "(?) Error: Unable To Deserialize String of All Techniques by malware: {}",
            malware
        );
        if malware.contains(":") {
            println!("{}", malware);
        }
        let _json: EnterpriseMatrixBreakdown =
            serde_json::from_slice(&self.content[..]).expect(_err.as_str());
        if many.len() == 1 {
            if _wants_correlation {
                self.correlate_malware(malware, &mut _results_correlation);
            } else {
                for _item in _json.breakdown_malware.iter() {
                    if _item.name.to_lowercase().as_str() == malware {
                        _results.push(_item);
                    }
                }
            }
        } else if many.len() > 1 {
            if malware.contains(",") {
                let _terms: Vec<_> = malware.split(',').collect();
                for _term in _terms {
                    if _wants_correlation  {
                        self.correlate_malware(_term, &mut _results_correlation);
                    } else {
                        for _item in _json.breakdown_malware.iter() {
                            if _item.name.to_lowercase().as_str() == _term {
                                _results.push(_item);
                            }
                        }
                    }
                }
            }
        }
        let _err = format!(
            "(?) Error: Unable To Convert String of All Techniques by malware: {}",
            malware
        );
        if _wants_correlation {
            serde_json::to_string(&_results_correlation).expect(_err.as_str())
        } else {
            serde_json::to_string(&_results).expect(_err.as_str())
        }
    }
    ///
    /// 
    /// 
    /// 
    fn search_by_tool(&self, tool: &str, many: Vec<usize>) -> String {
        let mut _results = vec![];
        let tool = tool.to_lowercase();
        let tool = tool.as_str();
        let _err = format!(
            "(?) Error: Unable To Deserialize String of All Techniques by tool: {}",
            tool
        );
        //println!("{}", tool);
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..])
                                                                           .expect(_err.as_str());
        if many.len() == 1 {
            for _item in _json.breakdown_tools.iter() {
                if _item.name.to_lowercase().as_str() == tool {
                    _results.push(_item);
                }
            }
        } else if many.len() > 1 {
            if tool.contains(",") {
                let _terms: Vec<_> = tool.split(',').collect();
                for _term in _terms {
                    for _item in _json.breakdown_tools.iter() {
                        if _item.name.to_lowercase().as_str() == _term {
                            _results.push(_item);
                        }
                    }
                }
            }
        }
        //println!("{}", serde_json::to_string_pretty(&_results).unwrap());
        let _err = format!(
            "(?) Error: Unable To Convert String of All Techniques by tool: {}",
            tool
        );
        serde_json::to_string(&_results).expect(_err.as_str())
    }
    ///
    ///
    ///
    ///
    fn search_by_datasource(
        &self, datasource: &str,
        _wants_subtechniques: bool,
        many: Vec<usize>
    ) -> String
    {
        let mut _results = vec![];
        let _err = format!(
            "(?) Error: Unable To Deserialize String of All Techniques by Datasource: {}",
            datasource
        );
        let _json: EnterpriseMatrixBreakdown =
            serde_json::from_slice(&self.content[..])
                        .expect(_err.as_str());
        let _datasource = datasource.to_lowercase().replace(" ", "");
        let _datasource = _datasource.as_str();
        // Check for Shorthand Terms
        // Transform to the explicit datasource
        /*

        */
        let mut _iterable: &Vec<_>;
        if _wants_subtechniques {
            _iterable = &_json.breakdown_subtechniques.platforms;
        } else {
            _iterable = &_json.breakdown_techniques.platforms;
        }
        if many.len() == 1 {
            for _item in _iterable {
                let _search_term = self.get_datasource_shorthand(_datasource);
                if _item.datasources.contains(&_search_term) {
                    let mut _et = EnterpriseTechnique::new();
                    _et.tid = _item.tid.clone();
                    _et.platform = _item.platform.clone();
                    _et.technique = _item.technique.clone();
                    _et.tactic = _item.tactic.clone();
                    _et.datasources = _search_term;
                    _et.has_subtechniques = _item.has_subtechniques.clone();
                    _et.subtechniques = _item.subtechniques.clone();
                    _results.push(_et);
                }
            }
        } else if many.len() > 1 {
            if _datasource.contains(",") {
                let _terms: Vec<String> = _datasource.split(',')
                                                     .map(|x| self.get_datasource_shorthand(x))
                                                     .collect();
                //println!("TERMS: {:#?}", _terms);
                let mut _match_count: usize = 0;
                let mut _temp_string: String = String::from("");
                for _item in _iterable {
                    for _term in _terms.iter() {
                        if _item.datasources.contains(_term.as_str()) { 
                            _match_count += 1;
                            if _match_count > 1 {
                                let _s = format!("|{}", _term);
                                _temp_string.push_str(_s.as_str());
                            } else if _match_count == 1 {
                                let _s = format!("{}", _term);
                                _temp_string.push_str(_s.as_str());
                            }
                        }
                    }
                    if _match_count >= 1 {
                        //_temp_string.pop();
                        let mut _et = EnterpriseTechnique::new();
                        _et.tid = _item.tid.clone();
                        _et.platform = _item.platform.clone();
                        _et.technique = _item.technique.clone();
                        _et.datasources = _temp_string.clone();
                        _et.tactic = _item.tactic.clone();
                        _et.has_subtechniques = _item.has_subtechniques.clone();
                        _et.subtechniques = _item.subtechniques.clone();
                        _results.push(_et);
                    }
                    _match_count = 0;       // Reset
                    _temp_string.clear();    
                }
            }
        }
        let _err = format!(
            "(?) Error: Unable To Convert String of All Techniques by Datasource: {}",
            datasource
        );
        serde_json::to_string(&_results).expect(_err.as_str())
    }
    ///
    ///
    ///
    fn get_datasource_shorthand(&self, _datasource: &str) -> String
    {
        let _datasource = match _datasource {
            "av" => "anti-virus",
            "dns" => "dns-records",
            "drivers" => "kernel-drivers",
            "eventlogs" | "evtx" => "windows-event-logs",
            "netflow" => "netflow-enclave-netflow",
            "nids" => "network-intrusion-detection-system",
            "pcap" => "packet-capture",
            "registry" => "windows-registry",
            "sandboxing" => "detonation-chamber",
            "waf" => "web-application-firewall-logs",
            "wer" => "windows-error-reporting",
            _ => _datasource
        };
        String::from(_datasource)
    }
    ///
    ///
    ///
    ///
    fn search_by_platform(
        &self,
        platform: &str,
        _wants_subtechniques: bool,
        many: Vec<usize>
    ) -> String 
    {
        let mut _results = vec![];
        let _err = format!(
            "(?) Error: Unable To Deserialize String of All Techniques by Platform: {}",
            platform
        );
        let _json: EnterpriseMatrixBreakdown =
            serde_json::from_slice(&self.content[..]).expect(_err.as_str());
            let _platform = platform.to_lowercase();
            let _platform = _platform.as_str();
            let mut _iterable: &Vec<_>;
            if _wants_subtechniques {
                _iterable = &_json.breakdown_subtechniques.platforms;
            } else {
                _iterable = &_json.breakdown_techniques.platforms;
            }
            if many.len() == 1 {
                for _item in _iterable {
                    if _item.platform.contains(_platform) {
                        let mut _et = EnterpriseTechnique::new();
                        _et.id = _item.id.clone();
                        _et.platform = _platform.to_string();
                        _et.tid = _item.tid.clone();
                        _et.technique = _item.technique.clone();
                        _et.tactic = _item.tactic.clone();
                        _et.datasources = _item.datasources.to_string();
                        _et.has_subtechniques = _item.has_subtechniques.clone();
                        _et.subtechniques = _item.subtechniques.clone();
                        _results.push(_et);
                    }
                }
            } else if many.len() > 1 {
                if _platform.contains(",") {
                    let _terms: Vec<&str> = _platform.split(',').collect();
                    let mut _match_count: usize = 0;
                    let mut _temp_string: String = String::from("");
                    for _item in _iterable {
                        for _term in _terms.iter() {
                            if _item.platform.contains(_term) { 
                                _match_count += 1;
                                if _match_count > 1 {
                                    let _s = format!("|{}", _term);
                                    _temp_string.push_str(_s.as_str());
                                } else if _match_count == 1 {
                                    let _s = format!("{}", _term);
                                    _temp_string.push_str(_s.as_str());
                                }
                            }
                        }
                        if _match_count >= 1 {
                            //_temp_string.pop();
                            let mut _et = EnterpriseTechnique::new();
                            _et.id = _item.id.clone();
                            _et.tid = _item.tid.clone();
                            _et.platform = _temp_string.clone();
                            _et.technique = _item.technique.clone();
                            _et.datasources = _item.datasources.clone();
                            _et.tactic = _item.tactic.clone();
                            _et.has_subtechniques = _item.has_subtechniques.clone();
                            _et.subtechniques = _item.subtechniques.clone();
                            _results.push(_et);
                        }
                        _match_count = 0;       // Reset
                        _temp_string.clear();    
                    }
                }
            }
        serde_json::to_string(&_results).expect(_err.as_str())
    }
    /// # Query By Tactics
    ///
    /// Allows the user to get all techniques by specifying a tactic.
    ///
    /// ```ignore
    /// self.search_by_tactic("initial-access", false)
    /// ```
    fn search_by_tactic(
        &self,
        tactic: &str,
        _wants_subtechniques: bool,
        many: Vec<usize>
    ) -> String 
    {
        let mut _results = vec![];
        let _err = format!(
            "(?) Error: Unable To Deserialize String of All Techniques by Tactic: {}",
            tactic
        );
        let _json: EnterpriseMatrixBreakdown =
            serde_json::from_slice(&self.content[..]).expect(_err.as_str());
            let _tactic = tactic.to_lowercase();
            let _tactic = _tactic.as_str();
            let mut _iterable: &Vec<_>;
            if _wants_subtechniques {
                _iterable = &_json.breakdown_subtechniques.platforms;
            } else {
                _iterable = &_json.breakdown_techniques.platforms;
            }
            if many.len() == 1 {
                for _item in _iterable {
                    if _item.tactic.contains(_tactic) {
                        let mut _et = EnterpriseTechnique::new();
                        _et.platform = _item.platform.clone();
                        _et.tid = _item.tid.clone();
                        _et.technique = _item.technique.clone();
                        _et.tactic = _item.tactic.clone();
                        _et.datasources = _item.datasources.to_string();
                        _et.has_subtechniques = _item.has_subtechniques.clone();
                        _et.subtechniques = _item.subtechniques.clone();
                        _results.push(_et);
                    }
                }
            } else if many.len() > 1 {
                if _tactic.contains(",") {
                    let _terms: Vec<&str> = _tactic.split(',').collect();
                    for _term in _terms {
                        for _item in _iterable {
                            if _item.tactic.contains(_term) {
                                let mut _et = EnterpriseTechnique::new();
                                _et.platform = _item.platform.clone();
                                _et.tid = _item.tid.clone();
                                _et.technique = _item.technique.clone();
                                _et.tactic = _item.tactic.clone();
                                _et.datasources = _item.datasources.to_string();
                                _et.has_subtechniques = _item.has_subtechniques.clone();
                                _et.subtechniques = _item.subtechniques.clone();
                                _results.push(_et);
                            }
                        }
                    }
                }
            }
        serde_json::to_string(&_results).expect(_err.as_str())
    }
    /// # Query By Deprecated Techniques
    ///
    /// Allows the user to get all deprecated techniques.
    ///
    /// ```ignore
    /// self.deprecated();
    /// ```
    fn search_by_deprecated(&self) -> String {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..])
            .expect("(?) Error: Unable to Deserialize All Deprecated Techniques");
        for _item in _json.deprecated_techniques {
            _results.push(_item)
        }
        _results.sort();
        serde_json::to_string(&_results)
            .expect("(?) Error: Unable To Deserialize String Of All Deprecated Techniques")
    }
    fn search_all_malware(&self) -> String {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..])
            .expect("(?) Error: Unable to Deserialize All Malware");
        for _item in _json.malware {
            for _malware in _json.breakdown_malware.iter() {
                if _malware.aliases.contains(&_item) {
                    _results.push(_malware);
                } else {
                    _results.push(_malware);
                }
            }
        }
        _results.sort();
        _results.dedup();
        _results.sort();
        serde_json::to_string(&_results).expect("(?) Error: Unable To Deserialize All Malware")
    }
    fn search_all_tools(&self) -> String {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..])
            .expect("(?) Error: Unable to Deserialize All Malware");
        for _item in _json.tools {
            for _tool in _json.breakdown_tools.iter() {
                if _tool.aliases.contains(&_item) {
                    _results.push(_tool);
                } else {
                    _results.push(_tool);
                }
            }
        }
        _results.sort();
        _results.dedup();
        _results.sort();
        serde_json::to_string(&_results).expect("(?) Error: Unable To Deserialize All Malware")
    }
    fn search_all_adversaries(&self) -> String {
        let mut _results = vec![];
        let _err = "(?) Error: Unable to Deserialize All Adversaries";
        let _json: EnterpriseMatrixBreakdown =
            serde_json::from_slice(&self.content[..]).expect(_err);
        for _item in _json.adversaries {
            for _adversary in _json.breakdown_adversaries.iter() {
                if _adversary.aliases.contains(&_item) {
                    _results.push(_adversary);
                } else {
                    _results.push(_adversary);
                }
            }
        }
        _results.sort();
        _results.dedup();
        _results.sort();
        serde_json::to_string(&_results).expect("(?) Error: Unable To Deserialize All Adversaries")
    }
    /// # Query To Get All Active Tactics
    ///
    /// Allows the user to get all of the Active Tactics.
    ///
    /// ```ignore
    /// self.search_all_tactics();
    /// ```
    /*
    fn search_all_tactics(&self) -> String {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..])
            .expect("(?) Error: Unable to Deserialize All Tactics");
        for _item in _json.tactics {
            _results.push(_item)
        }
        _results.sort();
        serde_json::to_string(&_results).expect("(?) Error: Unable To Deserialize All Tactics")
    }
    */
    /// # Query To Get All Overlapped Techniques
    ///
    /// Allows the user to get all of the techniques considered to have an overlap.
    /// Overlap occurs when a technique is spread across more than one tactic/killchain.
    ///
    /// ```ignore
    /// self.search_all_overlapped();
    /// ```
    fn search_all_overlapped(&self) -> String {
        let mut _results = vec![];
        let mut _targets = HashSet::new();
        let _err = "(?) Error: Unable to Deserialize All Overlapped Techniques";
        let _json: EnterpriseMatrixBreakdown =
            serde_json::from_slice(&self.content[..]).expect(_err);
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
            let mut _et = EnterpriseTechnique::new();
            for _technique in _json.breakdown_techniques.platforms.iter() {
                if _technique.tid.as_str() == _target.as_str() {
                    _results.push(_technique);
                }
            }
        }
        let _err = "(?) Error: Unable to Convert All Overlapped Techniques";
        serde_json::to_string(&_results).expect(_err)
    }
    /// # Query All Active Techniques
    ///
    /// Allows the user to get all of the Active Techniques.
    ///
    /// ```ignore
    /// self.search_all_techniques();
    /// ```
    fn search_all_techniques(&self) -> String {
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        serde_json::to_string(&_json.breakdown_techniques.platforms)
            .expect("(?) Error: Unable To Deserialize All Techniques")
    }
    /// # Query All Active Subtechniques
    ///
    /// Allows the user to get all of the Active Subtechniques.
    ///
    /// ```ignore
    /// self.search_all_subtechniques();
    /// ```
    fn search_all_subtechniques(&self) -> String {
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        serde_json::to_string(&_json.breakdown_subtechniques.platforms)
            .expect("(?) Error: Unable To Deserialize All Techniques")
    }
    /// # Query All Platforms
    ///
    /// Allows the user to get all the platforms.
    ///
    /// ```ignore
    /// self.search_all_platforms();
    /// ```
    /*
    fn search_all_platforms(&self) -> String {
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        serde_json::to_string(&_json.platforms)
            .expect("(?) Error: Unable To Deserialize All Platforms")
    }
    */
    /// # Query All Datasources
    ///
    /// Allows the user to get alll the datasources.
    ///
    /// ```ignore
    /// self.search_all_datasources();
    /// ```
    fn search_all_datasources(&self) -> String {
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        serde_json::to_string(&_json.datasources)
            .expect("(?) Error: Unable To Deserialize All Datasources")
    }
    /// # Query All Techniques That Do Not have Datasources
    ///
    /// Allows the user to get all the techniques and subtechniques
    /// that do not have assigned datasources.
    ///
    /// ```ignore
    /// self.search_by_no_datasources();
    /// ```
    fn search_by_no_datasources(&self) -> String {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..])
            .expect("(?) Error: Unable to Deserialize By No Datasources");
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
    /// # Query Techniques By Name
    ///
    /// Allows the user to query techniques by their name, works as `partial match`
    ///
    /// ```ignore
    /// self.search_by_name();
    /// ```
    ///
    ///
    ///
    fn search_by_name(&self, technique_name: &str) -> String {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        for _item in _json.breakdown_techniques.platforms.iter() {
            if _item.technique.to_lowercase().as_str() == technique_name.to_lowercase().as_str() {
                _results.push(_item);
            } else if _item
                .technique
                .to_lowercase()
                .as_str()
                .contains(technique_name.to_lowercase().as_str())
            {
                _results.push(_item);
            }
        }
        // Now Search Subtechniques
        for _item in _json.breakdown_subtechniques.platforms.iter() {
            if _item.technique.to_lowercase().as_str() == technique_name.to_lowercase().as_str() {
                _results.push(_item);
            } else if _item
                .technique
                .to_lowercase()
                .as_str()
                .contains(technique_name.to_lowercase().as_str())
            {
                _results.push(_item);
            }
        }
        serde_json::to_string_pretty(&_results)
            .expect("(?) Error:  Unable To Deserialize Search Results By Technique Name")
    }
    /// # Query By Technique ID
    ///
    /// Allows a user to query techniques by their ID - e.g., T1234.
    ///
    /// When the user passes a boolean set to `true` as the second parameter
    /// the query will also look for subtechniques that match the ID provided.
    ///
    /// ```ignore
    /// self.search_by_id("t1021", false);
    /// ```
    fn search_by_id(&self, technique_id: &str, _wants_subtechniques: bool) -> String {
        let mut _results = vec![];
        //let mut _temp = HashSet::new();
        let _json: EnterpriseMatrixBreakdown =
            serde_json::from_slice(&self.content[..]).expect("HERE");
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
        _results.sort();
        _results.dedup();
        _results.sort();
        if _results.len() == 0usize {
            // If no results then we want to search for a two conditions
            //      1. When the user wants subtechniques, then get them
            //      2. Or, when there are revoked techniques, let's add these
            //          to save time for users writing more queries
            //      3. Or, when there are deprecated techniques,get them too
            if _wants_subtechniques {
                for _subtechnique in _json.breakdown_subtechniques.platforms.iter() {
                    if _subtechnique
                        .tid
                        .contains(technique_id.to_uppercase().as_str())
                    {
                        _results.push(_subtechnique);
                    }
                }
            }
            // Check & Get From Revoked Techniques
            let mut _results = vec![];
            for _revoked in _json.enterprise_revoked_techniques.items.iter() {
                if _revoked.eid.to_lowercase().as_str() == technique_id.to_lowercase().as_str() {
                    let mut _et = EnterpriseTechnique::new();
                    _et.tid = _revoked.eid.clone();
                    _et.technique = _revoked.name.clone();
                    _et.is_revoked = true;
                    _results.push(_et);
                }
            }
            // Check & Get From Deprecated Techniques
            for _deprecated in _json.deprecated_techniques.iter() {
                if _deprecated.0.to_lowercase().as_str() == technique_id.to_lowercase().as_str() {
                    let mut _et = EnterpriseTechnique::new();
                    _et.tid = _deprecated.0.clone();
                    _et.technique = _deprecated.1.clone();
                    _et.is_deprecated = true;
                    _results.push(_et);
                }
            }
            _results.sort();
            _results.dedup();
            _results.sort();
            serde_json::to_string_pretty(&_results)
                .expect("(?) Error:  Unable To Deserialize Search Results By Revoked Technique ID")
        } else {
            _results.sort();
            _results.dedup();
            _results.sort();
            serde_json::to_string_pretty(&_results)
                .expect("(?) Error:  Unable To Deserialize Search Results By Technique ID")
        }
    }
    /// # Query By Subtechnique ID
    ///
    /// Allows a user to query by the ID of a subtechnique - e.g., T1021.001.
    ///
    /// ```ignore
    /// self.search_by_subtechnique_id("t1021.001");
    /// ```
    fn search_by_subtechnique_id(&self, technique_id: &str) -> String {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        for _item in _json.breakdown_subtechniques.platforms.iter() {
            if _item.tid.to_lowercase().as_str() == technique_id.to_lowercase().as_str() {
                _results.push(_item);
            }
        }
        _results.sort();
        _results.dedup();
        _results.sort();
        serde_json::to_string_pretty(&_results)
            .expect("(?) Error:  Unable To Deserialize Search Results By Subtechnique ID")
    }
    /// # Query By Revoked Techniques
    ///
    /// Allows a user to query for the techniques in a `revoked` status.
    ///
    /// ```ignore
    /// self.search_revoked();
    /// ```
    fn search_revoked(&self) -> String
    {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        for _item in _json.enterprise_revoked_techniques.items.iter() {
            _results.push(_item);
        }
        serde_json::to_string_pretty(&_results)
            .expect("(?) Error:  Unable To Deserialize Search Results By Revoked Techniques")
    }
    /// # Query To Get A Stats Overview
    ///
    /// Allows a user to get a summary of the matrix with `total` and `unique` counts
    /// of specific data elements.
    ///
    /// ```ignore
    /// self.search_stats();
    fn search_stats_by_subtechniques(&self) -> String
    {
        let mut _results: Vec<EnterpriseStatistic> = vec![];
        let mut _tracker: HashSet<String> = HashSet::new();
        let mut _tracker_tactics: Vec<(String, String)> = vec![];
        let mut _uniq_targets: HashSet<crate::args::searcher::parser::enterprise::EnterpriseTechnique> = HashSet::new();
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        // Load totals for percentages
        let _total_techniques: usize = _json.stats.count_active_total_techniques;
        let _total_subtechniques: usize = _json.stats.count_active_total_subtechniques;
        // Load tuple
        for _technique in _json.breakdown_subtechniques.platforms.iter() {
            _tracker_tactics.push((_technique.tid.clone(), _technique.tactic.clone()));
        }
        for _item in _json.uniques_subtechniques.iter() {
            if !_tracker.contains(_item.as_str()) {
                {
                    for _technique in _json.breakdown_subtechniques.platforms.iter() {
                        if _technique.tid.as_str() == _item {
                            let mut _et = _technique.clone();
                            _et.tactic = "stripped".to_string();
                            _uniq_targets.insert(_et);
                        }
                    }
                }
                _tracker.insert(_item.clone());
            }
        }
        
        for _technique in _uniq_targets.iter() {
            // # of Tactics
            let mut _stat: EnterpriseStatistic = EnterpriseStatistic::new();
            for _killchain in _tracker_tactics.iter() {
                if _technique.tid.as_str() == _killchain.0.as_str() {
                    _stat.count_tactics += 1;
                }
            }
            // # of Platforms
            if _technique.platform.contains("|") {
                let _x: Vec<&str> = _technique.platform.split("|").collect();
                for _item in _x {
                    _stat.count_platforms += 1;
                }
            } else {
                _stat.count_platforms += 1;
            }
            // # of Datasources
            if _technique.datasources.as_str() != "none" {
                let _x: Vec<&str> = _technique.datasources.as_str().split("|").collect();
                for _item in _x {
                    _stat.count_datasources += 1;
                }
            }
            // # of Adversaries
            for _adversary in _json.breakdown_adversaries.iter() {
                if _adversary.profile.subtechniques.items.len() > 0 {
                    for _at in _adversary.profile.subtechniques.items.iter() {
                        if _at.as_str() == _technique.tid.as_str() {
                            _stat.count_adversaries += 1;
                        }
                    }
                }
            }
            // # of Malware
            for _malware in _json.breakdown_malware.iter() {
                if _malware.profile.subtechniques.items.len() > 0 {
                    for _mt in _malware.profile.subtechniques.items.iter() {
                        if _mt.as_str() == _technique.tid.as_str() {
                            _stat.count_malware += 1;
                        }
                    }
                }
            }
            // # of Tools
            for _tool in _json.breakdown_tools.iter() {
                if _tool.profile.techniques.items.len() > 0 {
                    for _tt in _tool.profile.subtechniques.items.iter() {
                        if _tt.as_str() == _technique.tid.as_str() {
                            _stat.count_tools += 1;
                        }
                    }
                }
            }
            _stat.item = _technique.tid.clone();
            _stat.meta = _technique.technique.clone();
            let _tp = (_stat.count_techniques as f64 /_total_techniques as f64) *100f64;
            let _sp = (_stat.count_subtechniques as f64 /_total_subtechniques as f64) *100f64;
            _stat.percent_techniques = format!("{}{}", _tp.ceil().to_string(), "%");
            _stat.percent_subtechniques = format!("{}{}", _sp.ceil().to_string(), "%");
            _stat.from_total_techniques = _total_techniques as usize;
            _stat.from_total_subtechniques = _total_subtechniques as usize;
            _results.push(_stat);
        }
        _results.sort();
        // Rollup the Statistic
        let _err: &str = "(?) Error: Unable To Deserialize Statistics For Techniques";
        //println!("{:#?}", _results);
        serde_json::to_string(&_results).expect(_err)
    }
    ///
    ///
    ///
    fn search_stats_by_techniques(&self) -> String
    {
        let mut _results: Vec<EnterpriseStatistic> = vec![];
        let mut _tracker: HashSet<String> = HashSet::new();
        let mut _tracker_tactics: Vec<(String, String)> = vec![];
        let mut _uniq_targets: HashSet<crate::args::searcher::parser::enterprise::EnterpriseTechnique> = HashSet::new();
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        // Load totals for percentages
        let _total_techniques: usize = _json.stats.count_active_total_techniques;
        let _total_subtechniques: usize = _json.stats.count_active_total_subtechniques;
        // Load tuple
        for _technique in _json.breakdown_techniques.platforms.iter() {
            _tracker_tactics.push((_technique.tid.clone(), _technique.tactic.clone()));
        }
        for _item in _json.uniques_techniques.iter() {
            if !_tracker.contains(_item.as_str()) {
                {
                    for _technique in _json.breakdown_techniques.platforms.iter() {
                        if _technique.tid.as_str() == _item {
                            let mut _et = _technique.clone();
                            _et.tactic = "stripped".to_string();
                            _uniq_targets.insert(_et);
                        }
                    }
                }
                _tracker.insert(_item.clone());
            }
        }
        
        for _technique in _uniq_targets.iter() {
            // # of Tactics
            let mut _stat: EnterpriseStatistic = EnterpriseStatistic::new();
            for _killchain in _tracker_tactics.iter() {
                if _technique.tid.as_str() == _killchain.0.as_str() {
                    _stat.count_tactics += 1;
                }
            }
            // # of Platforms
            if _technique.platform.contains("|") {
                let _x: Vec<&str> = _technique.platform.split("|").collect();
                for _item in _x {
                    _stat.count_platforms += 1;
                }
            } else {
                _stat.count_platforms += 1;
            }
            // # of Subtechniques
            if _technique.has_subtechniques {
                _stat.count_subtechniques = _technique.subtechniques.len();
            }
            // # of Datasources
            if _technique.datasources.as_str() != "none" {
                let _x: Vec<&str> = _technique.datasources.as_str().split("|").collect();
                for _item in _x {
                    _stat.count_datasources += 1;
                }
            }
            // # of Adversaries
            for _adversary in _json.breakdown_adversaries.iter() {
                if _adversary.profile.techniques.items.len() > 0 {
                    for _at in _adversary.profile.techniques.items.iter() {
                        if _at.as_str() == _technique.tid.as_str() {
                            _stat.count_adversaries += 1;
                        }
                    }
                }
            }
            // # of Malware
            for _malware in _json.breakdown_malware.iter() {
                if _malware.profile.techniques.items.len() > 0 {
                    for _mt in _malware.profile.techniques.items.iter() {
                        if _mt.as_str() == _technique.tid.as_str() {
                            _stat.count_malware += 1;
                        }
                    }
                }
            }
            // # of Tools
            for _tool in _json.breakdown_tools.iter() {
                if _tool.profile.techniques.items.len() > 0 {
                    for _tt in _tool.profile.techniques.items.iter() {
                        if _tt.as_str() == _technique.tid.as_str() {
                            _stat.count_tools += 1;
                        }
                    }
                }
            }
            _stat.item = _technique.tid.clone();
            _stat.meta = _technique.technique.clone();
            let _tp = (_stat.count_techniques as f64 /_total_techniques as f64) *100f64;
            let _sp = (_stat.count_subtechniques as f64 /_total_subtechniques as f64) *100f64;
            _stat.percent_techniques = format!("{}{}", _tp.ceil().to_string(), "%");
            _stat.percent_subtechniques = format!("{}{}", _sp.ceil().to_string(), "%");
            _stat.from_total_techniques = _total_techniques as usize;
            _stat.from_total_subtechniques = _total_subtechniques as usize;
            _results.push(_stat);
        }
        _results.sort();

        // Rollup the Statistic
        let _err: &str = "(?) Error: Unable To Deserialize Statistics For Techniques";
        //println!("{:#?}", _results);
        serde_json::to_string(&_results).expect(_err)
    }      
    ///
    ///
    fn search_stats_by_tactics(&self) -> String
    {
        let mut _results: Vec<EnterpriseStatistic> = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        // Load totals for percentages
        let _total_techniques: usize = _json.stats.count_active_total_techniques;
        let _total_subtechniques: usize = _json.stats.count_active_total_subtechniques;
        for _item in _json.tactics.iter() {
            let mut _stat: EnterpriseStatistic = EnterpriseStatistic::new();
            for _technique in _json.breakdown_techniques.platforms.iter() {
                if _technique.tactic.to_lowercase().as_str() == _item {
                //if _technique.tactic.contains(_item) {
                    _stat.count_techniques += 1;
                }
            }
            for _subtechnique in _json.breakdown_subtechniques.platforms.iter() {
                //if _subtechnique.tactic.contains(_item) {
                if _subtechnique.tactic.to_lowercase().as_str() == _item {
                    _stat.count_subtechniques += 1;
                }
            }
            _stat.item = _item.clone();
            let _tp = (_stat.count_techniques as f64 /_total_techniques as f64) *100f64;
            let _sp = (_stat.count_subtechniques as f64 /_total_subtechniques as f64) *100f64;
            _stat.from_total_techniques = _total_techniques;
            _stat.from_total_subtechniques = _total_subtechniques;
            _stat.percent_techniques = format!("{}{}", _tp.ceil().to_string(), "%");
            _stat.percent_subtechniques = format!("{}{}", _sp.ceil().to_string(), "%");
            _stat.from_total_techniques = _total_techniques as usize;
            _stat.from_total_subtechniques = _total_subtechniques as usize;
            _results.push(_stat);
        }
        let _err: &str = "(?) Error: Unable To Deserialize Statistics For Datasources";
        //println!("{:#?}", _results);
        serde_json::to_string(&_results).expect(_err)
    }    
    ///
    ///
    fn search_stats_by_platforms(&self) -> String
    {
        let mut _results: Vec<EnterpriseStatistic> = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        // Load totals for percentages
        let _total_techniques: f64 = _json.stats.count_active_total_techniques as f64;
        let _total_subtechniques: f64 = _json.stats.count_active_total_subtechniques as f64;
        for _item in _json.platforms.iter() {
            let mut _stat: EnterpriseStatistic = EnterpriseStatistic::new();
            for _technique in _json.breakdown_techniques.platforms.iter() {
                if _technique.platform.contains(_item) {
                    _stat.count_techniques += 1;
                }
            }
            for _subtechnique in _json.breakdown_subtechniques.platforms.iter() {
                if _subtechnique.platform.contains(_item) {
                    _stat.count_subtechniques += 1;
                }
            }
            _stat.item = _item.clone();
            let _tp = (_stat.count_techniques as f64 /_total_techniques) *100f64;
            let _sp = (_stat.count_subtechniques as f64 /_total_subtechniques) *100f64;
            _stat.percent_techniques = format!("{}{}", _tp.ceil().to_string(), "%");
            _stat.percent_subtechniques = format!("{}{}", _sp.ceil().to_string(), "%");
            _stat.from_total_techniques = _total_techniques as usize;
            _stat.from_total_subtechniques = _total_subtechniques as usize;
            _results.push(_stat);
        }
        let _err: &str = "(?) Error: Unable To Deserialize Statistics For Datasources";
        //println!("{:#?}", _results);
        serde_json::to_string(&_results).expect(_err)
    }     
    ///
    ///
    fn search_stats_by_tools(&self) -> String
    {
        let mut _results: Vec<EnterpriseStatistic> = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        // Load totals for percentages
        let _total_techniques: f64 = _json.stats.count_active_total_techniques as f64;
        let _total_subtechniques: f64 = _json.stats.count_active_total_subtechniques as f64;
        for _adversary in _json.breakdown_tools.iter() {
            let mut _stat: EnterpriseStatistic = EnterpriseStatistic::new();

            if self.matrix.as_str() == "enterprise-legacy" {
                _stat.is_legacy_matrix = true;
            }
            _stat.item = _adversary.name.clone();
            _stat.count_adversaries = _adversary.profile.adversaries.count;
            _stat.count_tactics = _adversary.profile.tactics.count;
            _stat.count_techniques = _adversary.profile.techniques.count;
            _stat.count_subtechniques = _adversary.profile.subtechniques.count;
            let _tp = (_stat.count_techniques as f64 /_total_techniques) *100f64;
            let _sp = (_stat.count_subtechniques as f64 /_total_subtechniques) *100f64;
            _stat.percent_techniques = format!("{}{}", _tp.ceil().to_string(), "%");
            _stat.percent_subtechniques = format!("{}{}", _sp.ceil().to_string(), "%");
            _stat.from_total_techniques = _total_techniques as usize;
            _stat.from_total_subtechniques = _total_subtechniques as usize;
            _results.push(_stat);
        }
        let _err: &str = "(?) Error: Unable To Deserialize Statistics For Datasources";
        //println!("{:#?}", _results);
        serde_json::to_string(&_results).expect(_err)
    }    
    ///
    ///
    fn search_stats_by_malware(&self) -> String
    {
        let mut _results: Vec<EnterpriseStatistic> = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        // Load totals for percentages
        let _total_techniques: f64 = _json.stats.count_active_total_techniques as f64;
        let _total_subtechniques: f64 = _json.stats.count_active_total_subtechniques as f64;
        for _adversary in _json.breakdown_malware.iter() {
            let mut _stat: EnterpriseStatistic = EnterpriseStatistic::new();

            if self.matrix.as_str() == "enterprise-legacy" {
                _stat.is_legacy_matrix = true;
            }
            _stat.item = _adversary.name.clone();
            _stat.count_adversaries = _adversary.profile.adversaries.count;
            _stat.count_tactics = _adversary.profile.tactics.count;
            _stat.count_techniques = _adversary.profile.techniques.count;
            _stat.count_subtechniques = _adversary.profile.subtechniques.count;
            let _tp = (_stat.count_techniques as f64 /_total_techniques) *100f64;
            let _sp = (_stat.count_subtechniques as f64 /_total_subtechniques) *100f64;
            _stat.percent_techniques = format!("{}{}", _tp.ceil().to_string(), "%");
            _stat.percent_subtechniques = format!("{}{}", _sp.ceil().to_string(), "%");
            _stat.from_total_techniques = _total_techniques as usize;
            _stat.from_total_subtechniques = _total_subtechniques as usize;
            _results.push(_stat);
        }
        let _err: &str = "(?) Error: Unable To Deserialize Statistics For Malware";
        //println!("{:#?}", _results);
        serde_json::to_string(&_results).expect(_err)
    }    
    ///
    ///
    ///
    fn search_stats_by_adversaries(&self) -> String
    {
        let mut _results: Vec<EnterpriseStatistic> = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        // Load totals for percentages
        let _total_techniques: f64 = _json.stats.count_active_total_techniques as f64;
        let _total_subtechniques: f64 = _json.stats.count_active_total_subtechniques as f64;
        for _adversary in _json.breakdown_adversaries.iter() {
            let mut _stat: EnterpriseStatistic = EnterpriseStatistic::new();
            _stat.item = _adversary.name.clone();
            _stat.count_tools = _adversary.profile.tools.count;
            _stat.count_malware = _adversary.profile.malware.count;
            _stat.count_tactics = _adversary.profile.tactics.count;
            _stat.count_techniques = _adversary.profile.techniques.count;
            _stat.count_subtechniques = _adversary.profile.subtechniques.count;
            if self.matrix.as_str() == "enterprise-legacy" {
                _stat.is_legacy_matrix = true;
            }
            let _tp = (_stat.count_techniques as f64 /_total_techniques) *100f64;
            let _sp = (_stat.count_subtechniques as f64 /_total_subtechniques) *100f64;
            _stat.percent_techniques = format!("{}{}", _tp.ceil().to_string(), "%");
            _stat.percent_subtechniques = format!("{}{}", _sp.ceil().to_string(), "%");
            _stat.from_total_techniques = _total_techniques as usize;
            _stat.from_total_subtechniques = _total_subtechniques as usize;
            _results.push(_stat);
        }
        let _err: &str = "(?) Error: Unable To Deserialize Statistics For Datasources";
        //println!("{:#?}", _results);
        serde_json::to_string(&_results).expect(_err)
    }
    fn search_stats(&self) -> String {
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        serde_json::to_string_pretty(&_json.stats)
            .expect("(?) Error:  Unable To Deserialize Search Results By Enterprise Stats")
    }    
    ///
    ///
    ///
    fn search_stats_by_datasources(&self) -> String
    {
        let mut _results: Vec<EnterpriseStatistic> = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        let _total_techniques: f64 = _json.stats.count_active_total_techniques as f64;
        let _total_subtechniques: f64 = _json.stats.count_active_total_subtechniques as f64;
        for _datasource in _json.datasources.iter() {
            let mut _stat: EnterpriseStatistic = EnterpriseStatistic::new();
            for _technique in _json.breakdown_techniques.platforms.iter() {
                if _technique.datasources.contains(_datasource.as_str()) {
                    _stat.count_techniques += 1;
                }
            }
            if self.matrix.as_str() != "enterprise-legacy" {
                for _subtechnique in _json.breakdown_subtechniques.platforms.iter() {
                    if _subtechnique.datasources.contains(_datasource.as_str()) {
                        _stat.count_subtechniques += 1;
                    }
                }
            }
            if self.matrix.as_str() == "enterprise-legacy" {
                _stat.is_legacy_matrix = true;
            }
            _stat.item = _datasource.clone();
            let _tp = (_stat.count_techniques as f64 /_total_techniques) *100f64;
            let _sp = (_stat.count_subtechniques as f64 /_total_subtechniques) *100f64;
            _stat.percent_techniques = format!("{}{}", _tp.ceil().to_string(), "%");
            _stat.percent_subtechniques = format!("{}{}", _sp.ceil().to_string(), "%");
            _stat.from_total_techniques = _total_techniques as usize;
            _stat.from_total_subtechniques = _total_subtechniques as usize;
            _results.push(_stat);
        }
        let _err: &str = "(?) Error: Unable To Deserialize Statistics For Datasources";
        //println!("{:#?}", _results);
        serde_json::to_string(&_results).expect(_err)
    }
    /// # Query For All Subtechniques
    ///
    /// Allows the userto obtain a complete list of active subtechniques.
    ///
    /// ```ignore
    /// self.search_by_no_subtechniques();
    /// ```
    fn search_by_no_subtechniques(&self) -> String {
        let mut _results = vec![];
        let _json: EnterpriseMatrixBreakdown = serde_json::from_slice(&self.content[..]).unwrap();
        for _item in _json.breakdown_techniques.platforms.iter() {
            if !_item.has_subtechniques {
                _results.push(_item);
            }
        }
        serde_json::to_string_pretty(&_results)
            .expect("(?) Error: Unable To Deserialize Search Results By HAS_NO_SUBTECHNIQUES")
    }
    /// # Query Via XREF Dataources to Platforms
    ///
    /// Allows a user to obtain a 2d array of `counts` by active techniques.
    /// The array is aligned to the datasources in the "`Y`" axis, and the
    /// the platforms on the "`X`" axis.
    ///
    /// ```ignore
    /// self.search_stats_datatsources_and_platforms();
    /// ```
    fn search_stats_datasources_and_platforms(&self) -> String {
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
                        && _technique.platform.contains(_platform)
                    {
                        let _value = _os.get_mut(_platform.as_str()).unwrap();
                        *_value += 1usize;
                    }
                }
            }
            _ds.insert(_datasource.clone(), _os);
        }
        _results.push(_ds);
        serde_json::to_string_pretty(&_results)
            .expect("(?) Error: Unable To Deserialize STATS For Datasources & Platforms")
    }
    /// # Query Via XREF Dataources to Tactics
    ///
    /// Allows a user to obtain a 2d array of `counts` by active techniques.
    /// The array is aligned to the datasources in the "`Y`" axis, and the
    /// the tactics on the "`X`" axis.
    ///
    /// ```ignore
    /// self.search_stats_datatsources_and_platforms();
    /// ```    
    fn search_stats_datasources_and_tactics(&self) -> String {
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
                        && _technique.tactic.contains(_tactic)
                    {
                        let _value = _tactics.get_mut(_tactic.as_str()).unwrap();
                        *_value += 1usize;
                    }
                }
            }
            _ds.insert(_datasource.clone(), _tactics);
        }
        _results.push(_ds);
        serde_json::to_string_pretty(&_results)
            .expect("(?) Error: Unable To Deserialize STATS For Datasources & Tactics")
    }
    /// # **Rendering Functions**
    /// This section of the source code is for functions that render queery results
    /// or render information to the end-user.
    ///
    fn render_subtechniques_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        
        let mut _table = Table::new();
        if self.matrix.as_str() == "enterprise-legacy" {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FY"),
                Cell::new("SUBTECHNIQUE").style_spec("FW"),
                Cell::new("SUBTECHNIQUE NAME").style_spec("FW"),
                Cell::new("TACTICS").style_spec("cFW"),
                Cell::new("PLATFORMS").style_spec("cFW"),
                Cell::new("DATASOURCES").style_spec("cFW"),
                Cell::new("ADVERSARIES").style_spec("cFW"),
                Cell::new("MALWARE").style_spec("cFW"),
                Cell::new("TOOLS").style_spec("cFW"),
            ]));
        } else {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FY"),
                Cell::new("SUBTECHNIQUE").style_spec("cFW"),
                Cell::new("SUBTECHNIQUE NAME").style_spec("FW"),
                Cell::new("TACTICS").style_spec("cFW"),
                Cell::new("PLATFORMS").style_spec("cFW"),
                Cell::new("DATASOURCES").style_spec("cFW"),
                Cell::new("ADVERSARIES").style_spec("cFW"),
                Cell::new("MALWARE").style_spec("cFW"),
                Cell::new("TOOLS").style_spec("cFW"),
            ]));
        }

        let _json: Vec<EnterpriseStatistic> = serde_json::from_str(results[0].as_str())
            .expect("(?) Error: Unable To Deserialize Search Results By SubTechniques");
        for (_idx, _row) in _json.iter().enumerate() {
            if self.matrix.as_str() == "enterprise-legacy" {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("cFW"),
                    Cell::new(_row.meta.as_str()).style_spec("FW"),
                    Cell::new(_row.count_tactics.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_platforms.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_datasources.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_adversaries.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_malware.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_tools.to_string().as_str()).style_spec("cFW"),
                ]));
            } else {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("cFW"),
                    Cell::new(_row.meta.as_str()).style_spec("FW"),
                    Cell::new(_row.count_tactics.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_platforms.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_datasources.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_adversaries.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_malware.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_tools.to_string().as_str()).style_spec("cFW"),
                ]));
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_table);
        } else if _wants_export == "json" {
            println!("{}", serde_json::to_string_pretty(&_json).unwrap());
        } else {
            println!("{}", "\n\n");
            let mut _totals_table = Table::new();
            _totals_table.add_row(Row::new(vec![
                Cell::new("Total Techniques").style_spec("FY"),
                Cell::new(_json[0].from_total_techniques.to_string().as_str()).style_spec("cFW"),
                Cell::new(_json[0].from_total_subtechniques.to_string().as_str()).style_spec("cFW"),
                Cell::new("Total Subtechniques").style_spec("FY"),
            ]));

            _totals_table.printstd();
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
            
        }
    }       
    ///
    ///
    fn render_techniques_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        
        let mut _table = Table::new();
        if self.matrix.as_str() == "enterprise-legacy" {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FY"),
                Cell::new("TECHNIQUE").style_spec("FW"),
                Cell::new("TECHNIQUE NAME").style_spec("FW"),
                Cell::new("TACTICS").style_spec("cFW"),
                Cell::new("PLATFORMS").style_spec("cFW"),
                Cell::new("DATASOURCES").style_spec("cFW"),
                Cell::new("ADVERSARIES").style_spec("cFW"),
                Cell::new("MALWARE").style_spec("cFW"),
                Cell::new("TOOLS").style_spec("cFW"),
            ]));
        } else {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FY"),
                Cell::new("TECHNIQUE").style_spec("cFW"),
                Cell::new("TECHNIQUE NAME").style_spec("FW"),
                Cell::new("SUBTECHNIQUES").style_spec("cFW"),
                Cell::new("TACTICS").style_spec("cFW"),
                Cell::new("PLATFORMS").style_spec("cFW"),
                Cell::new("DATASOURCES").style_spec("cFW"),
                Cell::new("ADVERSARIES").style_spec("cFW"),
                Cell::new("MALWARE").style_spec("cFW"),
                Cell::new("TOOLS").style_spec("cFW"),
            ]));
        }

        let _json: Vec<EnterpriseStatistic> = serde_json::from_str(results[0].as_str())
            .expect("(?) Error: Unable To Deserialize Search Results By Techniques");
        for (_idx, _row) in _json.iter().enumerate() {
            if self.matrix.as_str() == "enterprise-legacy" {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("cFW"),
                    Cell::new(_row.meta.as_str()).style_spec("FW"),
                    Cell::new(_row.count_tactics.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_platforms.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_datasources.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_adversaries.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_malware.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_tools.to_string().as_str()).style_spec("cFW"),
                ]));
            } else {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("cFW"),
                    Cell::new(_row.meta.as_str()).style_spec("FW"),
                    Cell::new(_row.count_subtechniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_tactics.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_platforms.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_datasources.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_adversaries.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_malware.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_tools.to_string().as_str()).style_spec("cFW"),
                ]));
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_table);
        } else if _wants_export == "json" {
            println!("{}", serde_json::to_string_pretty(&_json).unwrap());
        } else {
            println!("{}", "\n\n");
            let mut _totals_table = Table::new();
            _totals_table.add_row(Row::new(vec![
                Cell::new("Total Techniques").style_spec("FY"),
                Cell::new(_json[0].from_total_techniques.to_string().as_str()).style_spec("cFW"),
                Cell::new(_json[0].from_total_subtechniques.to_string().as_str()).style_spec("cFW"),
                Cell::new("Total Subtechniques").style_spec("FY"),
            ]));

            _totals_table.printstd();
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
            
        }
    }    
    ///
    ///
    fn render_tactics_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        
        let mut _table = Table::new();
        if self.matrix.as_str() == "enterprise-legacy" {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FY"),
                Cell::new("TACTICS").style_spec("FW"),
                Cell::new("TECHNIQUES").style_spec("cFW"),
                Cell::new("% TECHNIQUES").style_spec("cFY"),
            ]));
        } else {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FY"),
                Cell::new("TACTICS").style_spec("FW"),
                Cell::new("TECHNIQUES").style_spec("cFW"),
                Cell::new("SUBTECHNIQUES").style_spec("cFW"),
                Cell::new("% TECHNIQUES").style_spec("cFY"),
                Cell::new("% SUBTECHNIQUES").style_spec("cFY"),
            ]));
        }

        let _json: Vec<EnterpriseStatistic> = serde_json::from_str(results[0].as_str())
            .expect("(?) Error: Unable To Deserialize Search Results By Tactics");
        for (_idx, _row) in _json.iter().enumerate() {
            if self.matrix.as_str() == "enterprise-legacy" {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("FW"),
                    Cell::new(_row.count_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_techniques.as_str()).style_spec("cFW"),
                ]));
            } else {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("FW"),
                    Cell::new(_row.count_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_subtechniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_techniques.as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_subtechniques.as_str()).style_spec("cFW"),
                ]));
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_table);
        } else if _wants_export == "json" {
            println!("{}", serde_json::to_string_pretty(&_json).unwrap());
        } else {
            println!("{}", "\n\n");
            let mut _totals_table = Table::new();
            _totals_table.add_row(Row::new(vec![
                Cell::new("Total Techniques").style_spec("FY"),
                Cell::new(_json[0].from_total_techniques.to_string().as_str()).style_spec("cFW"),
                Cell::new(_json[0].from_total_subtechniques.to_string().as_str()).style_spec("cFW"),
                Cell::new("Total Subtechniques").style_spec("FY"),
            ]));

            _totals_table.printstd();
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
            
        }
    }
    ///
    /// 
    /// 
    /// 
    fn render_tools_profile_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        let mut _table = Table::new();
        let mut _csv_table = Table::new();
        let _table_headers: Row = Row::new(vec![
            Cell::new("INDEX").style_spec("c"),
            Cell::new("STATUS").style_spec("cFW"),
            Cell::new("WID").style_spec("cFW"),
            Cell::new("TOOL").style_spec("cFW"),
            Cell::new("ALIASES").style_spec("c"),
            Cell::new("PLATFORMS").style_spec("cFW"),
            Cell::new("TACTICS").style_spec("cFW"),
            Cell::new("TECHNIQUES").style_spec("cFG"),
            Cell::new("SUBTECHNIQUES").style_spec("cFW"),
            Cell::new("ADVERSARIES").style_spec("c"),
        ]);
        if _wants_export == "csv" {
            _csv_table.add_row(_table_headers);
        } else {
            _table.add_row(_table_headers);
        }
        let _err = "(?) Error: Unable To Deserialize Search Results By tool";
        let mut _json: Vec<EnterpriseTool> = serde_json::from_str(results[0].as_str()).expect(_err);
        for (_idx, _row) in _json.iter().enumerate() {
            // Aliases
            let mut _aliases = "".to_string();
            if _row.aliases.len() == 0 {
                _aliases.push_str("none");
            } else {
                _aliases = _row.aliases.clone();
            }
            // Platforms
            let mut _platforms = "".to_string();
            if _row.platforms.len() == 0 {
                _platforms.push_str("none");
            } else {
                _platforms = _row.platforms.clone();
            }
            // Tactics
            let mut _tactics = "".to_string();
            if _row.profile.tactics.items.len() > 0 {
                _row.profile
                    .tactics
                    .items
                    .iter()
                    .map(|x| {
                        _tactics.push_str(x.as_str());
                        _tactics.push_str("|")
                    })
                    .collect::<Vec<_>>();
            } else {
                _tactics.push_str("none");
            }
            // Techniques
            let mut _techniques = "".to_string();
            if _row.profile.techniques.items.len() > 0 {
                _row.profile
                    .techniques
                    .items
                    .iter()
                    .map(|x| {
                        _techniques.push_str(x.as_str());
                        _techniques.push_str("|")
                    })
                    .collect::<Vec<_>>();
            } else {
                _techniques.push_str("none");
            }
            // Subtechniques
            let mut _subtechniques = "".to_string();
            if _row.profile.subtechniques.items.len() > 0 {
                _row.profile
                    .subtechniques
                    .items
                    .iter()
                    .map(|x| {
                        _subtechniques.push_str(x.as_str());
                        _subtechniques.push_str("|")
                    })
                    .collect::<Vec<_>>();
            } else {
                _subtechniques.push_str("none");
            }
            let mut _adversaries = "".to_string();
            if _row.profile.adversaries.items.len() > 0 {
                _row.profile
                    .adversaries
                    .items
                    .iter()
                    .map(|x| {
                        _adversaries.push_str(x.as_str());
                        _adversaries.push_str("|")
                    })
                    .collect::<Vec<_>>();
            } else {
                _adversaries.push_str("none");
            }             
            //
            let mut _status_cell: Cell;
            let mut _tool_id_cell: Cell;
            if _row.is_revoked {
                _status_cell = Cell::new("Revoked").style_spec("cFR");
                _tool_id_cell = Cell::new(&_row.tool_id.as_str()).style_spec("cFR");
            } else {
                _status_cell = Cell::new("Active").style_spec("cFG");
                _tool_id_cell = Cell::new(&_row.tool_id.as_str()).style_spec("cFW");
            }
            if _wants_export == "csv" {
                _csv_table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("c"),
                    _status_cell.clone(),
                    _tool_id_cell.clone(),
                    Cell::new(&_row.name.as_str()),
                    Cell::new(&_aliases),
                    Cell::new(&_platforms),
                    Cell::new(&_tactics.as_str()),
                    Cell::new(&_techniques),
                    Cell::new(&_subtechniques.as_str()),
                    Cell::new(&_adversaries.as_str())
                ]));
            } else {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("c"),
                    _status_cell.clone(),
                    _tool_id_cell.clone(),
                    Cell::new(&_row.name.as_str()).style_spec("FW"),
                    Cell::new(&_aliases.replace("|", "\n")),
                    Cell::new(&_platforms.replace("|", "\n")),
                    Cell::new(&_tactics.as_str().replace("|", "\n")),
                    Cell::new(&_techniques.as_str().replace("|", "\n")).style_spec("cFG"),
                    Cell::new(&_subtechniques.as_str().replace("|", "\n")).style_spec("cFW"),
                    Cell::new(&_adversaries.replace("|", "\n")),
                ]));
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_csv_table);
        } else if _wants_export == "json" {
            println!("{}", serde_json::to_string_pretty(&_json).unwrap());
        } else {
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
        }
    }
    ///
    ///
    ///
    ///
    fn render_malware_profile_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
        _wants_correlation: bool
    ) {
        let mut _table = Table::new();
        let mut _csv_table = Table::new();
        let mut _table_headers: Row;
        if _wants_correlation {
            _table_headers = Row::new(vec![
                Cell::new("INDEX").style_spec("c"),
                Cell::new("STATUS").style_spec("c"),
                //Cell::new("GID").style_spec("cFW"),
                Cell::new("MALWARE").style_spec("cFW"),
                //Cell::new("ALIASES").style_spec("c"),
                Cell::new("PLATFORMS"),
                Cell::new("TACTIC").style_spec("c"),
                Cell::new("TID").style_spec("cFG"),
                Cell::new("TECHNIQUE").style_spec("cFG"),
                //Cell::new("SUBTECHNIQUES").style_spec("cFW"),
                Cell::new("DATA SOURCES").style_spec("c"),
                //Cell::new("MALWARE").style_spec("cFY"),
                //Cell::new("TOOLS").style_spec("cFY"),
            ]);
        } else {
            _table_headers = Row::new(vec![
                Cell::new("INDEX").style_spec("c"),
                Cell::new("STATUS").style_spec("c"),
                Cell::new("MID").style_spec("cFW"),
                Cell::new("MALWARE").style_spec("cFW"),
                Cell::new("ALIASES").style_spec("c"),
                Cell::new("PLATFORMS").style_spec("cFW"),
                Cell::new("TACTICS").style_spec("cFW"),
                Cell::new("TECHNIQUES").style_spec("cFG"),
                Cell::new("SUBTECHNIQUES").style_spec("cFW"),
                Cell::new("ADVERSARIES").style_spec("c"),
            ]);
        }
        if _wants_export == "csv" {
            _csv_table.add_row(_table_headers);
        } else {
            _table.add_row(_table_headers);
        }
        let mut _json_out: Vec<EnterpriseTechnique> = vec![];
        let mut _json_out_malware: Vec<EnterpriseMalware> = vec![];
        if _wants_correlation {
            let _err = "(?) Error: Unable To Deserialize Search Correlation Results By Adversaries";
            let mut _json: Vec<EnterpriseTechnique>;
            _json = serde_json::from_str(results[0].as_str()).expect(_err);
            let mut _sorted_index: Vec<(String, usize, usize)> = vec![];
            let _err: &str = "(?) Error: Render Adversaries Correlation Table Deserialization";
            for (_ridx, _item) in results.iter().enumerate() {
                let _json: Vec<EnterpriseTechnique> =
                    serde_json::from_str(results[_ridx].as_str()).expect(_err);
                for (_jidx, _record) in _json.iter().enumerate() {
                    _sorted_index.push((_record.tid.clone(), _jidx, _ridx));
                }
            }
            _sorted_index.sort();
            let mut _st = String::from("");
            let mut _mw = String::from("");
            let mut _idx: usize = 0;
            let _err: &str = "(?) Error: Render Adversaries Correlation Table Deserialization";
            for (_technique, _jidx, _ridx) in _sorted_index {
                let _json: Vec<EnterpriseTechnique> =
                    serde_json::from_str(results[_ridx].as_str()).expect(_err);
                let _row = &_json[_jidx];
                if _row.has_subtechniques {
                    _row.subtechniques
                        .iter()
                        .map(|x| {
                            _st.push_str(x.as_str());
                            _st.push_str("|")
                        })
                        .collect::<Vec<_>>();
                } else {
                    _st.push_str("n_a");
                }

                // When a deprecated Technique is part of the result
                // then create a row for the deprecated technique
                let mut _status: Cell;
                let mut _tid: Cell;
                if _row.is_deprecated {
                    _status = Cell::new("Deprecated").style_spec("FY");
                    _tid = Cell::new(_row.tid.as_str()).style_spec("FY");
                } else if _row.is_revoked {
                    _status = Cell::new("Revoked").style_spec("FR");
                    _tid = Cell::new(_row.tid.as_str()).style_spec("FR");
                } else {
                    _status = Cell::new("Active").style_spec("FG");
                    _tid = Cell::new(_row.tid.as_str()).style_spec("cFG");
                }
                if _wants_export == "csv" {
                    _csv_table.add_row(Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()),
                        _status,
                        Cell::new(_row.correlation_malware.as_str()),
                        Cell::new(_row.platform.as_str()),
                        Cell::new(_row.tactic.as_str()),
                        _tid,
                        Cell::new(_row.technique.as_str()),
                        //Cell::new(_st.as_str()),
                        Cell::new(_row.datasources.as_str()),
                        //Cell::new(_row.correlation_malware.as_str()),
                        //Cell::new(_row.correlation_tool.as_str()),
                    ]));
                } else {
                    _table.add_row(Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()),
                        _status,
                        Cell::new(_row.correlation_malware.as_str()).style_spec("FW"),
                        Cell::new(_row.platform.replace("|", "\n").as_str()),
                        Cell::new(_row.tactic.as_str()).style_spec("FW"),
                        _tid,
                        Cell::new(_row.technique.as_str()).style_spec("FW"),
                        //Cell::new(_st.replace("|", "\n").as_str()).style_spec("cFW"),
                        Cell::new(_row.datasources.replace("|", "\n").as_str()),
                        //Cell::new(_row.correlation_malware.replace("|", "\n").as_str()).style_spec("FW"),
                        //Cell::new(_row.correlation_tool.replace("|", "\n").as_str()).style_spec("FW"),
                    ]));
                }
                _st.clear();
                _idx += 1;
                _json_out.push(_row.clone());
            }
        } else {
            let _err = "(?) Error: Unable To Deserialize Search Results By Malware";
            let mut _json: Vec<EnterpriseMalware> =
                serde_json::from_str(results[0].as_str()).expect(_err);
            for (_idx, _row) in _json.iter().enumerate() {
                // Aliases
                let mut _aliases = "".to_string();
                if _row.aliases.len() == 0 {
                    _aliases.push_str("none");
                } else {
                    _aliases = _row.aliases.clone();
                }
                // Platforms
                let mut _platforms = "".to_string();
                if _row.platforms.len() == 0 {
                    _platforms.push_str("none");
                } else {
                    _platforms = _row.platforms.clone();
                }            
                // Tactics
                let mut _tactics = "".to_string();
                if _row.profile.tactics.items.len() > 0 {
                    _row.profile
                        .tactics
                        .items
                        .iter()
                        .map(|x| {
                            _tactics.push_str(x.as_str());
                            _tactics.push_str("|")
                        })
                        .collect::<Vec<_>>();
                } else {
                    _tactics.push_str("none");
                }
                // Techniques
                let mut _techniques = "".to_string();
                if _row.profile.techniques.items.len() > 0 {
                    _row.profile
                        .techniques
                        .items
                        .iter()
                        .map(|x| {
                            _techniques.push_str(x.as_str());
                            _techniques.push_str("|")
                        })
                        .collect::<Vec<_>>();
                } else {
                    _techniques.push_str("none");
                }
                // Subtechniques
                let mut _subtechniques = "".to_string();
                if _row.profile.subtechniques.items.len() > 0 {
                    _row.profile
                        .subtechniques
                        .items
                        .iter()
                        .map(|x| {
                            _subtechniques.push_str(x.as_str());
                            _subtechniques.push_str("|")
                        })
                        .collect::<Vec<_>>();
                } else {
                    _subtechniques.push_str("none");
                }
               // Adversaries
               let mut _adversaries = "".to_string();
               if _row.profile.adversaries.items.len() > 0 {
                   _row.profile
                       .adversaries
                       .items
                       .iter()
                       .map(|x| {
                           _adversaries.push_str(x.as_str());
                           _adversaries.push_str("|")
                       })
                       .collect::<Vec<_>>();
               } else {
                   _adversaries.push_str("none");
               }         
                let mut _status_cell: Cell;
                let mut _malware_id_cell: Cell;
                if _row.is_revoked {
                    _status_cell = Cell::new("Revoked").style_spec("cFR");
                    _malware_id_cell = Cell::new(&_row.malware_id.as_str()).style_spec("cFR");
                } else {
                    _status_cell = Cell::new("Active").style_spec("cFG");
                    _malware_id_cell = Cell::new(&_row.malware_id.as_str()).style_spec("cFW");
                }
                if _wants_export == "csv" {
                    _csv_table.add_row(Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()).style_spec("c"),
                        _status_cell.clone(),
                        _malware_id_cell.clone(),
                        Cell::new(&_row.name.as_str()),
                        Cell::new(&_aliases),
                        Cell::new(&_platforms),
                        Cell::new(&_tactics.as_str()),
                        Cell::new(&_techniques),
                        Cell::new(&_subtechniques.as_str()),
                        Cell::new(&_adversaries.as_str())
                    ]));
                } else {
                        _table.add_row(Row::new(vec![
                            Cell::new((_idx + 1).to_string().as_str()).style_spec("c"),
                            _status_cell.clone(),
                            _malware_id_cell.clone(),
                            Cell::new(&_row.name.as_str()).style_spec("FW"),
                            Cell::new(&_aliases.replace("|", "\n")),
                            Cell::new(&_platforms.replace("|", "\n")),
                            Cell::new(&_tactics.as_str().replace("|", "\n")),
                            Cell::new(&_techniques.as_str().replace("|", "\n")).style_spec("cFG"),
                            Cell::new(&_subtechniques.as_str().replace("|", "\n")).style_spec("cFW"),
                            Cell::new(&_adversaries.as_str().replace("|","\n"))
                        ]));
                }
                _json_out_malware.push(_row.clone());
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_csv_table);
        } else if _wants_export == "json" {
            if _wants_correlation {
                println!("{}", serde_json::to_string_pretty(&_json_out).unwrap());
            } else {
                println!("{}",serde_json::to_string_pretty(&_json_out_malware).unwrap());
            }
        } else {
            println!("{}", "\n");
            _table.print_tty(false);
            println!("{}", "\n\n");
        }
    }
    ///
    ///
    ///
    ///
    fn render_adversaries_profile_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
        _wants_correlation: bool
    ) {
        let mut _table = Table::new();
        let mut _csv_table = Table::new();
        let mut _table_headers: Row;
        if _wants_correlation {
            _table_headers = Row::new(vec![
                Cell::new("INDEX").style_spec("c"),
                Cell::new("STATUS").style_spec("c"),
                //Cell::new("GID").style_spec("cFW"),
                Cell::new("ADVERSARY").style_spec("cFW"),
                //Cell::new("ALIASES").style_spec("c"),
                Cell::new("PLATFORMS"),
                Cell::new("TACTIC").style_spec("c"),
                Cell::new("TID").style_spec("cFG"),
                Cell::new("TECHNIQUE").style_spec("cFG"),
                //Cell::new("SUBTECHNIQUES").style_spec("cFW"),
                Cell::new("DATA SOURCES").style_spec("c"),
                Cell::new("MALWARE").style_spec("cFY"),
                Cell::new("TOOLS").style_spec("cFY"),
            ]);
        } else {
            _table_headers = Row::new(vec![
                Cell::new("INDEX").style_spec("c"),
                Cell::new("STATUS").style_spec("c"),
                Cell::new("GID").style_spec("cFW"),
                Cell::new("ADVERSARIES").style_spec("cFW"),
                Cell::new("ALIASES").style_spec("c"),
                Cell::new("TACTICS").style_spec("c"),
                Cell::new("TID").style_spec("cFG"),
                Cell::new("SUBTECHNIQUES").style_spec("cFW"),
                Cell::new("MALWARE").style_spec("c"),
                Cell::new("TOOLS").style_spec("c"),
            ]);
        }
        if _wants_export == "csv" {
            _csv_table.add_row(_table_headers);
        } else {
            _table.add_row(_table_headers);
        }
        let mut _json_out: Vec<EnterpriseTechnique> = vec![];
        let mut _json_out_adversary: Vec<EnterpriseAdversary> = vec![];
        if _wants_correlation {
            let _err = "(?) Error: Unable To Deserialize Search Correlation Results By Adversaries";
            let mut _json: Vec<EnterpriseTechnique>;
            _json = serde_json::from_str(results[0].as_str()).expect(_err);
            let mut _sorted_index: Vec<(String, usize, usize)> = vec![];
            let _err: &str = "(?) Error: Render Adversaries Correlation Table Deserialization";
            for (_ridx, _item) in results.iter().enumerate() {
                let _json: Vec<EnterpriseTechnique> =
                    serde_json::from_str(results[_ridx].as_str()).expect(_err);
                for (_jidx, _record) in _json.iter().enumerate() {
                    _sorted_index.push((_record.tid.clone(), _jidx, _ridx));
                }
            }
            _sorted_index.sort();
            let mut _st = String::from("");
            let mut _mw = String::from("");
            let mut _idx: usize = 0;
            let _err: &str = "(?) Error: Render Adversaries Correlation Table Deserialization";
            for (_technique, _jidx, _ridx) in _sorted_index {
                let _json: Vec<EnterpriseTechnique> =
                    serde_json::from_str(results[_ridx].as_str()).expect(_err);
                let _row = &_json[_jidx];
                if _row.has_subtechniques {
                    _row.subtechniques
                        .iter()
                        .map(|x| {
                            _st.push_str(x.as_str());
                            _st.push_str("|")
                        })
                        .collect::<Vec<_>>();
                } else {
                    _st.push_str("n_a");
                }

                // When a deprecated Technique is part of the result
                // then create a row for the deprecated technique
                let mut _status: Cell;
                let mut _tid: Cell;
                if _row.is_deprecated {
                    _status = Cell::new("Deprecated").style_spec("FY");
                    _tid = Cell::new(_row.tid.as_str()).style_spec("FY");
                } else if _row.is_revoked {
                    _status = Cell::new("Revoked").style_spec("FR");
                    _tid = Cell::new(_row.tid.as_str()).style_spec("FR");
                } else {
                    _status = Cell::new("Active").style_spec("FG");
                    _tid = Cell::new(_row.tid.as_str()).style_spec("cFG");
                }
                if _wants_export == "csv" {
                    _csv_table.add_row(Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()),
                        _status,
                        Cell::new(_row.correlation_adversary.as_str()),
                        Cell::new(_row.platform.as_str()),
                        Cell::new(_row.tactic.as_str()),
                        _tid,
                        Cell::new(_row.technique.as_str()),
                        //Cell::new(_st.as_str()),
                        Cell::new(_row.datasources.as_str()),
                        Cell::new(_row.correlation_malware.as_str()),
                        Cell::new(_row.correlation_tool.as_str()),
                    ]));
                } else {
                    _table.add_row(Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()),
                        _status,
                        Cell::new(_row.correlation_adversary.as_str()).style_spec("FW"),
                        Cell::new(_row.platform.replace("|", "\n").as_str()),
                        Cell::new(_row.tactic.as_str()).style_spec("FW"),
                        _tid,
                        Cell::new(_row.technique.as_str()).style_spec("FW"),
                        //Cell::new(_st.replace("|", "\n").as_str()).style_spec("cFW"),
                        Cell::new(_row.datasources.replace("|", "\n").as_str()),
                        Cell::new(_row.correlation_malware.replace("|", "\n").as_str()).style_spec("FW"),
                        Cell::new(_row.correlation_tool.replace("|", "\n").as_str()).style_spec("FW"),
                    ]));
                }
                _st.clear();
                _idx += 1;
                _json_out.push(_row.clone());
            }
        } else {
            let _err = "(?) Error: Unable To Deserialize Search Results By Adversaries";
            let mut _json: Vec<EnterpriseAdversary>;
            _json = serde_json::from_str(results[0].as_str()).expect(_err);
            for (_idx, _row) in _json.iter().enumerate() {
                let mut _aliases = "".to_string();
                if _row.aliases.len() == 0 {
                    _aliases.push_str("none");
                } else {
                    _aliases = _row.aliases.clone();
                }
                //
                let mut _tactics = "".to_string();
                if _row.profile.tactics.items.len() > 0 {
                    _row.profile
                        .tactics
                        .items
                        .iter()
                        .map(|x| {
                            _tactics.push_str(x.as_str());
                            _tactics.push_str("|")
                        })
                        .collect::<Vec<_>>();
                } else {
                    _tactics.push_str("none");
                }
                //
                let mut _techniques = "".to_string();
                if _row.profile.techniques.items.len() > 0 {
                    _row.profile
                        .techniques
                        .items
                        .iter()
                        .map(|x| {
                            _techniques.push_str(x.as_str());
                            _techniques.push_str("|")
                        })
                        .collect::<Vec<_>>();
                } else {
                    _techniques.push_str("none");
                }
                //
                let mut _subtechniques = "".to_string();
                if _row.profile.subtechniques.items.len() > 0 {
                    _row.profile
                        .subtechniques
                        .items
                        .iter()
                        .map(|x| {
                            _subtechniques.push_str(x.as_str());
                            _subtechniques.push_str("|")
                        })
                        .collect::<Vec<_>>();
                } else {
                    _subtechniques.push_str("none");
                }
                //
                let mut _malware = "".to_string();
                if _row.profile.malware.items.len() > 0 {
                    _row.profile
                        .malware
                        .items
                        .iter()
                        .map(|x| {
                            _malware.push_str(x.as_str());
                            _malware.push_str("|")
                        })
                        .collect::<Vec<_>>();
                } else {
                    _malware.push_str("none");
                }
                //
                let mut _tools = "".to_string();
                if _row.profile.tools.items.len() > 0 {
                    _row.profile
                        .tools
                        .items
                        .iter()
                        .map(|x| {
                            _tools.push_str(x.as_str());
                            _tools.push_str("|")
                        })
                        .collect::<Vec<_>>();
                } else {
                    _tools.push_str("none");
                }
                //
                let mut _revoked_cell: Cell;
                let mut _group_id_cell: Cell;
                if _row.is_revoked {
                    _revoked_cell = Cell::new("Revoked").style_spec("cFR");
                    _group_id_cell = Cell::new(&_row.group_id.as_str()).style_spec("cFR");
                } else {
                    _revoked_cell = Cell::new("Active").style_spec("cFG");
                    _group_id_cell = Cell::new(&_row.group_id.as_str()).style_spec("cFW");
                }
                if _wants_export == "csv" {
                    _csv_table.add_row(Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()).style_spec("c"),
                        _revoked_cell.clone(),
                        _group_id_cell.clone(),
                        Cell::new(&_row.name.as_str()),
                        Cell::new(&_aliases),
                        Cell::new(&_tactics.as_str()),
                        Cell::new(&_techniques),
                        Cell::new(&_subtechniques.as_str()),
                        Cell::new(&_malware),
                        Cell::new(&_tools),
                    ]));
                } else {
                    _table.add_row(Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()).style_spec("c"),
                        _revoked_cell.clone(),
                        _group_id_cell.clone(),
                        Cell::new(&_row.name.as_str()).style_spec("cFW"),
                        Cell::new(&_aliases.replace("|", "\n")),
                        Cell::new(&_tactics.as_str().replace("|", "\n")),
                        Cell::new(&_techniques.as_str().replace("|", "\n")).style_spec("cFG"),
                        Cell::new(&_subtechniques.as_str().replace("|", "\n")).style_spec("cFW"),
                        Cell::new(&_malware.replace("|", "\n")),
                        Cell::new(&_tools.as_str().replace("|", "\n")),
                    ]));
                }
                _json_out_adversary.push(_row.clone());
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_csv_table);
        } else if _wants_export == "json" {
            if _wants_correlation {
                println!("{}", serde_json::to_string_pretty(&_json_out).unwrap());
            } else {
                println!("{}",serde_json::to_string_pretty(&_json_out_adversary).unwrap());
            }
        } else {
            println!("{}", "\n");
            //_table.printstd();
            _table.print_tty(false);
            println!("{}", "\n\n");
        }
    }
    fn render_platforms_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        let mut _table = Table::new();
        if self.matrix.as_str() == "enterprise-legacy" {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FW"),
                Cell::new("PLATFORMS").style_spec("FW"),
                Cell::new("TECHNIQUES").style_spec("cFW"),
                Cell::new("% TECHNIQUES").style_spec("cFY"),
            ]));
        } else {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FW"),
                Cell::new("PLATFORMS").style_spec("FW"),
                Cell::new("TECHNIQUES").style_spec("cFW"),
                Cell::new("SUBTECHNIQUES").style_spec("cFW"),
                Cell::new("% TECHNIQUES").style_spec("cFY"),
                Cell::new("% SUBTECHNIQUES").style_spec("cFY"),
            ]));
        }
        let _err: &str = "(?) Error: Unable To Deserialize Search Results By Platforms";
        //let _json: Vec<String> = serde_json::from_str(results[0].as_str()).expect(_err);
        let _json: Vec<EnterpriseStatistic> = serde_json::from_str(results[0].as_str()).expect(_err);
        for (_idx, _row) in _json.iter().enumerate() {
            if self.matrix.as_str() == "enterprise-legacy" {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("FW"),
                    Cell::new(_row.count_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_techniques.as_str()).style_spec("cFW"),
                ]));
            } else {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("FW"),
                    Cell::new(_row.count_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_subtechniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_techniques.as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_subtechniques.as_str()).style_spec("cFW"),
                ]));
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_table);
        } else if _wants_export == "json" {
            println!("{}", serde_json::to_string_pretty(&_json).unwrap());
        } else {
            println!("{}", "\n\n");
            let mut _totals_table = Table::new();
            _totals_table.add_row(Row::new(vec![
                Cell::new("Total Techniques").style_spec("FY"),
                Cell::new(_json[0].from_total_techniques.to_string().as_str()).style_spec("cFW"),
                Cell::new(_json[0].from_total_subtechniques.to_string().as_str()).style_spec("cFW"),
                Cell::new("Total Subtechniques").style_spec("FY"),
            ]));

            _totals_table.printstd();
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
        }
    }
    ///
    fn render_adversaries_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        let mut _table = Table::new();
        if self.matrix.as_str() == "enterprise-legacy" {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FW"),
                Cell::new("ADVERSARY").style_spec("cFW"),
                Cell::new("TACTICS").style_spec("cFW"),
                Cell::new("TECHNIQUES").style_spec("cFW"),
                Cell::new("(%) TECHNIQUES").style_spec("cFY"),
            ]));
        } else {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FW"),
                Cell::new("ADVERSARY").style_spec("FW"),
                Cell::new("TACTICS").style_spec("cFW"),
                Cell::new("TECHNIQUES").style_spec("cFW"),
                Cell::new("SUBTECHNIQUES").style_spec("cFW"),
                Cell::new("(%) TECHNIQUES").style_spec("cFY"),
                Cell::new("(%) SUBTECHNIQUES").style_spec("cFY"),
            ]));
        }
        let _err: &str = "(?) Error: Unable To Deserialize Search Results By Adversaries";
        //let _json: Vec<String> = serde_json::from_str(results[0].as_str()).expect(_err);
        let _json: Vec<EnterpriseStatistic> = serde_json::from_str(results[0].as_str()).expect(_err);
        for (_idx, _row) in _json.iter().enumerate() {
            if self.matrix.as_str()  == "enterprise-legacy" {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("FW"),
                    Cell::new(_row.count_tactics.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_techniques.to_string().as_str()).style_spec("c"),
                    Cell::new(_row.percent_techniques.as_str()).style_spec("c"),
                ]));
            } else {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("FW"),
                    Cell::new(_row.count_tactics.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_subtechniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_techniques.as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_subtechniques.as_str()).style_spec("cFW"),
                ]));
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_table);
        } else if _wants_export == "json" {
            println!("{}", serde_json::to_string_pretty(&_json).unwrap()); 
        } else {
            println!("{}", "\n\n");
            let mut _totals_table = Table::new();
            _totals_table.add_row(Row::new(vec![
                Cell::new("Total Techniques").style_spec("FY"),
                Cell::new(_json[0].from_total_techniques.to_string().as_str()).style_spec("cFW"),
                Cell::new(_json[0].from_total_subtechniques.to_string().as_str()).style_spec("cFW"),
                Cell::new("Total Subtechniques").style_spec("FY"),
            ]));

            _totals_table.printstd();
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
        }
    }
    ///
    ///
    fn render_malware_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        let mut _table = Table::new();
        if self.matrix.as_str() == "enterprise-legacy" {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FW"),
                Cell::new("MALWARE").style_spec("cFW"),
                Cell::new("TECHNIQUES").style_spec("cFW"),
                Cell::new("% TECHNIQUES").style_spec("cFY"),
            ]));
        } else {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FW"),
                Cell::new("MALWARE").style_spec("cFW"),
                Cell::new("TECHNIQUES").style_spec("cFW"),
                Cell::new("SUBTECHNIQUES").style_spec("cFW"),
                Cell::new("% TECHNIQUES").style_spec("cFY"),
                Cell::new("% SUBTECHNIQUES").style_spec("cFY"),
            ]));
        }
        let _err: &str = "(?) Error: Unable To Deserialize Search Results By DataSources";
        //let _json: Vec<String> = serde_json::from_str(results[0].as_str()).expect(_err);
        let _json: Vec<EnterpriseStatistic> = serde_json::from_str(results[0].as_str()).expect(_err);
        for (_idx, _row) in _json.iter().enumerate() {
            if self.matrix.as_str()  == "enterprise-legacy" {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("FW"),
                    Cell::new(_row.count_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_subtechniques.to_string().as_str()).style_spec("cFW"),
                ]));
            } else {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("FW"),
                    Cell::new(_row.count_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_subtechniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_subtechniques.to_string().as_str()).style_spec("cFW"),
                ]));
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_table);
        } else if _wants_export == "json" {
            println!("{}", serde_json::to_string_pretty(&_json).unwrap()); 
        } else {
            println!("{}", "\n\n");
            let mut _totals_table = Table::new();
            _totals_table.add_row(Row::new(vec![
                Cell::new("Total Techniques").style_spec("FY"),
                Cell::new(_json[0].from_total_techniques.to_string().as_str()).style_spec("cFW"),
                Cell::new(_json[0].from_total_subtechniques.to_string().as_str()).style_spec("cFW"),
                Cell::new("Total Subtechniques").style_spec("FY"),
            ]));

            _totals_table.printstd();
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
        }
    }
    ///
    ///
    fn render_tools_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        let mut _table = Table::new();
        if self.matrix.as_str() == "enterprise-legacy" {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FW"),
                Cell::new("TOOL").style_spec("cFW"),
                Cell::new("TECHNIQUES").style_spec("cFW"),
                Cell::new("% TECHNIQUES").style_spec("cFY"),
            ]));
        } else {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FW"),
                Cell::new("TOOL").style_spec("cFW"),
                Cell::new("TECHNIQUES").style_spec("cFW"),
                Cell::new("SUBTECHNIQUES").style_spec("cFW"),
                Cell::new("% TECHNIQUES").style_spec("cFY"),
                Cell::new("% SUBTECHNIQUES").style_spec("cFY"),
            ]));
        }
        let _err: &str = "(?) Error: Unable To Deserialize Search Results By DataSources";
        //let _json: Vec<String> = serde_json::from_str(results[0].as_str()).expect(_err);
        let _json: Vec<EnterpriseStatistic> = serde_json::from_str(results[0].as_str()).expect(_err);
        for (_idx, _row) in _json.iter().enumerate() {
            if self.matrix.as_str()  == "enterprise-legacy" {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("FW"),
                    Cell::new(_row.count_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_techniques.to_string().as_str()).style_spec("cFW"),
                ]));
            } else {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("FW"),
                    Cell::new(_row.count_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_subtechniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_subtechniques.to_string().as_str()).style_spec("cFW"),
                ]));
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_table);
        } else if _wants_export == "json" {
            println!("{}", serde_json::to_string_pretty(&_json).unwrap()); 
        } else {
            println!("{}", "\n\n");
            let mut _totals_table = Table::new();
            _totals_table.add_row(Row::new(vec![
                Cell::new("Total Techniques").style_spec("FY"),
                Cell::new(_json[0].from_total_techniques.to_string().as_str()).style_spec("cFW"),
                Cell::new(_json[0].from_total_subtechniques.to_string().as_str()).style_spec("cFW"),
                Cell::new("Total Subtechniques").style_spec("FY"),
            ]));

            _totals_table.printstd();
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
        }
    }
    ///
    ///
    fn render_datasources_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        let mut _table = Table::new();
        if self.matrix.as_str() == "enterprise-legacy" {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FW"),
                Cell::new("DATASOURCE").style_spec("cFW"),
                Cell::new("TECHNIQUES").style_spec("cFW"),
                Cell::new("% TECHNIQUES").style_spec("cFY"),
            ]));
        } else {
            _table.add_row(Row::new(vec![
                Cell::new("INDEX").style_spec("FW"),
                Cell::new("DATASOURCE").style_spec("cFW"),
                Cell::new("TECHNIQUES").style_spec("cFW"),
                Cell::new("SUBTECHNIQUES").style_spec("cFW"),
                Cell::new("% TECHNIQUES").style_spec("cFY"),
                Cell::new("% SUBTECHNIQUES").style_spec("cFY"),
            ]));
        }
        let _err: &str = "(?) Error: Unable To Deserialize Search Results By DataSources";
        //let _json: Vec<String> = serde_json::from_str(results[0].as_str()).expect(_err);
        let _json: Vec<EnterpriseStatistic> = serde_json::from_str(results[0].as_str()).expect(_err);
        for (_idx, _row) in _json.iter().enumerate() {
            if self.matrix.as_str()  == "enterprise-legacy" {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("FW"),
                    Cell::new(_row.count_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_techniques.to_string().as_str()).style_spec("cFW"),
                ]));
            } else {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()).style_spec("FY"),
                    Cell::new(_row.item.as_str()).style_spec("FW"),
                    Cell::new(_row.count_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.count_subtechniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_techniques.to_string().as_str()).style_spec("cFW"),
                    Cell::new(_row.percent_techniques.to_string().as_str()).style_spec("cFW"),
                ]));
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_table);
        } else if _wants_export == "json" {
            println!("{}", serde_json::to_string_pretty(&_json).unwrap()); 
        } else {
            println!("{}", "\n\n");
            let mut _totals_table = Table::new();
            _totals_table.add_row(Row::new(vec![
                Cell::new("Total Techniques").style_spec("FY"),
                Cell::new(_json[0].from_total_techniques.to_string().as_str()).style_spec("cFW"),
                Cell::new(_json[0].from_total_subtechniques.to_string().as_str()).style_spec("cFW"),
                Cell::new("Total Subtechniques").style_spec("FY"),
            ]));

            _totals_table.printstd();
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
        }
    }
    fn render_techniques_details_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        let mut _csv_table = Table::new();
        let mut _table = Table::new();
        let _table_headers: Row = Row::new(vec![
            Cell::new("INDEX"),
            Cell::new("STATUS"),
            Cell::new("PLATFORMS"),
            Cell::new("TACTIC"),
            Cell::new("TID").style_spec("FG"),
            Cell::new("TECHNIQUE"),
            Cell::new("SUBTECHNIQUES"),
            Cell::new("DATA SOURCES"),
        ]);
        if _wants_export == "csv" {
            _csv_table.add_row(_table_headers);
        } else {
            _table.add_row(_table_headers);
        }
        let mut _sorted_index: Vec<(String, usize, usize)> = vec![];
        let _err: &str = "(?) Error: Render Table Deserialization";
        for (_ridx, _item) in results.iter().enumerate() {
            let _json: Vec<EnterpriseTechnique> =
                serde_json::from_str(results[_ridx].as_str()).expect(_err);
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
        let mut _json_out: Vec<EnterpriseTechnique> = vec![];
        let _err: &str = "(?) Error: Render Table Deserialization";
        for (_technique, _jidx, _ridx) in _sorted_index {
            let _json: Vec<EnterpriseTechnique> =
                serde_json::from_str(results[_ridx].as_str()).expect(_err);
            let _row = &_json[_jidx];
            if _row.has_subtechniques {
                _row.subtechniques
                    .iter()
                    .map(|x| {
                        _st.push_str(x.as_str());
                        _st.push_str("|")
                    })
                    .collect::<Vec<_>>();
            } else {
                _st.push_str("n_a");
            }
            // When a deprecated Technique is part of the result
            // then create a row for the deprecated technique
            let mut _status: Cell;
            let mut _tid: Cell;
            if _row.is_deprecated {
                _status = Cell::new("Deprecated").style_spec("FY");
                _tid = Cell::new(_row.tid.as_str()).style_spec("FY");
            } else if _row.is_revoked {
                _status = Cell::new("Revoked").style_spec("FR");
                _tid = Cell::new(_row.tid.as_str()).style_spec("FR");
            } else {
                _status = Cell::new("Active").style_spec("FG");
                _tid = Cell::new(_row.tid.as_str()).style_spec("FG");
            }
            if _wants_export == "csv" {
                _csv_table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()),
                    _status,
                    Cell::new(_row.platform.as_str()),
                    Cell::new(_row.tactic.as_str()),
                    _tid,
                    Cell::new(_row.technique.as_str()),
                    Cell::new(_st.as_str()),
                    Cell::new(_row.datasources.as_str()),
                ]));
            } else {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()),
                    _status,
                    Cell::new(_row.platform.replace("|", "\n").as_str()),
                    Cell::new(_row.tactic.as_str()),
                    _tid,
                    Cell::new(_row.technique.as_str()).style_spec("FW"),
                    Cell::new(_st.replace("|", "\n").as_str()).style_spec("cFW"),
                    Cell::new(_row.datasources.replace("|", "\n").as_str()),
                ]));
            }
            _st.clear();
            _idx += 1;
            _json_out.push(_row.clone());
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_csv_table);
        } else if _wants_export == "json" {
            println!("{}", serde_json::to_string_pretty(&_json_out).unwrap());
        } else {
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
        }
    }
    fn render_revoked_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        let mut _table = Table::new();
        _table.add_row(Row::new(vec![
            Cell::new("INDEX").style_spec("FW"),
            Cell::new("STATUS").style_spec("cFW"),
            Cell::new("OLD TID").style_spec("cFW"),
            Cell::new("TECHNIQUE").style_spec("cFW"),
            Cell::new("NEW TID").style_spec("cFG"),
            Cell::new("TECHNIQUE").style_spec("cFW")
        ]));
        let mut _idx: usize = 0;
        for _item in results.iter() {
            let mut _json: Vec<EnterpriseRevokedItem> = serde_json::from_str(_item.as_str())
                .expect("(?) Error:  Render Table Deserialization For Revoked");
            _json.sort();
            for _item in _json.iter() {
                _table.add_row(
                    Row::new(vec![
                        Cell::new((_idx + 1).to_string().as_str()),
                        Cell::new("Revoked").style_spec("FR"),
                        Cell::new(_item.eid.as_str()).style_spec("cFW"),
                        Cell::new(_item.name.as_str()).style_spec("FW"),
                        Cell::new(_item.new_eid.as_str()).style_spec("cFG"),
                        Cell::new(_item.new_name.as_str()).style_spec("FW")
                    ])
                );
                _idx += 1;
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_table);
        }
        else if _wants_export == "json" {
            println!("{}", results[0]);
        } 
        else {
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
        }
    }
    fn render_deprecated_table(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        let mut _table = Table::new();
        _table.add_row(Row::new(vec![
            Cell::new("INDEX").style_spec("FW"),
            Cell::new("STATUS").style_spec("FY"),
            Cell::new("TID").style_spec("FY"),
            Cell::new("TECHNIQUE"),
        ]));
        let mut _idx: usize = 0;
        for _item in results.iter() {
            let mut _json: Vec<(&str, &str)> = serde_json::from_str(_item.as_str())
                .expect("(?) Error:  Render Table Deserialization For Revoked");
            _json.sort();
            for (_tid, _technique) in _json.iter() {
                _table.add_row(Row::new(vec![
                    Cell::new((_idx + 1).to_string().as_str()),
                    Cell::new("Deprecated"),
                    Cell::new(_tid).style_spec("FY"),
                    Cell::new(_technique).style_spec("FW"),
                ]));
                _idx += 1;
            }
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_table);
        }
        else if _wants_export == "json" {
            println!("{}", results[0]);
        }
        else {
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
        }
    }
    fn render_stats_xref_datasource_platforms(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
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
                Cell::new(
                    &_data[_datasource]["aws"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["azure"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["azure-ad"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["gcp"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["linux"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["macos"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["office-365"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["saas"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["windows"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
            ]));
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_table);
        } 
        else {
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
        }
    }
    fn render_stats_xref_datasource_tactics(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
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
                Cell::new(
                    &_data[_datasource]["initial-access"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["execution"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["persistence"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["privilege-escalation"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["defense-evasion"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["credential-access"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["discovery"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["lateral-movement"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["collection"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["command-and-control"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["exfiltration"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
                Cell::new(
                    &_data[_datasource]["impact"]
                        .as_i64()
                        .unwrap()
                        .to_string()
                        .as_str(),
                )
                .style_spec("cFW"),
            ]));
        }
        if _wants_export == "csv" {
            self.save_csv_export(_wants_outfile, &_table);
        } else {
            println!("{}", "\n\n");
            _table.printstd();
            println!("{}", "\n\n");
        }
    }
    fn render_stats(
        &self,
        results: &Vec<String>,
        _wants_export: &str,
        _wants_outfile: &str,
    ) {
        let mut _table = Table::new();
        _table.add_row(Row::new(vec![
            Cell::new("CATEGORY"),
            Cell::new("COUNTS"),
            Cell::new("PERCENT %"),
        ]));
        let _item = &results[0];
        let _json: EnterpriseMatrixStatistics = serde_json::from_str(_item.as_str())
            .expect("(?) Error:  Render Table Deserialization For Stats");
        // Uniques - Overview Section
        // Describes the uniq number of techniques
        // by platform only - no tactics are included
        _table.add_row(Row::new(vec![
            Cell::new("By Uniques").style_spec("FY"),
            Cell::new(""),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Active Techniques"),
            Cell::new(_json.count_active_uniq_techniques.to_string().as_str()),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Active Subtechniques"),
            Cell::new(_json.count_active_uniq_subtechniques.to_string().as_str()),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Active Platforms"),
            Cell::new(_json.count_platforms.to_string().as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Active Tactics"),
            Cell::new(_json.count_tactics.to_string().as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Active Data Sources"),
            Cell::new(_json.count_datasources.to_string().as_str()),
            Cell::new(""),
        ]));
        // Totals - Overview Section
        // Describes the total number of techniques & subtechniques
        // by active, revoked - no tactics are included
        _table.add_empty_row();
        _table.add_row(Row::new(vec![
            Cell::new("By Totals").style_spec("FY"),
            Cell::new(""),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Deprecated Techniques"),
            Cell::new(_json.count_deprecated_techniques.to_string().as_str()),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Revoked Techniques"),
            Cell::new(_json.count_revoked_techniques.to_string().as_str()),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Active Techniques"),
            Cell::new(_json.count_active_total_techniques.to_string().as_str()),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Active Subtechniques"),
            Cell::new(_json.count_active_total_subtechniques.to_string().as_str()),
            Cell::new(""),
        ]));
        // Totals - Techniques Section
        // Describes the total number of techniques
        // by platform only - no tactics are included
        _table.add_empty_row();
        _table.add_row(Row::new(vec![
            Cell::new("Totals - Techniques By Platform").style_spec("FY"),
            Cell::new(""),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("AWS"),
            Cell::new(_json.count_techniques_aws.to_string().as_str()),
            Cell::new(_json.percent_techniques_aws.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("AZURE"),
            Cell::new(_json.count_techniques_azure.to_string().as_str()),
            Cell::new(_json.percent_techniques_azure.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("AZURE-AD"),
            Cell::new(_json.count_techniques_azure_ad.to_string().as_str()),
            Cell::new(_json.percent_techniques_azure_ad.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("GCP"),
            Cell::new(_json.count_techniques_gcp.to_string().as_str()),
            Cell::new(_json.percent_techniques_gcp.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("LINUX"),
            Cell::new(_json.count_techniques_linux.to_string().as_str()),
            Cell::new(_json.percent_techniques_linux.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("MAC-OS"),
            Cell::new(_json.count_techniques_macos.to_string().as_str()),
            Cell::new(_json.percent_techniques_macos.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("OFFICE-365"),
            Cell::new(_json.count_techniques_office365.to_string().as_str()),
            Cell::new(_json.percent_techniques_office365.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("SAAS"),
            Cell::new(_json.count_techniques_saas.to_string().as_str()),
            Cell::new(_json.percent_techniques_saas.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("WINDOWS"),
            Cell::new(_json.count_techniques_windows.to_string().as_str()),
            Cell::new(_json.percent_techniques_windows.as_str()),
        ]));
        // Totals - Subtechniques Section
        // Describes the total number of techniques
        // by platform only - no tactics are included
        _table.add_empty_row();
        _table.add_row(Row::new(vec![
            Cell::new("Total - Subtechniques By Platform").style_spec("FY"),
            Cell::new(""),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("AWS"),
            Cell::new(_json.count_subtechniques_aws.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_aws.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("AZURE"),
            Cell::new(_json.count_subtechniques_azure.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_azure.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("AZURE-AD"),
            Cell::new(_json.count_subtechniques_azure_ad.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_azure_ad.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("GCP"),
            Cell::new(_json.count_subtechniques_gcp.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_gcp.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("LINUX"),
            Cell::new(_json.count_subtechniques_linux.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_linux.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("MAC-OS"),
            Cell::new(_json.count_subtechniques_macos.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_macos.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("OFFICE-365"),
            Cell::new(_json.count_subtechniques_office365.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_office365.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("SAAS"),
            Cell::new(_json.count_subtechniques_saas.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_saas.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("WINDOWS"),
            Cell::new(_json.count_subtechniques_windows.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_windows.as_str()),
        ]));
        // Tactics/KillChain Sections
        // Techniques By Killchain
        _table.add_empty_row();
        _table.add_row(Row::new(vec![
            Cell::new("Totals - Techniques By Tactic/KillChain").style_spec("FY"),
            Cell::new(""),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Initial Access"),
            Cell::new(_json.count_techniques_initial_access.to_string().as_str()),
            Cell::new(_json.percent_techniques_initial_access.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Execution"),
            Cell::new(_json.count_techniques_execution.to_string().as_str()),
            Cell::new(_json.percent_techniques_execution.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Persistence"),
            Cell::new(_json.count_techniques_persistence.to_string().as_str()),
            Cell::new(_json.percent_techniques_persistence.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Privilege Escalation"),
            Cell::new(
                _json
                    .count_techniques_privilege_escalation
                    .to_string()
                    .as_str(),
            ),
            Cell::new(_json.percent_techniques_privilege_escalation.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Defense Evasion"),
            Cell::new(_json.count_techniques_defense_evasion.to_string().as_str()),
            Cell::new(_json.percent_techniques_defense_evasion.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Credential Access"),
            Cell::new(
                _json
                    .count_techniques_credential_access
                    .to_string()
                    .as_str(),
            ),
            Cell::new(_json.percent_techniques_credential_access.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Discovery"),
            Cell::new(_json.count_techniques_discovery.to_string().as_str()),
            Cell::new(_json.percent_techniques_discovery.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Lateral Movement"),
            Cell::new(_json.count_techniques_lateral_movement.to_string().as_str()),
            Cell::new(_json.percent_techniques_lateral_movement.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Collection"),
            Cell::new(_json.count_techniques_collection.to_string().as_str()),
            Cell::new(_json.percent_techniques_collection.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Command and Control"),
            Cell::new(
                _json
                    .count_techniques_command_and_control
                    .to_string()
                    .as_str(),
            ),
            Cell::new(_json.percent_techniques_command_and_control.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Exfiltration"),
            Cell::new(_json.count_techniques_exfiltration.to_string().as_str()),
            Cell::new(_json.percent_techniques_exfiltration.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Impact"),
            Cell::new(_json.count_techniques_impact.to_string().as_str()),
            Cell::new(_json.percent_techniques_impact.as_str()),
        ]));
        //
        // Subtechniques By Killchain
        _table.add_empty_row();
        _table.add_row(Row::new(vec![
            Cell::new("Totals - Subtechniques By Tactic/KillChain").style_spec("FY"),
            Cell::new(""),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Initial Access"),
            Cell::new(
                _json
                    .count_subtechniques_initial_access
                    .to_string()
                    .as_str(),
            ),
            Cell::new(_json.percent_subtechniques_initial_access.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Execution"),
            Cell::new(_json.count_subtechniques_execution.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_execution.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Persistence"),
            Cell::new(_json.count_subtechniques_persistence.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_persistence.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Privilege Escalation"),
            Cell::new(
                _json
                    .count_subtechniques_privilege_escalation
                    .to_string()
                    .as_str(),
            ),
            Cell::new(_json.percent_subtechniques_privilege_escalation.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Defense Evasion"),
            Cell::new(
                _json
                    .count_subtechniques_defense_evasion
                    .to_string()
                    .as_str(),
            ),
            Cell::new(_json.percent_subtechniques_defense_evasion.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Credential Access"),
            Cell::new(
                _json
                    .count_subtechniques_credential_access
                    .to_string()
                    .as_str(),
            ),
            Cell::new(_json.percent_subtechniques_credential_access.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Discovery"),
            Cell::new(_json.count_subtechniques_discovery.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_discovery.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Lateral Movement"),
            Cell::new(
                _json
                    .count_subtechniques_lateral_movement
                    .to_string()
                    .as_str(),
            ),
            Cell::new(_json.percent_subtechniques_lateral_movement.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Collection"),
            Cell::new(_json.count_subtechniques_collection.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_collection.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Command and Control"),
            Cell::new(
                _json
                    .count_subtechniques_command_and_control
                    .to_string()
                    .as_str(),
            ),
            Cell::new(_json.percent_subtechniques_command_and_control.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Exfiltration"),
            Cell::new(_json.count_subtechniques_exfiltration.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_exfiltration.as_str()),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Impact"),
            Cell::new(_json.count_subtechniques_impact.to_string().as_str()),
            Cell::new(_json.percent_subtechniques_impact.as_str()),
        ]));
        // General Section
        // Used for placeholders if items (objects) not yet analyzed
        // These are TODOs
        _table.add_empty_row();
        _table.add_row(Row::new(vec![
            Cell::new("General - Pending Analysis").style_spec("FY"),
            Cell::new(""),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Records For Malware"),
            Cell::new(_json.count_malwares.to_string().as_str()),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Records For Adversaries"),
            Cell::new(_json.count_adversaries.to_string().as_str()),
            Cell::new(""),
        ]));
        _table.add_row(Row::new(vec![
            Cell::new("Records For Tools"),
            Cell::new(_json.count_tools.to_string().as_str()),
            Cell::new(""),
        ]));
        println!("\n\n");
        _table.printstd();
        println!("\n\n");
        /*
        TO DO:
        if _wants_export == "csv" {
            _table.remove_row(index: usize)
            self.save_csv_export(_wants_outfile, &_table);
        }
        */
    }
}
