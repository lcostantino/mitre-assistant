use regex::{Regex, RegexSet, RegexSetBuilder};
use std::collections::HashSet;

#[derive(Debug)]
pub struct PatternManager {
    pub pattern:    RegexSet
}
impl PatternManager {
    pub fn load_subtechnique() -> Self
    {
        println!("[+] Loading Subtechnique Scanner");
        PatternManager {
            pattern: RegexSetBuilder::new(&[
                r#"T\d{4}\.\d{3}|T\d{4}"#,
            ]).case_insensitive(true)
              .unicode(true)
              .build()
              .expect("(?) Error: PatternManager | Cannot Build Subtechnique Pattern")
        }
    }
    pub fn load_correlation_tactics(input: &str, correlation_type: &str, tactics: &HashSet<String>) -> String
    {
        let _input = input.to_lowercase().replace(" ", "");
        let mut _match_result: String = "none".to_string();
        '__check: for _tactic in tactics.iter() {
            let _token: String = format!("{}:{}:{}", "correlation", correlation_type, _tactic);
            if _input.as_str() == _token.as_str() {
                _match_result = _token.clone();
                break;
            }
        }
        println!("[+] Loading Tactics Scanner: {}", _match_result);
        _match_result
    }
    pub fn load_technique() -> Self
    {
        PatternManager {
            pattern:  RegexSetBuilder::new(&[
                r#"T\d{4}"#,
            ]).case_insensitive(true)
              .unicode(true)
              .build()
              .expect("(?) Error: PatternManager | Cannot Build Technique ID Pattern")
        }
    }
    pub fn load_search_term_patterns() -> Self
    {
        PatternManager {
            pattern:  RegexSetBuilder::new(&[
                r#"^T\d{4}$"#,                  // Technique ID
                r#"^T\d{4}\.\d{3}$"#,           // Subtechnique ID
                r#"(\W|^)[A-z]{2,}(\W|$)"#,     // Technique Name, controls input length in search
            ]).case_insensitive(true)
              .unicode(true)
              .build()
              .expect("(?) Error: PatternManager | Cannot Build Search Terms Patterns")
        }
    }
    pub fn load_search_datasources(ds: &Vec<String>, platforms: &HashSet<String>) -> Self
    {
        let mut _patterns: Vec<String> = vec![];
        // First Create The Patterns of just datasources
        for _item in ds.iter() {
            // TODO: Alias Terms
            // These are common among users and save
            // typing time
            if _item.starts_with("anti-virus") {
                _patterns.push(format!(r"\b{}\b", "av"));
            }
            else if _item.starts_with("kernel-drivers") {
                _patterns.push(format!(r"\b{}\b", "drivers"));
            }            
            else if _item.starts_with("netflow") {
                _patterns.push(format!(r"\b{}\b", "netflow"));
            }
            else if _item.starts_with("network-intrusion-detection-system") {
                _patterns.push(format!(r"\b{}\b", "nids"));
            }
            else if _item.starts_with("packet-capture") {
                _patterns.push(format!(r"\b{}\b", "pcap"));
            }
            else if _item.starts_with("web-application-firewall-logs") {
                _patterns.push(format!(r"\b{}\b", "waf"));
            }
            else if _item.starts_with("windows-error-reporting") {
                _patterns.push(format!(r"\b{}\b", "wer"));
            }
            else if _item.starts_with("dns-records") {
                _patterns.push(format!(r"\b{}\b", "dns"));
            }
            else if _item.starts_with("detonation-chamber") {
                _patterns.push(format!(r"\b{}\b", "sandboxing"));
            }
            else if _item.starts_with("windows-event-logs") {
                _patterns.push(format!(r"\b{}\b", "eventlogs"));
                _patterns.push(format!(r"\b{}\b", "evtx"));
            }
            _patterns.push(format!(r"\b{}\b", _item));
        }
        // Now Create the Patterns of Platforms with Datasource
        // example - `windows:process-monitoring`
        for _os in platforms.iter() {
            for _item in ds.iter() {
                let _p = format!(r"{}:{}", _os, _item);
                _patterns.push(_p);
            }
        }
        //println!("{:#?}", _patterns);
        PatternManager {
            pattern: RegexSetBuilder::new(&_patterns[..])
                        .case_insensitive(true)
                        .unicode(true)
                        .build()
                        .expect("(?) Error: PatternManager | Cannot Build SearcH Terms For Datasources")
        }
    }
    pub fn load_search_adversaries(adversaries: &Vec<String>) -> Self
    {
        let mut _patterns: Vec<String> = vec![];
        for _item in adversaries.iter() {
            let _p = format!(r"\b{}\b", _item);
            _patterns.push(_p);
        }
        //println!("{:#?}", _patterns);
        PatternManager {
            pattern: RegexSetBuilder::new(&_patterns[..])
                        .case_insensitive(true)
                        .unicode(true)
                        .build()
                        .expect("(?) Error: PatternManager | Cannot Build Searc Terms For Adversaries")
        }
    }
    pub fn load_search_malware(malware: &Vec<String>, actors: &Vec<String>) -> Self
    {
        let mut _patterns: Vec<String> = vec![];
        for _item in malware.iter() {
            let _p = format!(r"\b{}\b", _item);
            _patterns.push(_p);
        }
        for _item in malware.iter() {
            for _actor in actors.iter() {
                if _actor.as_str() == _item {
                    let _p = format!(r"\b_{}\b", _item);
                    _patterns.push(_p);
                }
            }
        }
        //println!("{:#?}", _patterns);
        PatternManager {
            pattern: RegexSetBuilder::new(&_patterns[..])
                        .case_insensitive(true)
                        .unicode(true)
                        .build()
                        .expect("(?) Error: PatternManager | Cannot Build Search Terms For Malware")
        }
    }
    pub fn load_search_tools(tools: &Vec<String>) -> Self
    {
        let mut _patterns: Vec<String> = vec![];
        for _item in tools.iter() {
            let _p = format!(r"\b{}\b", _item);
            _patterns.push(_p);
        }
        //println!("{:#?}", _patterns);
        PatternManager {
            pattern: RegexSetBuilder::new(&_patterns[..])
                        .case_insensitive(true)
                        .unicode(true)
                        .build()
                        .expect("(?) Error: PatternManager | Cannot Build Search Terms For Tools")
        }
    }
    pub fn load_search_platforms(platforms: &HashSet<String>) -> Self
    {
        let mut _patterns: Vec<String> = vec![];
        for _item in platforms.iter() {
            let _p = format!(r"\b{}\b", _item);
            _patterns.push(_p);
        }
        //println!("{:#?}", _patterns);
        PatternManager {
            pattern: RegexSetBuilder::new(&_patterns[..])
                        .case_insensitive(true)
                        .unicode(true)
                        .build()
                        .expect("(?) Error: PatternManager | Cannot Build Search Terms For Platforms")
        }
    }
    pub fn load_search_tactics(tactics: &HashSet<String>) -> Self
    {
        let mut _patterns: Vec<String> = vec![];
        for _item in tactics.iter() {
            let _p = format!(r"\b{}\b", _item);
            _patterns.push(_p);
        }
        //println!("{:#?}", _patterns);
        PatternManager {
            pattern: RegexSetBuilder::new(&_patterns[..])
                        .case_insensitive(true)
                        .unicode(true)
                        .build()
                        .expect("(?) Error: PatternManager | Cannot Build Search Terms For Tactics")
        }
    }          
}