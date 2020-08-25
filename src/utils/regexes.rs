use regex::{Regex, RegexSet, RegexSetBuilder};
use std::collections::HashSet;

#[derive(Debug)]
pub struct RegexPatternManager {
    pub pattern:    RegexSet
}
impl RegexPatternManager {
    pub fn load_subtechnique() -> Self
    {
        RegexPatternManager {
            pattern: RegexSetBuilder::new(&[
                r#"T\d{4}\.\d{3}"#,
            ]).case_insensitive(true)
              .unicode(true)
              .build()
              .expect("(?) Error: RegexPatternManager | Cannot Build Subtechnique Pattern")
        }
    }
    pub fn load_technique() -> Self
    {
        RegexPatternManager {
            pattern:  RegexSetBuilder::new(&[
                r#"T\d{4}"#,
            ]).case_insensitive(true)
              .unicode(true)
              .build()
              .expect("(?) Error: RegexPatternManager | Cannot Build Technique ID Pattern")
        }
    }
    pub fn load_search_term_patterns() -> Self
    {
        RegexPatternManager {
            pattern:  RegexSetBuilder::new(&[
                r#"^T\d{4}$"#,                  // Technique ID
                r#"^T\d{4}\.\d{3}$"#,           // Subtechnique ID
                r#"(\W|^)[A-z]{3,}(\W|$)"#,     // Technique Name, controls input length in search
            ]).case_insensitive(true)
              .unicode(true)
              .build()
              .expect("(?) Error: RegexPatternManager | Cannot Build Search Terms Patterns")
        }
    }
    pub fn load_search_datasources(ds: &Vec<String>, platforms: &HashSet<String>) -> Self
    {
        let mut _patterns: Vec<String> = vec![];
        // First Create The Patterns of just datasources
        for _item in ds.iter() {
            let _p = format!(r"{}", _item);
            _patterns.push(_p);
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
        RegexPatternManager {
            pattern: RegexSetBuilder::new(&_patterns[..])
                        .case_insensitive(true)
                        .unicode(true)
                        .build()
                        .expect("(?) Error: RegexPatternManager | Cannot Build SearcH Terms For Datasources")
        }
    }
    pub fn load_search_adversaries(adversaries: &Vec<String>) -> Self
    {
        let mut _patterns: Vec<String> = vec![];
        // First Create The Patterns of just datasources
        for _item in adversaries.iter() {
            let _p = format!(r"{}", _item);
            _patterns.push(_p);
        }
        //println!("{:#?}", _patterns);
        RegexPatternManager {
            pattern: RegexSetBuilder::new(&_patterns[..])
                        .case_insensitive(true)
                        .unicode(true)
                        .build()
                        .expect("(?) Error: RegexPatternManager | Cannot Build Searc Terms For Adversaries")
        }
    }
    pub fn load_search_malware(malware: &Vec<String>) -> Self
    {
        let mut _patterns: Vec<String> = vec![];
        // First Create The Patterns of just datasources
        for _item in malware.iter() {
            let _p = format!(r"{}", _item);
            _patterns.push(_p);
        }
        //println!("{:#?}", _patterns);
        RegexPatternManager {
            pattern: RegexSetBuilder::new(&_patterns[..])
                        .case_insensitive(true)
                        .unicode(true)
                        .build()
                        .expect("(?) Error: RegexPatternManager | Cannot Build Search Terms For Malware")
        }
    }
    pub fn load_search_tools(tools: &Vec<String>) -> Self
    {
        let mut _patterns: Vec<String> = vec![];
        // First Create The Patterns of just datasources
        for _item in tools.iter() {
            let _p = format!(r"{}", _item);
            _patterns.push(_p);
        }
        //println!("{:#?}", _patterns);
        RegexPatternManager {
            pattern: RegexSetBuilder::new(&_patterns[..])
                        .case_insensitive(true)
                        .unicode(true)
                        .build()
                        .expect("(?) Error: RegexPatternManager | Cannot Build Search Terms For Tools")
        }
    }            
}