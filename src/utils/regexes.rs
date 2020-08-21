use regex::{Regex, RegexSet, RegexSetBuilder};

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
    pub fn load_search_datasources(ds: &Vec<String>) -> Self
    {
        let mut _patterns: Vec<String> = vec![];
        for _item in ds.iter() {
            let _p = format!(r"{}", _item);
            _patterns.push(_p);
        }
        RegexPatternManager {
            pattern: RegexSetBuilder::new(&_patterns[..])
                        .case_insensitive(true)
                        .unicode(true)
                        .build()
                        .expect("(?) Error: RegexPatternManager | Cannot Build Searc Terms For Datasources")
        }
    }
}