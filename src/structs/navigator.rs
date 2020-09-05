use serde_derive;


/// # Navigator Version 2
/// These structs accomdoate the legacy version of the
/// navigator application's data format before the new
/// version with subtechniques was introduced in 2020.
/// 
/// While the newer version is being introduced, let's
/// support the legacy version as most people like are
/// using this version for now.
/// 
/// When the newer version, the `mitre-assistant` will
/// split the compatibility into two distinct structs
/// prefixed with a `V2` for legacy, and a `V3` for the
/// newer versions.
/// 
/// 
/// 
/// # Legacy: V2Navigator
/// The entire `json` used by the `mitre-navigator` application
/// is represented in the `mitre-assistant` as `V2Navigator`.
/// 
/// The constructor is invoked like this:
/// 
/// ```ignore
/// // Assumes you want to setup a V2 object
/// // and manipulate it yourself.
/// 
/// let mut _nav = V2Navigator::new();
/// 
/// // Add the name of your navigator
/// _nav.name = "My Awesome Navigator Object";
/// ```
/// 
/// # Serializing
/// The `mitre-assistant` mainly offers the export
/// of its parsed data into a the format of the navigator.
/// 
/// The approach is to write a navigator layer file from
/// a query.
#[derive(Debug, Deserialize, Serialize)]
pub struct V2Navigator {
    pub name:                               String,
    pub version:                            String,
    pub domain:                             String,
    pub description:                        String,
    pub filters:                            V2NavigatorFilters,
    pub sorting:                            u8,
    pub view_mode:                          u8,
    pub hide_disabled:                      bool,
    pub techniques:                         Vec<V2NavigatorTechnique>,
    pub gradient:                           V2NavigatorGradient,
    pub legend_items:                       Vec<V2NavigatorLegendItem>
    pub metadata:                           Vec<String>,
    pub show_tactic_row_background:         bool,
    pub tactic_row_background:              String,
    pub select_techniques_across_tactics:   bool,
}
impl V2Navigator {
    /// # V2Navigator Constructor
    /// 
    pub new() -> Self
    {
        V2Navigator {
            name:           "".to_string(),
            version:        "".to_string(),
            domain:         "".to_string(),
            description:    "".to_string(),
            filters:        V2NavigatorFilters::new(),
            sorting:        1,
            view_mode:      0,
            hide_disabled:  true,
            techniques:     vec![],
            gradient:       V2NavigatorGradient::new(),
            legend_items:   vec![],
            metadata:       vec![],
            show_tactic_row_background: true,
            select_techniques_across_tactics: true
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V2NavigatorFilters {
    pub stages:     Vec<String>,
    pub platforms:  Vec<String>
}
impl V2NavigatorFilters {
    pub new() ->
    {
        V2NavigatorFilters {
            stages:     vec![],
            platforms:  vec![]
        }
    }
}


#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V2NavigatorTechnique {
    pub technique_id:   String,
    pub tactic:         String,
    pub score:          u32,
    pub color:          String,
    pub comment:        String,
    pub enabled:        bool,
    pub metadata:       Vec<String>
}
impl V2NavigatorTechnique {
    pub new() -> Self
    {
        V2NavigatorTechnique {
            technique_id:   "".to_string(),
            tactic:         "".to_string(),
            score:          0,
            color:          "".to_string(),
            comment:        "".to_string(),
            enabled:        false,
            metadata:       vec![]
        }
    }
}


#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V2NavigatorGradient {
    pub colors:     Vec<String>,
    pub min_value:  u32,
    pub max_value:  u32
}
impl V2NavigatorGradient {
    pub new() -> Self
    {
        V2NavigatorGradient {
            colors:     vec![],
            min_value:  0,
            max_value:  0
        }
    }
}


#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V2NavigatorLegendItem {
    pub color:  String,
    pub label:  String
}
impl V2NavigatorLegendItem {
    pub new() -> Self
    {
        V2NavigatorLegendItem {
            color:  "".to_string(),
            label:  "".to_string()
        }
    }
}