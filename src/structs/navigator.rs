use serde_derive::{Deserialize, Serialize};

/// # Navigator Version 2
/// These structs accommodate the legacy version of the
/// navigator application's data format before the new
/// version with subtechniques was introduced in 2020.
/// 
/// While the newer version is being introduced, let's
/// support the legacy version as most people likely are
/// using this version for now.
/// 
/// When the newer version is stable, the `mitre-assistant` will
/// split the compatibility into two distinct structs
/// prefixed with a `V2` for legacy, and a `V3` for the
/// newer versions.
/// 
/// 
/// 
/// # Legacy: V2
/// The entire `json` used by the `mitre-navigator` application
/// is represented in the `mitre-assistant` as `V2`.
/// 
/// The constructor is invoked like this:
/// 
/// ```ignore
/// // Assumes you want to setup a V2 object
/// // and manipulate it yourself.
/// 
/// let mut _nav = V2::new();
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
    pub filters:                            Option<V2Filters>,
    pub sorting:                            u8,
    
    #[serde(rename = "viewMode")]
    pub view_mode:                          Option<u8>,
    
    #[serde(rename = "hideDisabled")]
    pub hide_disabled:                      bool,
    
    pub techniques:                         Vec<V2Technique>,
    pub gradient:                           Option<V2Gradient>,
    
    #[serde(rename = "legendItems")]
    pub legend_items:                       Vec<V2LegendItem>,
    pub metadata:                           Option<Vec<String>>,
    
    #[serde(rename = "showTacticRowBackground")]
    pub show_tactic_row_background:         bool,
    
    #[serde(rename = "tacticRowBackground")]
    pub tactic_row_background:              String,
    
    #[serde(rename = "selectTechniquesAcrossTactics")]
    pub select_techniques_across_tactics:   bool,
}

impl V2Navigator {
    /// # V2 Constructor
    /// 
    pub fn new() -> Self
    {
        V2Navigator {
            name:           "".to_string(),
            version:        "".to_string(),
            domain:         "".to_string(),
            description:    "".to_string(),
            filters:        Some(V2Filters::new()),
            sorting:        1,
            view_mode:      Some(0),
            hide_disabled:  true,
            techniques:     vec![],
            gradient:       Some(V2Gradient::new()),
            legend_items:   vec![],
            metadata:       Some(vec![]),
            show_tactic_row_background: true,
			tactic_row_background: "".to_string(),
            select_techniques_across_tactics: true
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V2Filters {
    pub stages:     Vec<String>,
    pub platforms:  Vec<String>
}
impl V2Filters {
    pub fn new() -> Self
    {
        V2Filters {
            stages:     vec![],
            platforms:  vec![]
        }
    }
}
#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V2Technique {
    #[serde(rename = "techniqueID")]
    pub technique_id:   String,
    pub tactic:         String,
    pub score:          Option<u32>,
    pub color:          String,
    pub comment:        String,
    pub enabled:        bool,
    pub metadata:       Option<Vec<String>>
}
impl V2Technique {
    pub fn new() -> Self
    {
        V2Technique {
            technique_id:   "".to_string(),
            tactic:         "".to_string(),
            score:          Some(0),
            color:          "".to_string(),
            comment:        "".to_string(),
            enabled:        false,
            metadata:       Some(vec![])
        }
    }
}
#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V2Gradient {
    pub colors:     Vec<String>,
    
    #[serde(rename = "minValue")]
    pub min_value:  u32,
    
    #[serde(rename = "maxValue")]
    pub max_value:  u32
}
impl V2Gradient {
    pub fn new() -> Self
    {
        V2Gradient {
            colors:     vec![],
            min_value:  0,
            max_value:  0
        }
    }
}
#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V2LegendItem {
    pub color:  String,
    pub label:  String
}
impl V2LegendItem {
    pub fn new() -> Self
    {
        V2LegendItem {
            color:  "".to_string(),
            label:  "".to_string()
        }
    }
}


/// # Navigator Version 3
/// Structures for the newer version introduced in 2020
///
#[derive(Debug, Deserialize, Serialize)]
pub struct V3Navigator {
    pub name:           String,
    pub versions:       std::collections::HashMap<String, String>,
    pub domain:         String,
    pub description:    String,
    pub filters:        V3Filters,
    pub sorting:        u16,
    pub layout:         V3Layout, 

    #[serde(rename = "viewMode")]
    pub view_mode:      Option<u8>,
    
    #[serde(rename = "hideDisabled")]
    pub hide_disabled:  bool,
    pub techniques:     Vec<V3Technique>,
    pub gradient:       V3Gradient,

    #[serde(rename = "legendItems")]
    pub legend_items: Vec<V3LegendItem>,

    pub metadata: Vec<String>,

    #[serde(rename = "showTacticRowBackground")]
    pub show_tactic_row_background: bool,

	#[serde(rename = "tacticRowBackground")]
    pub tactic_row_background: String,

    #[serde(rename = "selectTechniquesAcrossTactics")]
    pub select_techniques_across_tactics: bool,

    #[serde(rename = "selectSubtechniquesWithParent")]
    pub select_subtechniques_with_parent: bool
}


#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V3Layout {
    pub layout: String,

    #[serde(rename = "showId")]
    pub show_id: bool,

    #[serde(rename = "showName")]
    pub show_name: bool
}
impl V3Layout {
    pub fn new() -> Self
    {
        V3Layout {
            layout: "side".to_string(),
            show_id: false,
            show_name: true
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V3Technique {
    #[serde(rename = "techniqueID")]
    pub technique_id:   String,
    pub tactic:         String,
    pub score:          Option<u32>,
    pub color:          String,
    pub comment:        String,
    pub enabled:        bool,
    pub metadata:       Option<Vec<String>>,
    
    #[serde(rename = "showSubtechniques")]
    pub show_subtechniques: bool,
}

#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V3Filters {
    pub stages:     Vec<String>,
    pub platforms:  Vec<String>
}
impl V3Filters {
    pub fn new() -> Self
    {
        V3Filters {
            stages:     vec![],
            platforms:  vec![]
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V3Gradient {
    pub colors:     Vec<String>,
    
    
    #[serde(rename = "minValue")]
    pub min_value:  u32,
    
    #[serde(rename = "maxValue")]
    pub max_value:  u32
}
impl V3Gradient {
    pub fn new() -> Self
    {
        V3Gradient {
            colors:     vec![],
            min_value:  0,
            max_value:  0
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Hash)]
pub struct V3LegendItem {
    pub color:  String,
    pub label:  String
}
impl V3LegendItem {
    pub fn new() -> Self
    {
        V3LegendItem {
            color:  "".to_string(),
            label:  "".to_string()
        }
    }
}