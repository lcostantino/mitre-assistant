use serde_derive::{Deserialize, Serialize};
use std::collections::HashSet;


#[derive(Debug,Deserialize, Serialize)]
pub struct EnterpriseMatrixStatistics {
    pub count_revoked_techniques:           usize,
    pub count_deprecated_techniques:        usize,
    pub count_active_total_techniques:      usize,
    pub count_active_total_subtechniques:   usize,
    pub count_active_uniq_techniques:       usize,
    pub count_active_uniq_subtechniques:    usize,
    pub count_malwares:                     usize,
    pub count_adversaries:                  usize,
    pub count_tools:                        usize,
    pub count_platforms:                    usize,
    pub count_tactics:                      usize,
    pub count_datasources:                  usize,
    // Count of Techniques by Platforms
    // Use these with stats functions
    pub count_techniques_aws:               usize,
    pub count_techniques_azure:             usize,
    pub count_techniques_azure_ad:          usize,
    pub count_techniques_gcp:               usize,
    pub count_techniques_linux:             usize,
    pub count_techniques_macos:             usize,
    pub count_techniques_office365:         usize,
    pub count_techniques_saas:              usize,
    pub count_techniques_windows:           usize,
    // Count of Subtechniques by Platforms
    // Use these with stats functions
    pub count_subtechniques_aws:            usize,
    pub count_subtechniques_azure:          usize,
    pub count_subtechniques_azure_ad:       usize,
    pub count_subtechniques_gcp:            usize,
    pub count_subtechniques_linux:          usize,
    pub count_subtechniques_macos:          usize,
    pub count_subtechniques_office365:      usize,
    pub count_subtechniques_saas:           usize,
    pub count_subtechniques_windows:        usize,
    // Count of Techniques by Tactic - KilChain
    // Use these with stats functions
    pub count_techniques_initial_access:    usize,
    pub count_techniques_execution:         usize,
    pub count_techniques_persistence:       usize,
    pub count_techniques_privilege_escalation: usize,
    pub count_techniques_defense_evasion:   usize,
    pub count_techniques_credential_access: usize,
    pub count_techniques_collection:        usize,
    pub count_techniques_discovery:         usize,
    pub count_techniques_lateral_movement:  usize,
    pub count_techniques_command_and_control: usize,
    pub count_techniques_exfiltration:      usize,
    pub count_techniques_impact:            usize,
    // Count of Subechniques by Tactic - KilChain
    // Use these with stats functions
    pub count_subtechniques_initial_access:    usize,
    pub count_subtechniques_execution:         usize,
    pub count_subtechniques_persistence:       usize,
    pub count_subtechniques_privilege_escalation: usize,
    pub count_subtechniques_defense_evasion:   usize,
    pub count_subtechniques_credential_access: usize,
    pub count_subtechniques_collection:        usize,
    pub count_subtechniques_discovery:         usize,
    pub count_subtechniques_lateral_movement:  usize,
    pub count_subtechniques_command_and_control: usize,
    pub count_subtechniques_exfiltration:      usize,
    pub count_subtechniques_impact:            usize,
    // Percentages of Specific Items
    // Use these with stats function
    // To get the percentage, go to the parser.rs module
    // and invoke the `get_percentage()` private method.
    // The total param is by the:
    //      `count_active_total_techniques`
    //      `count_active_total_subtechniques`
    //
    // Percentage Techniques By Platform
    pub percent_techniques_aws:         String,
    pub percent_techniques_azure:       String,
    pub percent_techniques_azure_ad:    String,
    pub percent_techniques_gcp:         String,
    pub percent_techniques_linux:       String,
    pub percent_techniques_macos:       String,
    pub percent_techniques_office365:  String,
    pub percent_techniques_saas:        String,
    pub percent_techniques_windows:     String,
    // Percentage Subtechniques By Platform
    pub percent_subtechniques_aws:      String,
    pub percent_subtechniques_azure:    String,
    pub percent_subtechniques_azure_ad: String,
    pub percent_subtechniques_gcp:      String,
    pub percent_subtechniques_linux:    String,
    pub percent_subtechniques_macos:    String,
    pub percent_subtechniques_office365: String,
    pub percent_subtechniques_saas:     String,
    pub percent_subtechniques_windows:  String,
    // Percentage Techniques By KillChain/Tactic
    pub percent_techniques_initial_access:          String,
    pub percent_techniques_execution:               String,
    pub percent_techniques_persistence:             String,
    pub percent_techniques_privilege_escalation:    String,
    pub percent_techniques_defense_evasion:         String,
    pub percent_techniques_credential_access:       String,
    pub percent_techniques_discovery:               String,
    pub percent_techniques_lateral_movement:        String,
    pub percent_techniques_collection:              String,
    pub percent_techniques_command_and_control:     String,
    pub percent_techniques_exfiltration:            String,
    pub percent_techniques_impact:                  String,    
    // Percentage Subtechniques By KillChain/Tactic
    pub percent_subtechniques_initial_access:          String,
    pub percent_subtechniques_execution:               String,
    pub percent_subtechniques_persistence:             String,
    pub percent_subtechniques_privilege_escalation:    String,
    pub percent_subtechniques_defense_evasion:         String,
    pub percent_subtechniques_credential_access:       String,
    pub percent_subtechniques_discovery:               String,
    pub percent_subtechniques_lateral_movement:        String,
    pub percent_subtechniques_collection:              String,
    pub percent_subtechniques_command_and_control:     String,
    pub percent_subtechniques_exfiltration:            String,
    pub percent_subtechniques_impact:                  String,     
}
impl EnterpriseMatrixStatistics {
    pub fn new() -> Self
    {
        EnterpriseMatrixStatistics {
            count_revoked_techniques:           0,
            count_deprecated_techniques:        0,
            count_active_total_techniques:      0,
            count_active_total_subtechniques:   0,
            count_active_uniq_techniques:       0,
            count_active_uniq_subtechniques:    0,
            count_malwares:                     0,
            count_adversaries:                  0,
            count_tools:                        0,
            count_platforms:                    0,
            count_tactics:                      0,
            count_datasources:                  0,
            count_techniques_aws:               0,
            count_techniques_azure:             0,
            count_techniques_azure_ad:          0,
            count_techniques_gcp:               0,
            count_techniques_linux:             0,
            count_techniques_macos:             0,
            count_techniques_office365:         0,
            count_techniques_saas:              0,
            count_techniques_windows:           0,
            count_subtechniques_aws:            0,
            count_subtechniques_azure:          0,
            count_subtechniques_azure_ad:       0,
            count_subtechniques_gcp:            0,
            count_subtechniques_linux:          0,
            count_subtechniques_macos:          0,
            count_subtechniques_office365:      0,
            count_subtechniques_saas:           0,
            count_subtechniques_windows:        0,
            count_techniques_initial_access:    0,
            count_techniques_execution:         0,
            count_techniques_persistence:       0,
            count_techniques_privilege_escalation: 0,
            count_techniques_defense_evasion:   0,
            count_techniques_credential_access: 0,
            count_techniques_collection:        0,
            count_techniques_discovery:         0,
            count_techniques_lateral_movement:  0,
            count_techniques_command_and_control: 0,
            count_techniques_exfiltration:         0,
            count_techniques_impact:               0,
            count_subtechniques_initial_access:    0,
            count_subtechniques_execution:         0,
            count_subtechniques_persistence:       0,
            count_subtechniques_privilege_escalation: 0,
            count_subtechniques_defense_evasion:   0,
            count_subtechniques_credential_access: 0,
            count_subtechniques_collection:        0,
            count_subtechniques_discovery:         0,
            count_subtechniques_lateral_movement:  0,
            count_subtechniques_command_and_control: 0,
            count_subtechniques_exfiltration:      0,
            count_subtechniques_impact:            0,
            // Percentages
            // Percentage Techniques By Platform
            percent_techniques_aws:          String::from(""),
            percent_techniques_azure:        String::from(""),
            percent_techniques_azure_ad:     String::from(""),
            percent_techniques_gcp:          String::from(""),
            percent_techniques_linux:        String::from(""),
            percent_techniques_macos:        String::from(""),
            percent_techniques_office365:   String::from(""),
            percent_techniques_saas:         String::from(""),
            percent_techniques_windows:      String::from(""),
            // Percentage Subtechniques By Platform            
            percent_subtechniques_aws:          String::from(""),
            percent_subtechniques_azure:        String::from(""),
            percent_subtechniques_azure_ad:     String::from(""),
            percent_subtechniques_gcp:          String::from(""),
            percent_subtechniques_linux:        String::from(""),
            percent_subtechniques_macos:        String::from(""),
            percent_subtechniques_office365:    String::from(""),
            percent_subtechniques_saas:         String::from(""),
            percent_subtechniques_windows:      String::from(""),
            // Percentage Technique By KillChain
            percent_techniques_initial_access:          String::from(""),
            percent_techniques_execution:               String::from(""),
            percent_techniques_persistence:             String::from(""),
            percent_techniques_privilege_escalation:    String::from(""),
            percent_techniques_defense_evasion:         String::from(""),
            percent_techniques_credential_access:       String::from(""),
            percent_techniques_discovery:               String::from(""),
            percent_techniques_lateral_movement:        String::from(""),
            percent_techniques_collection:              String::from(""),
            percent_techniques_command_and_control:     String::from(""),
            percent_techniques_exfiltration:            String::from(""),
            percent_techniques_impact:                  String::from(""),
            // Percentage Subtechniques By KillChain/Tactic
            percent_subtechniques_initial_access:          String::from(""),
            percent_subtechniques_execution:               String::from(""),
            percent_subtechniques_persistence:             String::from(""),
            percent_subtechniques_privilege_escalation:    String::from(""),
            percent_subtechniques_defense_evasion:         String::from(""),
            percent_subtechniques_credential_access:       String::from(""),
            percent_subtechniques_discovery:               String::from(""),
            percent_subtechniques_lateral_movement:        String::from(""),
            percent_subtechniques_collection:              String::from(""),
            percent_subtechniques_command_and_control:     String::from(""),
            percent_subtechniques_exfiltration:            String::from(""),
            percent_subtechniques_impact:                  String::from(""),                                      
        }
    }
}


#[derive(Debug,Deserialize, Serialize)]
pub struct EnterpriseTechniquesByPlatform {
    pub count:      usize,
    pub platforms:  Vec<EnterpriseTechnique>
}
impl EnterpriseTechniquesByPlatform {
    pub fn new() -> Self
    {
        EnterpriseTechniquesByPlatform {
            platforms:  vec![],
            count:      0
        }
    }
    pub fn update_count(&mut self)
    {
        self.count = self.platforms.len();
    }
}


#[derive(Debug,Deserialize, Serialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EnterpriseTechnique {
    pub id:             String,
    pub platform:       String,
    pub tid:            String,
    pub technique:      String,
    pub tactic:         String,
    pub datasources:    String,
    pub has_subtechniques: bool,
    pub is_deprecated:  bool,
    pub is_revoked:     bool,
    pub subtechniques:  Vec<String>,
    pub count_subtechniques: usize
}
impl EnterpriseTechnique {
    pub fn new() -> Self
    {
        EnterpriseTechnique {
            id:                 String::from(""),
            platform:           String::from("n_a"),
            tid:                String::from(""),
            technique:          String::from(""),
            tactic:             String::from("n_a"),
            datasources:        String::from("n_a"),
            has_subtechniques:  false,
            is_deprecated:      false,
            is_revoked:         false,
            subtechniques:      vec![],
            count_subtechniques: 0usize
        }
    }
    pub fn update(&mut self)
    {
        self.count_subtechniques = self.subtechniques.len();
    }
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct EnterpriseRevokedItem {
    pub id:         String,
    pub name:       String,
    pub eid:        String,     // T1234,S01234,etc
    pub is_revoked: bool,
    pub new_id:     String,
    pub new_name:   String,
    pub new_eid:    String
}
impl EnterpriseRevokedItem {
    pub fn new() -> Self
    {
        EnterpriseRevokedItem {
            id:         "".to_string(),
            name:       "".to_string(),
            eid:        "".to_string(),
            is_revoked: true,
            new_id:     "".to_string(),
            new_eid:    "".to_string(),
            new_name:   "".to_string()
        }
    }
}

#[derive(Debug,Deserialize, Serialize)]
pub struct EnterpriseSubtechniquesByPlatform {
    pub count:      usize,
    pub platforms:  Vec<EnterpriseTechnique>
}
impl EnterpriseSubtechniquesByPlatform {
    pub fn new() -> Self
    {
        EnterpriseSubtechniquesByPlatform {
            count:     0,
            platforms: vec![]
        }
    }
    pub fn update_count(&mut self) {
        self.count = self.platforms.len();
    }
}


#[derive(Debug,Deserialize, Serialize)]
pub struct EnterpriseTechniquesByTactic {
    pub count:  usize,
    pub tactic: EnterpriseTactic  
}
impl EnterpriseTechniquesByTactic {
    pub fn new(tactic_name: &str) -> Self
    {
        EnterpriseTechniquesByTactic {
            count:  0,
            tactic: EnterpriseTactic::new(tactic_name)
        }
    }
}


#[derive(Debug,Deserialize, Serialize)]
pub struct EnterpriseTactic {
    pub name:   String,
    pub items:  Vec<String>
}
impl EnterpriseTactic {
    pub fn new(tactic_name: &str) -> Self
    {
        EnterpriseTactic {
            name: tactic_name.to_string(),
            items: vec![]
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct EnterpriseAdversary {
    pub id:         String,
    pub name:       String,
    pub aliases:    String,
    pub group_id:   String,
    pub is_revoked: bool,
    pub profile:    EnterpriseAdversaryProfile,
}
impl EnterpriseAdversary {
    pub fn new() -> Self
    {
        EnterpriseAdversary {
            id:         "none".to_string(),
            name:       "none".to_string(),
            aliases:    "none".to_string(),
            group_id:   "none".to_string(),
            is_revoked: false,
            profile:    EnterpriseAdversaryProfile::new()
        }
    }
    pub fn update(&mut self)
    {
        self.profile.update();
    }
}


#[derive(Debug, Deserialize, Serialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EnterpriseAdversaryProfile {
    pub malware:        EnterpriseProfileEntry,
    pub tools:          EnterpriseProfileEntry,
    pub techniques:     EnterpriseProfileEntry,
    pub subtechniques:  EnterpriseProfileEntry,
    pub tactics:        EnterpriseProfileEntry
}
impl EnterpriseAdversaryProfile {
    pub fn new() -> Self
    {
        EnterpriseAdversaryProfile {
            malware:        EnterpriseProfileEntry::new(),
            tools:          EnterpriseProfileEntry::new(),
            techniques:     EnterpriseProfileEntry::new(),
            subtechniques:  EnterpriseProfileEntry::new(),
            tactics:        EnterpriseProfileEntry::new(),
        }
    }
    pub fn update(&mut self)
    {
        self.malware.update();
        self.tools.update();
        self.techniques.update();
        self.subtechniques.update();
        self.tactics.update();
    }
}


#[derive(Debug, Deserialize, Serialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EnterpriseProfileEntry {
    pub count: usize,
    pub items: Vec<String>
}
impl EnterpriseProfileEntry {
    pub fn new() -> Self
    {
        EnterpriseProfileEntry {
            count: 0,
            items: vec![]
        }
    }
    pub fn update(&mut self)
    {
        self.items.sort();
        self.items.dedup();
        self.items.sort();
        self.count = self.items.len();
    }
}


#[derive(Debug, Deserialize, Serialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EnterpriseTool {
    pub id:         String,
    pub name:       String,
    pub aliases:    String,
    pub platforms:  String,
    pub tool_id:    String,
    pub is_revoked: bool,
    pub profile:    EnterpriseToolProfile,

}
impl EnterpriseTool {
    pub fn new() -> Self
    {
        EnterpriseTool {
            id:         "none".to_string(),
            name:       "none".to_string(),
            aliases:    "none".to_string(),
            platforms:  "none".to_string(),
            tool_id:    "none".to_string(),
            is_revoked: false,
            profile:    EnterpriseToolProfile::new()
        }
    }
    pub fn update(&mut self)
    {
        self.profile.update();
    }
}


#[derive(Debug, Deserialize, Serialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EnterpriseToolProfile {
    pub tactics:        EnterpriseProfileEntry,
    pub techniques:     EnterpriseProfileEntry,
    pub subtechniques:  EnterpriseProfileEntry,
    pub adversaries:    EnterpriseProfileEntry
}
impl EnterpriseToolProfile {
    pub fn new() -> Self
    {
        EnterpriseToolProfile {
            tactics:        EnterpriseProfileEntry::new(),
            techniques:     EnterpriseProfileEntry::new(),
            subtechniques:  EnterpriseProfileEntry::new(),
            adversaries:    EnterpriseProfileEntry::new()
        }
    }
    pub fn update(&mut self)
    {
        self.tactics.update();
        self.techniques.update();
        self.subtechniques.update();
        self.adversaries.update();
    }
}


#[derive(Debug, Deserialize, Serialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EnterpriseMalware {
    pub id:         String,
    pub name:       String,
    pub aliases:    String,
    pub platforms:  String,
    pub malware_id: String,
    pub is_revoked: bool,
    pub profile:    EnterpriseMalwareProfile
}
impl EnterpriseMalware {
    pub fn new() -> Self
    {
        EnterpriseMalware {
            id:         "none".to_string(),
            name:       "none".to_string(),
            aliases:    "none".to_string(),
            platforms:  "none".to_string(),
            malware_id: "none".to_string(),
            is_revoked: false,
            profile:    EnterpriseMalwareProfile::new()
        }
    }
}


#[derive(Debug, Deserialize, Serialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EnterpriseMalwareProfile {
    pub tactics:        EnterpriseProfileEntry,
    pub techniques:     EnterpriseProfileEntry,
    pub subtechniques:  EnterpriseProfileEntry,
    pub adversaries:    EnterpriseProfileEntry
}
impl EnterpriseMalwareProfile {
    pub fn new() -> Self
    {
        EnterpriseMalwareProfile {
            tactics:        EnterpriseProfileEntry::new(),
            techniques:     EnterpriseProfileEntry::new(),
            subtechniques:  EnterpriseProfileEntry::new(),
            adversaries:    EnterpriseProfileEntry::new()
        }
    }
    pub fn update(&mut self)
    {
        self.tactics.update();
        self.techniques.update();
        self.subtechniques.update();
        self.adversaries.update();
    }
}


#[derive(Debug, Deserialize, Serialize)]
pub struct EnterpriseRelationships {
    pub adversary_to_malware:       HashSet<EnterpriseRelationship>,
    pub adversary_to_techniques:    HashSet<EnterpriseRelationship>,
    pub adversary_to_tools:         HashSet<EnterpriseRelationship>,
    pub malware_to_techniques:      HashSet<EnterpriseRelationship>,
    pub tool_to_techniques:         HashSet<EnterpriseRelationship>,
    pub old_to_new_techniques:      HashSet<EnterpriseRelationship>
}
impl EnterpriseRelationships {
    pub fn new() -> Self
    {
        EnterpriseRelationships {
            adversary_to_malware:       HashSet::new(),
            adversary_to_techniques:    HashSet::new(),
            adversary_to_tools:         HashSet::new(),
            malware_to_techniques:      HashSet::new(),
            tool_to_techniques:         HashSet::new(),
            old_to_new_techniques:      HashSet::new()
        }
    }
}


#[derive(Debug, Deserialize, Serialize, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct EnterpriseRelationship {
    pub id:             String,
    pub relation_type:  String,
    pub source:         String,
    pub target:         String,
}
impl EnterpriseRelationship {
    pub fn new() -> Self
    {
        EnterpriseRelationship {
            id:             "none".to_string(),
            relation_type:  "none".to_string(),
            source:         "none".to_string(),
            target:         "none".to_string()
        }
    }
}