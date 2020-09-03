fn search_by_adversary(&self, adversary: &str, many: Vec<usize>) -> String {
    let mut _results = vec![];
    let adversary = adversary.to_lowercase();
    let adversary = adversary.as_str();
    let _err = format!(
        "(?) Error: Unable To Deserialize String of All Techniques by Adversary: {}",
        adversary
    );
    let _json: EnterpriseMatrixBreakdown =
        serde_json::from_slice(&self.content[..]).expect(_err.as_str());
    if many.len() == 1 {
        for _item in _json.breakdown_adversaries.iter() {
            if _item.name.to_lowercase().as_str() == adversary {
                _results.push(_item);
            }
        }
    } else {
        if adversary.contains(",") {
            let _terms: Vec<_> = adversary.split(',').collect();
            for _term in _terms {
                for _item in _json.breakdown_adversaries.iter() {
                    if _item.name.to_lowercase().as_str() == _term {
                        _results.push(_item);
                    }
                }
            }
        }
    }
    //println!("{}", serde_json::to_string_pretty(&_results).unwrap());
    let _err = format!(
        "(?) Error: Unable To Convert String of All Techniques by Adversary: {}",
        adversary
    );
    serde_json::to_string(&_results).expect(_err.as_str())
}