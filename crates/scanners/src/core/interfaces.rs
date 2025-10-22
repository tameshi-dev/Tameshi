
pub trait InheritanceProvider {
    fn get_parents(&self, contract: &str) -> Vec<String>;

    fn get_all_ancestors(&self, contract: &str) -> Vec<String>;

    fn inherits_from(&self, child: &str, parent: &str) -> bool;
}

pub trait StateVariableProvider {
    fn has_state_variable(&self, contract: &str, var_name: &str) -> bool;

    fn get_variable_type(&self, contract: &str, var_name: &str) -> Option<String>;
}

pub trait FunctionProvider {
    fn get_functions(&self, contract: &str) -> Vec<&FunctionInfo>;

    fn get_function(&self, contract: &str, signature: &str) -> Option<&FunctionInfo>;

    fn has_function(&self, contract: &str, name: &str) -> bool;
}

pub trait UnifiedAnalysisProvider:
    InheritanceProvider + StateVariableProvider + FunctionProvider
{
    fn get_contracts(&self) -> Vec<String>;

    fn get_main_contract(&self) -> String;
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub signature: String,
    pub visibility: String,
    pub modifiers: Vec<String>,
    pub state_mutability: Option<String>,
}
