use crate::ghidra_pcode::{PcodeProject, Varnode};
use crate::intermediate_representation::{ExternSymbol as IrExternSymbol, Tid};

use serde::{Deserialize, Serialize};

mod domain_knowledge;
use domain_knowledge::apply_domain_knowledge_to;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ExternFunction {
    name: String,
    calling_convention: String,
    parameters: Vec<Varnode>,
    return_location: Option<Varnode>,
    thunks: Vec<String>,
    has_no_return: bool,
    has_var_args: bool,
}

impl ExternFunction {
    pub fn to_ir_extern_symbol(&self, pcode_project: &PcodeProject) -> IrExternSymbol {
        let ir_expr_sp = pcode_project.stack_pointer_register.to_ir_expr();
        let mut ir_extern_symbol = IrExternSymbol {
            tid: Tid::new_external_function(&self.name),
            addresses: self.thunks.to_owned(),
            name: self.name.clone(),
            calling_convention: Some(self.calling_convention.clone()),
            parameters: self
                .parameters
                .iter()
                .map(|vn| vn.to_ir_arg(&ir_expr_sp))
                .collect(),
            return_values: self
                .return_location
                .as_ref()
                .map(|vn| vec![vn.to_ir_arg(&ir_expr_sp)])
                .unwrap_or_default(),
            no_return: self.has_no_return,
            has_var_args: self.has_var_args,
        };

        apply_domain_knowledge_to(&mut ir_extern_symbol, pcode_project);

        ir_extern_symbol
    }
}
