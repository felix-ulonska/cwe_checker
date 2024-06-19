use super::prelude::*;

use crate::intermediate_representation::Arg as IrArg;

const APPLICABLE_SYMBOLS: [&str; 4] = ["scanf", "sscanf", "__isoc99_scanf", "__isoc99_sscanf"];
const SSCANF_SYMBOLS: [&str; 2] = ["sscanf", "__isoc99_sscanf"];

pub const DOMAIN_KNOWLEDGE: ExternalSymbolDomainKnowledge = ExternalSymbolDomainKnowledge {
    applicable_symbols: &APPLICABLE_SYMBOLS,
    apply_domain_knowledge_fp: apply_domain_knowledge_to,
};

fn apply_domain_knowledge_to(
    ir_extern_symbol: &mut IrExternSymbol,
    pcode_project: &PcodeProject,
) -> bool {
    let should_stop = true;

    ir_extern_symbol.no_return = false;
    ir_extern_symbol.has_var_args = true;

    if ir_extern_symbol.parameters.is_empty() {
        let ir_expr_sp = pcode_project.stack_pointer_register.to_ir_expr();
        let cconv = pcode_project
            .calling_conventions
            .get(ir_extern_symbol.calling_convention.as_ref().unwrap())
            .unwrap();
        let mut parameters: Vec<IrArg> = Vec::new();

        // TODO: Test that this is indeed on the stack for x86.
        // TODO: Insert domain knowledge about parameter type.
        let param0 = cconv
            .get_integer_parameter_register(0)
            .unwrap()
            .to_ir_arg(&ir_expr_sp);
        parameters.push(param0);

        if SSCANF_SYMBOLS.contains(&ir_extern_symbol.name.as_str()) {
            let param1 = cconv
                .get_integer_parameter_register(1)
                .unwrap()
                .to_ir_arg(&ir_expr_sp);
            parameters.push(param1);
        }

        ir_extern_symbol.parameters = parameters;
    }

    should_stop
}
