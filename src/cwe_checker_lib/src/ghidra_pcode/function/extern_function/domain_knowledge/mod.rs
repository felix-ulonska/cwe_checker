mod scanf_sscanf;

mod prelude {
    pub use super::ExternalSymbolDomainKnowledge;
    pub use crate::ghidra_pcode::PcodeProject;
    pub use crate::intermediate_representation::ExternSymbol as IrExternSymbol;
}
use prelude::*;

const AVAILABLE_DOMAIN_KNOWLEDGE: [ExternalSymbolDomainKnowledge; 1] =
    [scanf_sscanf::DOMAIN_KNOWLEDGE];

pub struct ExternalSymbolDomainKnowledge {
    applicable_symbols: &'static [&'static str],
    apply_domain_knowledge_fp: fn(&mut IrExternSymbol, &PcodeProject) -> bool,
}

impl ExternalSymbolDomainKnowledge {
    fn is_applicable_to(&self, ir_extern_symbol: &IrExternSymbol) -> bool {
        self.applicable_symbols
            .contains(&ir_extern_symbol.name.as_str())
    }

    fn apply_domain_knowledge_to(
        &self,
        ir_extern_symbol: &mut IrExternSymbol,
        pcode_project: &PcodeProject,
    ) -> bool {
        let fp = self.apply_domain_knowledge_fp;

        fp(ir_extern_symbol, pcode_project)
    }
}

pub fn apply_domain_knowledge_to(
    ir_extern_symbol: &mut IrExternSymbol,
    pcode_project: &PcodeProject,
) {
    for domain_knowledge in AVAILABLE_DOMAIN_KNOWLEDGE.iter() {
        if !domain_knowledge.is_applicable_to(ir_extern_symbol) {
            continue;
        }
        if domain_knowledge.apply_domain_knowledge_to(ir_extern_symbol, pcode_project) {
            break;
        }
    }
}
