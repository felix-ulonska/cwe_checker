use serde::Serialize;

use crate::intermediate_representation::{Jmp, Program};

#[derive(Serialize, Debug)]
pub struct Call {
    pub from_instr: u64,
    pub to_instr: u64,
    pub is_indirect: bool,
}

#[derive(Serialize, Debug)]
pub struct Metadata {
    pub address_base_offset: u64,
    pub indirect_call_sites: Vec<u64>,
}

#[derive(Serialize, Debug)]
pub struct ExportCallGraph {
    pub metadata: Metadata,
    pub calls: Vec<Call>,
}

/// Exports the callgraph to json, also if a call is indirect or direct
pub fn export_json(program: &Program) {
    let mut indirect_call_sites: Vec<u64> = vec![];

    let mut calls = vec![];

    //program
    //    .subs
    //    .iter()
    //    .for_each(|sub| println!("{}", sub.1.name));

    for blk in program.blocks() {
        for jmp in blk.jmps() {
            if let Jmp::Call { target, .. } = &jmp.term {
                // Target address is unknown if function is external
                if target.address().is_unknown() {
                    continue;
                }
                calls.push(Call {
                    from_instr: jmp
                        .tid
                        .address()
                        .try_into()
                        .expect(&format!("Call should have addr, {}", jmp.tid)),
                    // If this panics, we test that some lines above
                    to_instr: target.address().try_into().unwrap(),
                    is_indirect: false,
                })
            }
            if let Jmp::CallInd { .. } = &jmp.term {
                if let Some(call_targets) = blk.ind_call_targets() {
                    let call_targets = call_targets.map(|call_target| Call {
                        from_instr: jmp.tid.address().try_into().expect("Call should have addr"),
                        to_instr: call_target
                            .address()
                            .try_into()
                            .expect(&format!("Target should have addr, {}", call_target)),
                        is_indirect: true,
                    });
                    calls.extend(call_targets);
                }
                indirect_call_sites.push(jmp.tid.address().try_into().unwrap());
            }
        }
    }

    let metadata = Metadata {
        address_base_offset: program.address_base_offset,
        indirect_call_sites,
    };

    let call_graph = ExportCallGraph { metadata, calls };
    println!(
        "{}",
        serde_json::to_string(&call_graph).expect("Could not create json")
    );
}
