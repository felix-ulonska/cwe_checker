//! Varnodes.

use super::RegisterName;

use crate::intermediate_representation::{
    Arg as IrArg, BitvectorExtended, ByteSize, Def as IrDef, Expression as IrExpression,
    Variable as IrVariable,
};
use crate::prelude::*;

use std::convert::From;
use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};

/// A varnode.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Varnode {
    /// Size of the varnode.
    size: u64,
    /// Address space of the varnode.
    address_space: AddressSpace,
    /// Offset (value) in address space.
    address_space_offset: String,
    /// Size of a pointer in bytes.
    ///
    /// Needed to translate offsets into RAM address space to constants.
    pointer_size: u64,
    /// If the varnode is associated with a named CPU register, this can be used
    /// to obtain its [`RegisterProperties`](super::RegisterProperties).
    register_name: Option<RegisterName>,
    /// If the varnode is associated with a named CPU register, this can be used
    /// to obtain the size of this register.
    // Note: Shortcut to avoid passing the register map down to the IR
    // translation functions.
    register_size: Option<u64>,
}

impl Display for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}]:{}",
            self.address_space, self.address_space_offset, self.size
        )
    }
}

/// The address space of a varnode.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "lowercase")]
enum AddressSpace {
    Ram,
    Const,
    Register,
    Unique,
    Stack,
}

impl<T: AsRef<str>> From<T> for AddressSpace {
    fn from(s: T) -> AddressSpace {
        match s.as_ref() {
            "ram" => AddressSpace::Ram,
            "const" => AddressSpace::Const,
            "register" => AddressSpace::Register,
            "unique" => AddressSpace::Register,
            "stack" => AddressSpace::Stack,
            _ => panic!(),
        }
    }
}

impl Display for AddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AddressSpace::*;
        match self {
            Ram => write!(f, "Ram"),
            Const => write!(f, "Const"),
            Register => write!(f, "Register"),
            Unique => write!(f, "Unique"),
            Stack => write!(f, "Stack"),
        }
    }
}

impl Varnode {
    /// Translates this varnode to an IR function argument or return value.
    pub fn to_ir_arg(&self, ir_expr_sp: &IrExpression) -> IrArg {
        match &self.address_space {
            AddressSpace::Stack => IrArg::Stack {
                address: ir_expr_sp.clone().plus_const(self.to_sp_offset()),
                size: ByteSize::new(self.size()),
                data_type: None,
            },
            AddressSpace::Register => IrArg::from_var(self.to_ir_var(), None),
            _ => panic!("Varnode can not be translated to argument."),
        }
    }

    /// Returns the offset into the stack address space.
    ///
    /// Panics if this varnode is not in the stack address space.
    fn to_sp_offset(&self) -> i64 {
        assert!(matches!(self.address_space, AddressSpace::Stack));

        if let Ok(sp_offset) = u64::from_str_radix(
            self.address_space_offset
                .trim_start_matches("0xStack[0x")
                .trim_end_matches("]"),
            16,
        ) {
            return sp_offset as i64;
        }
        if let Ok(sp_offset) = u64::from_str_radix(
            self.address_space_offset
                .trim_start_matches("0xStack[-0x")
                .trim_end_matches("]"),
            16,
        ) {
            return -(sp_offset as i64);
        }

        panic!(
            "Unable to parse offset into stack address space: {}",
            self.address_space_offset
        );
    }

    /// Translates into [`IrExpression::Const`] for constants or
    /// [`IrExpression::Var`] for registers or virtual registers.
    ///
    /// Panics if the address space is neither `"const"`, `"register"`
    /// nor `"unique"`.
    pub fn to_ir_expr(&self) -> IrExpression {
        match self.address_space {
            AddressSpace::Const => IrExpression::Const(self.to_const()),
            AddressSpace::Unique | AddressSpace::Register => IrExpression::Var(self.to_ir_var()),
            AddressSpace::Ram | AddressSpace::Stack => {
                panic!("Varnode translation failed: {}", self)
            }
        }
    }

    /// Translates a varnode with the "const" address space into the bitvector
    /// constant it represents.
    ///
    /// Panics if this varnode is not in the const address space.
    fn to_const(&self) -> Bitvector {
        assert!(self.is_in_const());

        // FIXME: Does Ghidra produce constants larger than 8 bytes?
        // If yes, they could be parsed incorrectly by the current
        // implementation.
        let constant = Bitvector::from_u64(
            u64::from_str_radix(self.address_space_offset.trim_start_matches("0x"), 16).unwrap(),
        );
        constant.into_resize_unsigned(self.size.into())
    }

    /// Returns the address space offset of this varnode.
    ///
    /// Panics if this varnode is in the stack address space.
    pub fn address_space_offset(&self) -> u64 {
        assert!(!self.is_in_stack());

        u64::from_str_radix(self.address_space_offset.trim_start_matches("0x"), 16).unwrap()
    }

    /// Translates a varnode within the "register" or "unique" address spaces
    /// into a (regular or temporary) variable.
    ///
    /// Returns None IFF the varnode is NOT in the Register or Unique Address
    /// Space.
    pub fn try_to_ir_var(&self) -> Option<IrVariable> {
        match self.address_space {
            AddressSpace::Register => Some(IrVariable {
                name: {
                    match &self.register_name {
                        // Note: The fact that Ghidra associated a varnode
                        // with a register name is not sufficient to conclude
                        // that it corresponds to the register. This happens if
                        // a varnode corresponds only to some LSBs of a
                        // register.
                        Some(register_name) if self.register_size.unwrap() == self.size => {
                            register_name.to_string()
                        }
                        _ => format!(
                            "{}{}",
                            IrVariable::UNNAMED_SUBREG_PREFIX,
                            self.address_space_offset
                        ),
                    }
                },
                size: ByteSize::new(self.size),
                is_temp: false,
            }),
            AddressSpace::Unique => Some(IrVariable {
                name: format!(
                    "{}{}",
                    IrVariable::TMP_REG_PREFIX,
                    self.address_space_offset
                ),
                size: ByteSize::new(self.size),
                is_temp: true,
            }),
            AddressSpace::Const | AddressSpace::Ram | AddressSpace::Stack => None,
        }
    }

    /// Translates a varnode within the "register" or "unique" address spaces
    /// into a (regular or temporary) variable.
    pub fn to_ir_var(&self) -> IrVariable {
        match self.try_to_ir_var() {
            Some(v) => v,
            None => {
                panic!(
                    "Attempt to convert non Register or Unique Varnode to IR variable: {}",
                    self
                )
            }
        }
    }

    /// Returns `Bitvector` representing a constant address in ram, if
    /// the varnode represents such address.
    pub fn get_ram_address(&self) -> Option<Bitvector> {
        if self.is_in_ram() {
            let offset = Bitvector::from_u64(
                u64::from_str_radix(self.address_space_offset.trim_start_matches("0x"), 16)
                    .unwrap_or_else(|_| panic!("Cannot parse {}", &self.address_space_offset)),
            );

            Some(offset.into_resize_unsigned(self.pointer_size.into()))
        } else {
            None
        }
    }

    /// Return the string representing a constant address in RAM,
    /// if the varnode represents such an address.
    pub fn get_ram_address_as_string(&self) -> Option<&str> {
        if self.is_in_ram() {
            Some(&self.address_space_offset)
        } else {
            None
        }
    }

    /// Returns [`IrDef::Load`], if the varnode describes an implicit load
    /// operation.
    ///
    /// Changes the varnode's `id` and `address_space` to the virtual variable.
    ///
    /// Panics, if varnode's address_space is not `ram`
    pub fn make_explicitly_loaded_var_and_return_ir_def_load<T: ToString + ?Sized>(
        &mut self,
        var_name: &T,
    ) -> IrDef {
        let load_address = IrExpression::Const(
            self.get_ram_address()
                .expect("Varnode's address space is not ram."),
        );

        // Change varnode to newly introduced explicit variable.
        self.address_space_offset = var_name.to_string();
        self.address_space = AddressSpace::Unique;

        IrDef::Load {
            var: self.to_ir_var(),
            address: load_address,
        }
    }

    /// Returns true iff this varnode is in the RAM address space.
    pub fn is_in_ram(&self) -> bool {
        matches!(self.address_space, AddressSpace::Ram)
    }

    /// Returns true iff this varnode is in the const address space.
    pub fn is_in_const(&self) -> bool {
        matches!(self.address_space, AddressSpace::Const)
    }

    /// Returns true iff this varnode is in the unique address space.
    pub fn is_in_unique(&self) -> bool {
        matches!(self.address_space, AddressSpace::Unique)
    }

    /// Returns true iff this varnode is in the register address space.
    pub fn is_in_register(&self) -> bool {
        matches!(self.address_space, AddressSpace::Register)
    }

    /// Returns true iff this varnode is in the stack address space.
    pub fn is_in_stack(&self) -> bool {
        matches!(self.address_space, AddressSpace::Stack)
    }

    /// Returns the size of this varnode.
    pub fn size(&self) -> u64 {
        self.size
    }
}

// TODO: Fix tests.
/*
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{bitvec, variable};

    impl Varnode {
        /// Mock a varnode via a string on the form `AddressSpace_Id_Size`. Examples:
        /// - `register_RSP_8` for the `RAX` register.
        /// - `const_0x1_4` for a 4-byte-constant with value 1.
        pub fn mock(varnode: &str) -> Self {
            let components: Vec<_> = varnode.trim().split("_").collect();
            assert_eq!(components.len(), 3);
            for elem in &components {
                assert_eq!(*elem, elem.trim());
            }
            Varnode {
                address_space: components[0].into(),
                address_space_offset: components[1].to_string(),
                size: u64::from_str_radix(components[2], 10).unwrap(),
                // TODO: Fix tests.
                register_name: None,
                register_size: None,
            }
        }
    }

    #[test]
    fn test_varnode_mock() {
        let mock = Varnode::mock("const_0x1_16");
        let expected_varnode = Varnode {
            address_space: "const".into(),
            address_space_offset: "0x1".to_string(),
            size: 16,
            register_name: None,
            register_size: None,
        };
        assert_eq!(mock, expected_varnode);
    }

    #[test]
    fn test_varnode_into_const() {
        assert_eq!(
            Varnode::mock("const_0x0_8").to_ir_expr(),
            Expression::Const(bitvec!("0x0:8"))
        );
        assert_eq!(
            Varnode::mock("const_0x42_4").to_ir_expr(),
            Expression::Const(bitvec!("0x42:4"))
        );
        assert_eq!(
            Varnode::mock("const_0xFFFFFFFF_4").to_ir_expr(),
            Expression::Const(bitvec!("0x-1:4"))
        );
    }

    #[test]
    fn test_varnode_into_var() {
        assert_eq!(
            Varnode::mock("register_RSP_8").to_ir_expr(),
            Expression::Var(variable!("RSP:8"))
        );
    }

    #[test]
    fn test_varnode_into_temp_var() {
        assert_eq!(
            Varnode::mock("unique_virtual_8").to_ir_expr(),
            Expression::Var(Variable {
                name: "$U_virtual".into(),
                size: 8.into(),
                is_temp: true
            })
        );
    }

    #[test]
    #[should_panic]
    fn test_varnode_alternative_address_space() {
        Varnode::mock("something_id_8").to_ir_expr();
    }

    #[test]
    fn test_varnode_into_ram_address() {
        assert_eq!(
            Varnode::mock("ram_0xFF11_8").get_ram_address(),
            Some(bitvec!("0xFF11:8"))
        );
        assert_eq!(Varnode::mock("something_0xFF11_8").get_ram_address(), None);
    }
}
*/
