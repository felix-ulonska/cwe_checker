use crate::ghidra_pcode::Varnode;
use crate::intermediate_representation::{
    BinOpType as IrBinOpType, ByteSize, Expression as IrExpression, Variable as IrVariable,
};

use std::collections::{BTreeSet, HashMap};
use std::convert::From;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// Description of a named CPU register.
///
/// Each element in the sub-poset of named registers has such a description.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RegisterProperties {
    /// Unique identifier of this register.
    ///
    /// In the following called `r`.
    register_name: RegisterName,
    /// The largest register that contains (equality included) this register.
    ///
    /// aka `base(r)`
    base_register: RegisterName,
    /// Smallest register that properly contains the register.
    ///
    /// aka `parent(r)`
    parent_register: Option<RegisterName>,
    /// All registers properly contained within this register.
    ///
    /// aka. { r' | parent(r') == r and r' in R }
    children: Vec<RegisterName>,
    /// Distance between the least significant byte of this register and the
    /// base register's in bytes.
    lsbyte_in_base: u64,
    /// Size of a varnode for this register.
    size: u64,
    /// Offset into the Register Address Space of the first byte of this
    /// register.
    address_space_offset: u64,
    /// Full bytes in the Register Address Space that are "touched" by this
    /// register.
    bytes_spanned: u64,
    /// Size of the register in bits.
    bit_length: u64,
    /// Boolean indicating whether reads from this register will always return
    /// zero.
    is_zero: bool,
    /// Boolean indicating whether this is a processor status register, as
    /// opposed to a general purpose register.
    is_processor_context: bool,
    /// Equivalent to `register_name` == `base_register`.
    ///
    /// aka. `r == base(r)`
    is_base_register: bool,
    /// True iff the MSB is at the lowest address.
    is_big_endian: bool,
}

impl From<&RegisterProperties> for IrVariable {
    fn from(reg: &RegisterProperties) -> Self {
        Self {
            name: reg.register_name.to_string(),
            size: ByteSize::new(reg.size),
            is_temp: false,
        }
    }
}

impl RegisterProperties {
    /// True iff `size` bytes starting at `offset` into the Register Address
    /// Space are contained within this register.
    fn contains_offset_size(&self, offset: u64, size: u64) -> bool {
        self.address_space_offset <= offset
            && self.address_space_offset + self.size >= offset + size
    }

    /// Returns the size of a varnode for this register.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// True iff the MSB is at the lowest address.
    pub fn is_big_endian(&self) -> bool {
        self.is_big_endian
    }

    /// Returns the IR VARIABLE expression that corresponds to this named
    /// register.
    pub fn to_ir_expr(&self) -> IrExpression {
        IrExpression::Var(self.to_ir_var())
    }

    /// Returns the IR variable that corresponds to this named register.
    pub fn to_ir_var(&self) -> IrVariable {
        self.into()
    }
}

/// Type to represent elements in `Ext(R)`.
///
/// The representation of `r in Ext(R)` by instances of this type is not unique.
/// The canonical representation is the one slicing `base(r)`.
pub struct RegisterSlice<'a> {
    /// Beginning of the slice relative to the low-address of the sliced
    /// register.
    start: u64,
    /// Length of the slice.
    len: u64,
    /// Register that is being sliced.
    register: &'a RegisterProperties,
}

impl<'a> RegisterSlice<'a> {
    /// True iff this is the trivial slice.
    pub fn is_full(&self) -> bool {
        self.len == self.register.size
    }

    /// True iff this is a proper slice.
    pub fn is_proper(&self) -> bool {
        !self.is_full()
    }

    /// Returns the sliced register.
    pub fn register(&self) -> &'a RegisterProperties {
        self.register
    }

    /// Returns the IR SUBPIECE expression that corresponds to this register
    /// slice.
    pub fn to_ir_subpiece_expr(&self) -> IrExpression {
        IrExpression::Subpiece {
            low_byte: if self.register.is_big_endian() {
                ByteSize::new(self.register.size - self.start - self.len)
            } else {
                ByteSize::new(self.start)
            },
            size: ByteSize::new(self.len),
            arg: Box::new(self.register.to_ir_expr()),
        }
    }

    /// Returns an expression that can be assigned to the underlying register
    /// instead of assigning `expr` to only this slice.
    pub fn expand_to_full_size_expr(&self, expr: &IrExpression) -> IrExpression {
        // The size of the value produced by the initial expression should match
        // the size of the slice.
        debug_assert_eq!(ByteSize::new(self.len), expr.bytesize());

        let full_size_expr = match (self.msb_subpiece(), self.lsb_subpiece()) {
            (None, None) => expr.clone(),
            (Some(high_subpiece), None) => IrExpression::BinOp {
                op: IrBinOpType::Piece,
                lhs: Box::new(high_subpiece),
                rhs: Box::new(expr.clone()),
            },
            (None, Some(low_subpiece)) => IrExpression::BinOp {
                op: IrBinOpType::Piece,
                lhs: Box::new(expr.clone()),
                rhs: Box::new(low_subpiece),
            },
            (Some(high_subpiece), Some(low_subpiece)) => IrExpression::BinOp {
                op: IrBinOpType::Piece,
                lhs: Box::new(IrExpression::BinOp {
                    op: IrBinOpType::Piece,
                    lhs: Box::new(high_subpiece),
                    rhs: Box::new(expr.clone()),
                }),
                rhs: Box::new(low_subpiece),
            },
        };

        // The size of the value produced by the final expression should match
        // the size of the underlying register.
        debug_assert_eq!(ByteSize::new(self.register.size), full_size_expr.bytesize());

        full_size_expr
    }

    /// Returns the SUBPIECE expression over the base register that extracts the
    /// MSBs that are NOT covered by the slice.
    fn msb_subpiece(&self) -> Option<IrExpression> {
        if self.is_full() {
            None
        } else if self.register.is_big_endian() && self.start > 0 {
            Some(IrExpression::Subpiece {
                low_byte: (self.register.size - self.start).into(),
                size: self.start.into(),
                arg: Box::new(self.register.to_ir_expr()),
            })
        } else if !self.register.is_big_endian() && self.start + self.len < self.register.size {
            Some(IrExpression::Subpiece {
                low_byte: (self.start + self.len).into(),
                size: (self.register.size - self.start - self.len).into(),
                arg: Box::new(self.register.to_ir_expr()),
            })
        } else {
            None
        }
    }

    /// Returns the SUBPIECE expression over the base register that extracts the
    /// LSBs that are NOT covered by the slice.
    fn lsb_subpiece(&self) -> Option<IrExpression> {
        if self.is_full() {
            None
        } else if !self.register.is_big_endian() && self.start > 0 {
            Some(IrExpression::Subpiece {
                low_byte: 0.into(),
                size: self.start.into(),
                arg: Box::new(self.register.to_ir_expr()),
            })
        } else if self.register.is_big_endian() && self.start + self.len < self.register.size {
            Some(IrExpression::Subpiece {
                low_byte: 0.into(),
                size: (self.register.size - self.start - self.len).into(),
                arg: Box::new(self.register.to_ir_expr()),
            })
        } else {
            None
        }
    }
}

/// Unique identifier of a named CPU register.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct RegisterName(String);

impl Deref for RegisterName {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Type that represents `Ext(R)`.
///
/// - Provides translation between named CPU registers and offset-size pairs in
///   the register address space.
#[derive(Debug, Clone)]
pub struct RegisterMap<'a> {
    name_map: HashMap<&'a RegisterName, &'a RegisterProperties>,
    // Maps offsets into the Register Address Space to all registers that
    // contain the byte at this offset.
    offset_map: HashMap<u64, Vec<&'a RegisterProperties>>,
}

impl<'a> RegisterMap<'a> {
    /// Builds a `RegisterMap` from the given list of `RegisterProperties`.
    pub fn new(register_properties: &'a [RegisterProperties]) -> Self {
        let mut offset_map: HashMap<u64, Vec<&RegisterProperties>> = HashMap::new();

        for reg in register_properties.iter() {
            for offset in reg.address_space_offset..reg.address_space_offset + reg.bytes_spanned {
                offset_map
                    .entry(offset)
                    .and_modify(|regs| regs.push(reg))
                    .or_insert(vec![reg]);
            }
        }

        Self {
            name_map: register_properties
                .iter()
                .map(|reg| (&reg.register_name, reg))
                .collect(),
            offset_map,
        }
    }

    /// Returns the set of IR variables that correspond to base registers.
    pub fn get_base_reg_ir_vars(&self) -> BTreeSet<IrVariable> {
        self.name_map
            .iter()
            .filter_map(|(_, reg)| {
                if reg.is_base_register {
                    Some(IrVariable::from(*reg))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns all named registers that contain the given IR variable.
    ///
    /// For each non-temporary IR variable there is at least one such register
    /// (i.e. `upper_named(p(ir_var))` has at least one element).
    ///
    /// Returns `None` iff given a temporary variable.
    pub fn lookup_ir_variable(&self, ir_var: &IrVariable) -> Option<Vec<&'a RegisterProperties>> {
        if !ir_var.is_physical_register() {
            return None;
        }

        let offset = if ir_var.is_unnamed_subregister() {
            ir_var.name_to_offset().unwrap()
        } else {
            self.lookup_ir_variable_unique(ir_var)
                .unwrap()
                .address_space_offset
        };

        let regs = self.lookup_offset_size(offset, ir_var.size.into());

        debug_assert!(regs.is_some());

        regs
    }

    /// Returns all named registers that contain the given varnode.
    ///
    /// Each Varnode corresponds to a unique element in the canonical extended
    /// poset.
    ///
    /// Returns `None` iff the varnode is not in the register address space.
    /// Panics if there is no named register that contains the varnode.
    pub fn lookup_varnode(&self, varnode: &Varnode) -> Option<Vec<&'a RegisterProperties>> {
        if !varnode.is_in_register() {
            return None;
        }

        let offset = varnode.address_space_offset();
        let size = varnode.size();
        let named_upper_bounds = self.lookup_offset_size(offset, size);

        assert!(named_upper_bounds
            .as_ref()
            .is_some_and(|upper_bounds| !upper_bounds.is_empty()));

        named_upper_bounds
    }

    /// Returns the base register for this varnode.
    ///
    /// Returns `None` iff the varnode is not in the register address space.
    /// Panics if there is no named register that contains the varnode.
    pub fn lookup_base_reg_for_varnode(&self, varnode: &Varnode) -> Option<&'a RegisterProperties> {
        let named_upper_bounds = self.lookup_varnode(varnode)?;
        let base_register_name = &named_upper_bounds.first().unwrap().base_register;

        Some(self.lookup_name(base_register_name).unwrap())
    }

    /// Returns the unique named register corresponding to this IR variable.
    ///
    /// Returns `None` iff given a temporary variable or
    /// `p(ir_var) not in R`.
    // Note: Not quite true ... might return `Some` for low bytes of register
    // due to Ghidra quirk.
    pub fn lookup_ir_variable_unique(&self, ir_var: &IrVariable) -> Option<&'a RegisterProperties> {
        if !ir_var.is_physical_register() || ir_var.is_unnamed_subregister() {
            None
        } else {
            let reg_name = RegisterName(ir_var.name.clone());

            let reg = self.lookup_name(&reg_name);

            debug_assert!(reg.is_some());

            reg
        }
    }

    /// Returns the canonical representation of `p(ir_var)`.
    ///
    /// Returns `None` iff given a temporary variable or `p(ir_var)` is a base
    /// register.
    pub fn get_proper_base_reg_slice_for_ir_variable(
        &self,
        ir_var: &IrVariable,
    ) -> Option<RegisterSlice<'a>> {
        let base_reg_slice = self.get_base_reg_slice_for_ir_variable(ir_var);

        if base_reg_slice
            .as_ref()
            .is_some_and(|slice| slice.is_proper())
        {
            base_reg_slice
        } else {
            None
        }
    }

    /// Returns the canonical representation of `p(ir_var)`.
    ///
    /// Returns `None` iff given a temporary variable.
    pub fn get_base_reg_slice_for_ir_variable(
        &self,
        ir_var: &IrVariable,
    ) -> Option<RegisterSlice<'a>> {
        if !ir_var.is_physical_register() {
            None
        } else if ir_var.is_unnamed_subregister() {
            let offset = ir_var.name_to_offset().unwrap();
            let size = ir_var.size.into();
            let base_register_name = &self
                .lookup_offset_size(offset, size)
                .unwrap()
                .first()
                .unwrap()
                .base_register;
            let base_register = self.lookup_name(base_register_name).unwrap();

            Some(RegisterSlice {
                start: offset - base_register.address_space_offset,
                len: size,
                register: base_register,
            })
        } else {
            // Note: There is a quirk when the variable represents some LSBs of
            // a larger register. In this case Ghidra uses the name of the
            // larger register but a smaller size, so we have
            // `reg.size != ir_var.size` ...
            let reg = self.lookup_ir_variable_unique(ir_var).unwrap();
            let base_register = self.lookup_name(&reg.base_register).unwrap();

            Some(RegisterSlice {
                start: reg.address_space_offset - base_register.address_space_offset,
                // ... this matters here.
                len: ir_var.size.into(),
                register: base_register,
            })
        }
    }

    /// Returns the [`RegisterProperties`] of this named register.
    pub fn lookup_name(&self, register_name: &RegisterName) -> Option<&'a RegisterProperties> {
        self.name_map.get(register_name).copied()
    }

    /// Returns all named registers that contain the byte at the given `offset`.
    pub fn lookup_offset(&self, offset: u64) -> Option<&Vec<&'a RegisterProperties>> {
        self.offset_map.get(&offset)
    }

    /// Returns all named registers that contain the `size` bytes at the given
    /// `offset`.
    pub fn lookup_offset_size(
        &self,
        offset: u64,
        size: u64,
    ) -> Option<Vec<&'a RegisterProperties>> {
        Some(
            self.lookup_offset(offset)?
                .iter()
                .filter(|reg| reg.contains_offset_size(offset, size))
                .copied()
                .collect(),
        )
    }
}
