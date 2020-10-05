use super::*;

impl State {
    /// Get the value of a register or Top() if no value is known.
    ///
    /// Returns an error if the variable is not a register.
    pub fn get_register(&self, variable: &Variable) -> Result<Data, Error> {
        if let Some(data) = self.register.get(variable) {
            Ok(data.clone())
        } else {
            Ok(Data::new_top(variable.size))
        }
    }

    /// Get the value of a register by its name.
    ///
    /// Returns None if no value is set for the register.
    pub fn get_register_by_name(&self, reg_name: &str) -> Option<Data> {
        self.register.iter().find_map(|(key, value)| {
            if key.name == reg_name {
                Some(value.clone())
            } else {
                None
            }
        })
    }

    /// Set the value of a register.
    ///
    /// Returns an error if the variable is not a register.
    pub fn set_register(&mut self, variable: &Variable, value: Data) {
        if !value.is_top() {
            self.register.insert(variable.clone(), value);
        } else {
            self.register.remove(variable);
        }
    }

    /// Evaluate expression on the given state and write the result to the target register.
    pub fn handle_register_assign(
        &mut self,
        target: &Variable,
        expression: &Expression,
    ) -> Result<(), Error> {
        match self.eval(expression) {
            Ok(new_value) => {
                self.set_register(target, new_value);
                Ok(())
            }
            Err(err) => {
                self.set_register(target, Data::new_top(target.size));
                Err(err)
            }
        }
    }

    /// Store `value` at the given `address`.
    pub fn store_value(&mut self, address: &Data, value: &Data) -> Result<(), Error> {
        // If the address is a unique caller stack address, write to *all* caller stacks.
        if let Some(offset) = self.unwrap_offset_if_caller_stack_address(address) {
            let caller_addresses: Vec<_> = self
                .caller_stack_ids
                .iter()
                .map(|caller_stack_id| {
                    PointerDomain::new(caller_stack_id.clone(), offset.clone()).into()
                })
                .collect();
            let mut result = Ok(());
            for address in caller_addresses {
                if let Err(err) = self.store_value(&address, &value.clone()) {
                    result = Err(err);
                }
            }
            // Note that this only returns the last error that was detected.
            result
        } else if let Data::Pointer(pointer) = self.adjust_pointer_for_read(address) {
            self.memory.set_value(pointer, value.clone())?;
            Ok(())
        } else {
            // TODO: Implement recognition of stores to global memory.
            Err(anyhow!("Memory write to non-pointer data"))
        }
    }

    /// Write a value to the address one gets when evaluating the address expression.
    pub fn write_to_address(&mut self, address: &Expression, value: &Data) -> Result<(), Error> {
        match self.eval(address) {
            Ok(address_data) => self.store_value(&address_data, value),
            Err(err) => Err(err),
        }
    }

    /// Evaluate the given store instruction on the given state and return the resulting state.
    ///
    /// The function panics if given anything else than a store expression.
    pub fn handle_store(&mut self, address: &Expression, value: &Expression) -> Result<(), Error> {
        match self.eval(value) {
            Ok(data) => self.write_to_address(address, &data),
            Err(err) => {
                // we still need to write to the target location before reporting the error
                self.write_to_address(address, &Data::new_top(value.bytesize()))?;
                Err(err)
            }
        }
    }

    /// Evaluate the given load instruction and return the data read on success.
    pub fn load_value(&self, address: &Expression, size: ByteSize) -> Result<Data, Error> {
        Ok(self
            .memory
            .get_value(&self.adjust_pointer_for_read(&self.eval(address)?), size)?)
    }

    /// Handle a load instruction by assigning the value loaded from the address given by the `address` expression to `var`.
    pub fn handle_load(&mut self, var: &Variable, address: &Expression) -> Result<(), Error> {
        match self.load_value(address, var.size) {
            Ok(data) => {
                self.set_register(var, data);
                Ok(())
            }
            Err(err) => {
                self.set_register(var, Data::new_top(var.size));
                Err(err)
            }
        }
    }

    /// If the pointer contains a reference to the stack with offset >= 0, replace it with a pointer
    /// pointing to all possible caller IDs.
    fn adjust_pointer_for_read(&self, address: &Data) -> Data {
        if let Data::Pointer(pointer) = address {
            let mut new_targets = BTreeMap::new();
            for (id, offset) in pointer.targets() {
                if *id == self.stack_id {
                    match offset {
                        BitvectorDomain::Value(offset_val) => {
                            if offset_val.try_to_i64().unwrap() >= 0
                                && !self.caller_stack_ids.is_empty()
                            {
                                for caller_id in self.caller_stack_ids.iter() {
                                    new_targets.insert(caller_id.clone(), offset.clone());
                                }
                            // Note that the id of the current stack frame was *not* added.
                            } else {
                                new_targets.insert(id.clone(), offset.clone());
                            }
                        }
                        BitvectorDomain::Top(_bytesize) => {
                            for caller_id in self.caller_stack_ids.iter() {
                                new_targets.insert(caller_id.clone(), offset.clone());
                            }
                            // Note that we also add the id of the current stack frame
                            new_targets.insert(id.clone(), offset.clone());
                        }
                    }
                } else {
                    new_targets.insert(id.clone(), offset.clone());
                }
            }
            Data::Pointer(PointerDomain::with_targets(new_targets))
        } else {
            address.clone()
        }
    }

    /// Evaluate the value of an expression in the current state
    pub fn eval(&self, expression: &Expression) -> Result<Data, Error> {
        use Expression::*;
        match expression {
            Var(variable) => self.get_register(&variable),
            Const(bitvector) => Ok(bitvector.clone().into()),
            BinOp { op, lhs, rhs } => {
                if *op == BinOpType::IntXOr && lhs == rhs {
                    // the result of `x XOR x` is always zero.
                    return Ok(Bitvector::zero(apint::BitWidth::from(lhs.bytesize())).into());
                }
                let (left, right) = (self.eval(lhs)?, self.eval(rhs)?);
                Ok(left.bin_op(*op, &right))
            }
            UnOp { op, arg } => Ok(self.eval(arg)?.un_op(*op)),
            Cast { op, size, arg } => Ok(self.eval(arg)?.cast(*op, *size)),
            Unknown {
                description: _,
                size,
            } => Ok(Data::new_top(*size)),
            Subpiece {
                low_byte,
                size,
                arg,
            } => Ok(self.eval(arg)?.subpiece(*low_byte, *size)),
        }
    }

    /// Check if an expression contains a use-after-free
    pub fn contains_access_of_dangling_memory(&self, def: &Def) -> bool {
        match def {
            Def::Load { address, .. } | Def::Store { address, .. } => {
                if let Ok(pointer) = self.eval(address) {
                    self.memory.is_dangling_pointer(&pointer, true)
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// If  the given address is a positive stack offset and `self.caller_stack_ids` is non-empty,
    /// i.e. it is an access to the caller stack, return the offset.
    ///
    /// In all other cases, including the case that the address has more than one target, return `None`.
    fn unwrap_offset_if_caller_stack_address(&self, address: &Data) -> Option<BitvectorDomain> {
        if self.caller_stack_ids.is_empty() {
            return None;
        }
        if let Data::Pointer(pointer) = address {
            match (pointer.targets().len(), pointer.targets().iter().next()) {
                (1, Some((id, offset))) if self.stack_id == *id => {
                    if let BitvectorDomain::Value(offset_val) = offset {
                        if offset_val.try_to_i64().unwrap() >= 0 {
                            return Some(offset.clone());
                        }
                    }
                }
                _ => (),
            }
        }
        None
    }
}