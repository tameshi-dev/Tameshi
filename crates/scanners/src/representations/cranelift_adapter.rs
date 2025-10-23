use crate::representations::{Representation, Visitable};
use std::any::Any;
use thalir_core::contract::Contract as IRContract;

impl Representation for IRContract {
    type Id = String; // Contract name as ID

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

pub trait CraneliftVisitor {
    fn visit_contract(&mut self, contract: &IRContract) {
        for (_name, function) in &contract.functions {
            self.visit_function(function);
        }
    }

    fn visit_function(&mut self, function: &thalir_core::Function) {
        for block in function.body.blocks.values() {
            self.visit_block(block);
        }
    }

    fn visit_block(&mut self, block: &thalir_core::block::BasicBlock) {
        for instruction in &block.instructions {
            self.visit_instruction(instruction);
        }
    }

    fn visit_instruction(&mut self, _instruction: &thalir_core::instructions::Instruction) {}
}

impl Visitable for IRContract {
    type Visitor = dyn CraneliftVisitor;

    fn accept(&self, visitor: &mut Self::Visitor) {
        visitor.visit_contract(self);
    }
}
