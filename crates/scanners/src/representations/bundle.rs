use crate::representations::Representation;
use anyhow::Result;
use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct RepresentationSet {
    required: HashSet<TypeId>,
    optional: HashSet<TypeId>,
}

impl RepresentationSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn require<T: Representation + 'static>(mut self) -> Self {
        self.required.insert(TypeId::of::<T>());
        self
    }

    pub fn optional<T: Representation + 'static>(mut self) -> Self {
        self.optional.insert(TypeId::of::<T>());
        self
    }

    pub fn are_satisfied_by(&self, bundle: &RepresentationBundle) -> bool {
        self.required.iter().all(|id| bundle.has_by_id(*id))
    }

    pub fn missing_from(&self, bundle: &RepresentationBundle) -> Vec<TypeId> {
        self.required
            .iter()
            .filter(|id| !bundle.has_by_id(**id))
            .copied()
            .collect()
    }
}

#[derive(Clone)]
pub struct RepresentationBundle {
    representations: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
}

impl RepresentationBundle {
    pub fn new() -> Self {
        Self {
            representations: HashMap::new(),
        }
    }

    pub fn add<T: Representation + 'static>(mut self, representation: T) -> Self {
        self.representations.insert(
            TypeId::of::<T>(),
            Arc::new(representation) as Arc<dyn Any + Send + Sync>,
        );
        self
    }

    pub fn get<T: Representation + 'static>(&self) -> Result<&T> {
        self.representations
            .get(&TypeId::of::<T>())
            .and_then(|r| r.downcast_ref::<T>())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Representation {} not available",
                    std::any::type_name::<T>()
                )
            })
    }

    pub fn has<T: Representation + 'static>(&self) -> bool {
        self.has_by_id(TypeId::of::<T>())
    }

    pub fn has_by_id(&self, id: TypeId) -> bool {
        self.representations.contains_key(&id)
    }

    pub fn available_types(&self) -> Vec<TypeId> {
        self.representations.keys().copied().collect()
    }
}

impl Default for RepresentationBundle {
    fn default() -> Self {
        Self::new()
    }
}
