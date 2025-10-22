use std::any::{Any, TypeId};
use std::fmt::Debug;
use std::hash::Hash;

pub trait Representation: Any + Send + Sync + Debug {
    type Id: Hash + Eq + Clone + Debug;

    fn type_id(&self) -> TypeId {
        TypeId::of::<Self>()
    }

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;
}

pub trait Visitable {
    type Visitor: ?Sized;

    fn accept(&self, visitor: &mut Self::Visitor);
}

pub trait RepresentationExt: Representation {
    fn downcast_ref<T: Representation + 'static>(&self) -> Option<&T> {
        self.as_any().downcast_ref::<T>()
    }

    fn downcast_mut<T: Representation + 'static>(&mut self) -> Option<&mut T> {
        self.as_any_mut().downcast_mut::<T>()
    }
}

impl<R: Representation> RepresentationExt for R {}
