use std::hash::Hash;
use std::sync::Arc;

use ascent::hashbrown::HashMap;
use itertools::Itertools;

pub struct ArcCache<T>
where
    T: Hash + Eq + Clone,
{
    cache: HashMap<T, Arc<T>>,
}

impl<T> ArcCache<T>
where
    T: Hash + Eq + Clone,
{
    pub fn new() -> ArcCache<T> {
        ArcCache {
            cache: HashMap::new(),
        }
    }

    pub fn get(&mut self, val: &T) -> Arc<T> {
        match self.cache.get(val) {
            Some(existing_arc) => existing_arc.clone(),
            None => {
                let new_arc = Arc::new(val.clone());
                self.cache.insert(val.clone(), new_arc.clone());
                new_arc
            }
        }
    }

    pub fn get_all(&self) -> Vec<T> {
        self.cache.keys().map(|key| key.clone()).collect_vec()
    }
}
