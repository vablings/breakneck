use std::{
    collections::HashSet,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use std::hash::Hash;
use std::hash::Hasher;

pub static PAGE_TRACKER: LazyLock<EncryptedPages> = LazyLock::new(EncryptedPages::new);
pub struct EncryptedPages(Mutex<HashSet<PageInformation>>);

impl EncryptedPages {
    fn new() -> Self {
        Self {
            0: Mutex::new(HashSet::new()),
        }
    }
    pub fn insert_or_update(&self, address: u64, encrypted: bool, trap_page: bool) {
        let new_page = PageInformation {
            address,
            encrypted,
            trap_page,
            last_accessed: Instant::now(),
        };
        let mut guard = self.0.lock().unwrap();
        if let Some(mut existing) = guard.take(&new_page) {
            existing.encrypted = encrypted;
            existing.trap_page = trap_page;
            existing.last_accessed = Instant::now();
            guard.insert(existing);
        } else {
            guard.insert(new_page);
        }
    }

    pub fn get(&self, address: u64) -> Option<PageInformation> {
        let guard = self.0.lock().unwrap();
        guard
            .get(&PageInformation {
                address,
                encrypted: false,
                trap_page: false,
                last_accessed: Instant::now(),
            })
            .cloned()
    }

    pub fn get_all_unencrypted(&self) -> Vec<u64> {
        let guard = self.0.lock().unwrap();
        let now = Instant::now();
        guard
            .iter()
            .filter(|info| !info.encrypted && !info.trap_page)
            //we filter out any pages that have been recently decrypted because well. performance
            .filter(|info| now.duration_since(info.last_accessed) > Duration::from_millis(500))
            .map(|page| page.address)
            .collect()
    }
}

#[derive(Clone)]
pub struct PageInformation {
    address: u64,
    encrypted: bool,
    trap_page: bool,
    last_accessed: Instant,
}

impl PageInformation {
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }
}

impl PartialEq for PageInformation {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}
impl Eq for PageInformation {}
impl Hash for PageInformation {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}
