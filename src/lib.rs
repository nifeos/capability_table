//! Capability tables: a file descriptor table that can point at anything.
//!
//! The table lives in the kernel's memory and a program sees only a slot number, so the
//! unforgeability is an array and a bounds check. Pure logic, host-tested and Kani-proved; the
//! owner supplies the object type and picks the size, which is part of the type, so creating a table
//! allocates nothing.
//!
//! # Examples
//!
//! Rights narrow by intersection, so a capability passed on never carries more than was held.
//!
//! ```
//! use capability_table::Rights;
//!
//! let held = Rights::READ.union(Rights::WRITE);
//! assert!(held.allows(Rights::READ));
//! assert!(!held.allows(Rights::GRANT));
//!
//! // Handing it on with a mask can only ever narrow it.
//! let passed_on = held.intersect(Rights::READ.union(Rights::GRANT));
//! assert_eq!(passed_on, Rights::READ);
//! assert!(passed_on.is_subset_of(held));
//! ```
//!
//! No operation widens:
//!
//! ```
//! use capability_table::Rights;
//!
//! let read_only = Rights::READ;
//! // The best you can do with ALL on the other side is get back what you already had.
//! assert_eq!(read_only.intersect(Rights::ALL), read_only);
//! assert!(!read_only.intersect(Rights::ALL).allows(Rights::WRITE));
//! ```

#![no_std]

use core::num::NonZeroU32;

/// What you may do with a capability.
///
/// Rights only narrow: [`CapabilityTable::derive`] cannot widen them, because the type offers no
/// operation that would.
///
/// The word keeps its top bit set as a presence marker, so it is never zero. `Option<Rights>` and
/// `Option<Capability<O>>` use the zero word for `None`, and an empty slot costs no space beyond the
/// capability, whatever the object type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rights(NonZeroU32);

/// The bit [`Rights`] keeps set in its word, which is no right. [`Rights::bits`] clears it.
const PRESENT: u32 = 1 << 31;

impl Rights {
    /// No rights at all.
    pub const NONE: Rights = Rights::from_word(0);
    /// The right to read the object's contents.
    pub const READ: Rights = Rights::from_word(1 << 0);
    /// The right to modify the object's contents.
    pub const WRITE: Rights = Rights::from_word(1 << 1);

    /// The right to **pass this capability on**. Without it, you may use a thing and not lend it,
    /// which makes delegation a decision rather than an accident.
    pub const GRANT: Rights = Rights::from_word(1 << 2);

    /// The right to **learn what exists**, as distinct from acting on it: the table's twin of a
    /// directory's `ENUMERATE`.
    ///
    /// A domain names its members and never acts on them, so a survey takes this rather than the
    /// `READ` that a receive and a reap take. An owner decides which objects consult it.
    pub const ENUMERATE: Rights = Rights::from_word(1 << 3);

    /// **The right to add a thread to a process.** Held on a process capability, it lets a thread
    /// under construction join that process without consuming the capability. An owner decides
    /// which objects consult it.
    pub const BIND: Rights = Rights::from_word(1 << 4);

    /// **The right to revoke: to withdraw what was passed on from this capability.** Distinct from
    /// [`GRANT`](Self::GRANT), so a holder may lend a thing without the power to take back what
    /// others lent from it, or the other way round. An owner decides which objects consult it.
    pub const REVOKE: Rights = Rights::from_word(1 << 5);

    /// **Every defined bit.** [`from_bits`](Self::from_bits) masks against this, so a right that is
    /// missing here is silently dropped at every delegation: adding a constant above without
    /// widening this mask produces a right that cannot survive being passed on.
    pub const ALL: Rights = Rights::READ
        .union(Rights::WRITE)
        .union(Rights::GRANT)
        .union(Rights::ENUMERATE)
        .union(Rights::BIND)
        .union(Rights::REVOKE);

    /// The raw bit pattern, for carrying rights across a boundary as an integer (a system call
    /// register). [`from_bits`](Self::from_bits) is the inverse.
    pub const fn bits(self) -> u32 {
        self.0.get() & !PRESENT
    }

    /// Rights from a word as it stands, every bit but the marker kept: the one constructor, which
    /// sets the marker. [`from_bits`](Self::from_bits) is the public door, and it masks first.
    const fn from_word(bits: u32) -> Rights {
        match NonZeroU32::new(bits | PRESENT) {
            Some(word) => Rights(word),
            None => unreachable!(),
        }
    }

    /// Rebuild rights from a raw bit pattern, keeping only defined bits: the inverse of
    /// [`bits`](Self::bits), for rights that crossed a boundary in a system call register. Undefined
    /// bits are dropped, so a caller cannot conjure a right that does not exist.
    pub const fn from_bits(bits: u32) -> Rights {
        Rights::from_word(bits & Rights::ALL.bits())
    }

    /// Every right either side holds.
    pub const fn union(self, other: Rights) -> Rights {
        Rights::from_word(self.bits() | other.bits())
    }

    /// Only the rights both sides hold. The one operation on the delegation path: it can only
    /// narrow, never widen, which is the monotonicity the whole model rests on.
    pub const fn intersect(self, other: Rights) -> Rights {
        Rights::from_word(self.bits() & other.bits())
    }

    /// Do I hold *at least* these rights?
    pub const fn allows(self, needed: Rights) -> bool {
        self.bits() & needed.bits() == needed.bits()
    }

    /// Is `self` no more than `other`? The subset test that [`CapabilityTable::derive`] turns on.
    pub const fn is_subset_of(self, other: Rights) -> bool {
        self.bits() & !other.bits() == 0
    }
}

impl core::fmt::Debug for Rights {
    /// The rights bits, without the marker: `Rights(5)` is `READ` and `GRANT`.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_tuple("Rights").field(&self.bits()).finish()
    }
}

/// A capability: **an object, and what you may do with it.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability<O> {
    /// What this capability names.
    pub object: O,
    /// What the holder may do with it.
    pub rights: Rights,
}

impl<O: Copy> Capability<O> {
    /// **Pass this capability on with `rights`, or refuse.** The one delegation rule: the holder
    /// must hold [`Rights::GRANT`], and the copy may only narrow. The copy names the same object.
    /// [`CapabilityTable::derive`] files the result, and an owner that reads its source under a
    /// lock of its own calls this on what it read, so the rule has one body.
    ///
    /// Without `GRANT` the answer is [`Error::GrantRequired`], whatever `rights` asks for. With it,
    /// asking for a right the source lacks is [`Error::CannotWiden`], not a silent clamp.
    pub fn delegate(&self, rights: Rights) -> Result<Capability<O>, Error> {
        if !self.rights.allows(Rights::GRANT) {
            return Err(Error::GrantRequired);
        }
        if !rights.is_subset_of(self.rights) {
            return Err(Error::CannotWiden);
        }
        Ok(Capability {
            object: self.object,
            rights,
        })
    }
}

impl<O> Capability<O> {
    /// **Mint a fresh capability to `object` with exactly this one's rights.** The mint site for
    /// authority created outside [`CapabilityTable::derive`], such as carving a child budget out of
    /// a parent. The harness `split_never_widens_rights` proves it, so a spend-only (`GRANT`-less)
    /// budget cannot split itself a `GRANT`-bearing child.
    pub fn mint_child(&self, object: O) -> Capability<O> {
        Capability {
            object,
            rights: self.rights,
        }
    }
}

/// Why a capability table operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// **The slot is empty.** Note what this is *not*: it is not "permission denied." There is
    /// nothing there. The thing you tried to name does not exist, for you.
    NoSuchSlot,
    /// You asked to derive a capability with rights you do not hold.
    CannotWiden,
    /// **The capability may not be passed on.** Its holder lacks [`Rights::GRANT`].
    GrantRequired,
    /// The table is full.
    NoFreeSlot,
    /// **The slot asked for is already occupied.** Distinct from [`NoFreeSlot`](Self::NoFreeSlot),
    /// which says the whole table is full.
    SlotOccupied,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::NoSuchSlot => "the slot is empty or out of range",
            Error::CannotWiden => "the rights asked for are not all held",
            Error::GrantRequired => "the capability may not be passed on",
            Error::NoFreeSlot => "the table is full",
            Error::SlotOccupied => "the slot is already occupied",
        })
    }
}

impl core::error::Error for Error {}

/// **The most slots a [`CapabilityTable`] may have**, whatever its storage.
///
/// 256, set from the most slots one table has been measured to hold, 39, with generous headroom:
/// six and a half times that peak and four times the 64 slots a table was limited to before. The
/// free-slot set is four 64-bit words at this bound, 32 bytes in every table, and a search for a
/// free slot reads at most those four. A 256-slot table of 32-byte capabilities is 8 KiB.
///
/// It may only grow. A table that was legal stays legal when it grows, and a lower bound would
/// refuse a table some owner already builds. Growing it widens the free-slot set of every table by
/// one word per 64 slots.
pub const MAXIMUM_SLOTS: usize = 256;

/// The words of the free-slot set: one bit per slot, up to [`MAXIMUM_SLOTS`].
const FREE_WORDS: usize = MAXIMUM_SLOTS / WORD_BITS;

/// The slots one free-slot word covers.
const WORD_BITS: usize = u64::BITS as usize;

// The bound fills its words exactly, and the counts that hold a slot number fit their `u16`.
const _: () = assert!(MAXIMUM_SLOTS % WORD_BITS == 0);
const _: () = assert!(MAXIMUM_SLOTS <= u16::MAX as usize);

pub use storage::CapabilityTable;

/// **The only code that can touch a slot**, and that is the mechanism rather than a convention.
///
/// The free-slot set, the size, the occupancy count and the high-water mark are private to this
/// module, which changes a slot only through [`fill`](CapabilityTable::fill) and
/// [`empty`](CapabilityTable::empty). Every other mutator is written in terms of those two, so it
/// cannot forget the bookkeeping. The harnesses `the_free_mask_is_the_empty_slots` and
/// `the_count_is_the_slots` check the two doors against the array.
mod storage {
    #[cfg(all(target_has_atomic = "32", feature = "peak"))]
    use super::note_peak;
    use super::{Capability, FREE_WORDS, MAXIMUM_SLOTS, WORD_BITS};

    /// A thread's capability table: a flat array, an fd table with a type tag on each entry,
    /// rather than seL4's tree of `CNode` objects.
    ///
    /// `N` is the storage, the most slots this type can hold. The table's size is chosen when it is
    /// made, at most `N`, and never changes: [`new`](Self::new) takes all `N`, and
    /// [`with_size`](Self::with_size) fewer. A slot at or above the size is always empty, so a
    /// lookup needs no check beyond the array's own.
    pub struct CapabilityTable<O, const N: usize> {
        slots: [Option<Capability<O>>; N],
        /// **Bit `i % 64` of word `i / 64` set means slot `i` is empty**, so `insert`'s first free
        /// slot is one `trailing_zeros` in the first word that is not zero. Bits at and above the
        /// size stay clear, so a full table is all zero words.
        free: [u64; FREE_WORDS],
        /// How many slots the table has: every slot below it may be filled, and none at or above.
        /// Set when the table is made, and never changed after.
        size_slots: u16,
        /// How many of the slots are occupied right now. Maintained by the two doors rather than
        /// counted on demand, because the thing that wants it is a high-water mark and a mark
        /// sampled at a convenient moment is not one.
        used: u16,
        /// The largest `used` this table has ever held. **Never decreases**, which is the whole
        /// point: the number a boot reports is what it *reached*, not what it happens to be holding
        /// when somebody looks. See [`peak`](Self::peak), and `highest_seen` behind the
        /// `peak` feature.
        peak: u16,
    }

    /// The free-slot word `word` of a table of `size` slots with every slot empty: the bits of
    /// the slots from `word * 64` up to `size`.
    pub(super) const fn all_free_word(size: usize, word: usize) -> u64 {
        let low = word * WORD_BITS;
        if size <= low {
            0
        } else if size - low >= WORD_BITS {
            u64::MAX
        } else {
            (1u64 << (size - low)) - 1
        }
    }

    impl<O: Copy, const N: usize> CapabilityTable<O, N> {
        /// The free-slot words a table of this storage reads: enough for `N` slots, which
        /// [`with_size`](Self::with_size) bounds by [`MAXIMUM_SLOTS`].
        pub(super) const WORDS: usize = N.div_ceil(WORD_BITS);

        /// **A brand-new process holds nothing**: it can name nothing until somebody hands it
        /// something. The table has all `N` slots.
        pub const fn new() -> Self {
            match Self::with_size(N) {
                Some(table) => table,
                None => unreachable!(),
            }
        }

        /// **An empty table of `size` slots**, or `None` when `size` is more than the storage
        /// holds. The size never changes after: a slot a holder was told it may fill stays one it
        /// may fill.
        pub const fn with_size(size: usize) -> Option<Self> {
            // The compile-time wall `MAXIMUM_SLOTS` describes, evaluated for each `N` that is
            // instantiated: the one constructor refuses storage the free-slot set cannot cover.
            const {
                assert!(
                    N <= MAXIMUM_SLOTS,
                    "a capability table has at most MAXIMUM_SLOTS slots"
                );
            }
            if size > N {
                return None;
            }
            let mut free = [0u64; FREE_WORDS];
            let mut word = 0;
            while word < FREE_WORDS {
                free[word] = all_free_word(size, word);
                word += 1;
            }
            Some(CapabilityTable {
                slots: [const { None }; N],
                free,
                // At most `N`, which the assertion bounds by `MAXIMUM_SLOTS`, which fits a `u16`.
                size_slots: size as u16,
                used: 0,
                peak: 0,
            })
        }

        /// How many slots the table has, set when it was made.
        pub const fn size(&self) -> usize {
            self.size_slots as usize
        }

        /// The capability in `slot`, or `None` for an empty or out-of-range one. A slot at or above
        /// the size is empty, which [`fill`](Self::fill) keeps true, so the array's bound is the
        /// only check.
        pub(super) fn slot(&self, slot: usize) -> Option<Capability<O>> {
            self.slots.get(slot).copied().flatten()
        }

        /// The lowest-numbered empty slot, or `None` when the table is full. One count of trailing
        /// zeros in the first free-slot word that is not zero.
        pub(super) fn first_free(&self) -> Option<usize> {
            self.first_free_from(0)
        }

        /// The lowest empty slot at or above `floor`, or `None` when there is none.
        pub(super) fn first_free_from(&self, floor: usize) -> Option<usize> {
            let mut word = floor / WORD_BITS;
            if word >= Self::WORDS {
                return None;
            }
            // The first word drops the slots below the floor; the words after it count whole.
            let mut bits = self.free[word] & (u64::MAX << (floor % WORD_BITS));
            loop {
                if bits != 0 {
                    return Some(word * WORD_BITS + bits.trailing_zeros() as usize);
                }
                word += 1;
                if word >= Self::WORDS {
                    return None;
                }
                bits = self.free[word];
            }
        }

        /// The free-slot set itself, for the proofs and the tests that check it against the array.
        #[cfg_attr(not(any(test, kani)), allow(dead_code))]
        pub(super) fn free_mask(&self) -> [u64; FREE_WORDS] {
            self.free
        }

        /// The occupied slots of word `word`, as a mask: `free`'s complement, restricted to the
        /// slots below the size (inverting `free` alone would set the bits above it).
        /// [`delete_matching`](super::CapabilityTable::delete_matching) walks these so a sweep
        /// costs a table's occupancy, not its capacity.
        pub(super) fn occupied_word(&self, word: usize) -> u64 {
            !self.free[word] & all_free_word(self.size_slots as usize, word)
        }

        /// Whether every slot is empty: one compare, because the count already knows.
        pub(super) fn all_free(&self) -> bool {
            self.used == 0
        }

        /// **Door one: put `capability` in `slot`**, occupied or not. `None` if `slot` is at or above
        /// the size; otherwise whether it was empty before. Clears the slot's free bit, and if the
        /// slot was empty, counts the growth and raises the high-water mark.
        pub(super) fn fill(&mut self, slot: usize, capability: Capability<O>) -> Option<bool> {
            if slot >= self.size_slots as usize {
                return None;
            }
            let s = self.slots.get_mut(slot)?;
            let was_empty = s.is_none();
            *s = Some(capability);
            self.free[slot / WORD_BITS] &= !(1u64 << (slot % WORD_BITS));
            if was_empty {
                // Wrapping, because the wrap cannot happen and this is on every reply-capability
                // mint (release builds check overflow). `used` counts
                // occupied slots (`the_count_is_the_slots` proves it), this slot was empty, so the
                // result is at most the size, which `MAXIMUM_SLOTS` bounds below `u16::MAX`.
                self.used = self.used.wrapping_add(1);
                if self.used > self.peak {
                    self.peak = self.used;
                    #[cfg(all(target_has_atomic = "32", feature = "peak"))]
                    note_peak(self.peak, self.size_slots as usize);
                }
            }
            Some(was_empty)
        }

        /// **Door two: take whatever is in `slot`**, leaving it empty. `None` if `slot` is out of
        /// range or already empty, and then nothing changes. Sets the slot's free bit and counts
        /// the loss. `peak` is untouched: a mark that fell when the table drained would report
        /// what a boot holds, not what it reached.
        pub(super) fn empty(&mut self, slot: usize) -> Option<Capability<O>> {
            let capability = self.slots.get_mut(slot)?.take()?;
            self.free[slot / WORD_BITS] |= 1u64 << (slot % WORD_BITS);
            self.used -= 1;
            Some(capability)
        }

        /// How many slots are occupied right now.
        pub fn used(&self) -> usize {
            self.used as usize
        }

        /// **The most slots this table has ever held at once**, which is the number a capacity
        /// decision is actually made against. `used` at any given moment is whatever the last few
        /// calls left behind; this is the wall the table came closest to.
        pub fn peak(&self) -> usize {
            self.peak as usize
        }
    }
}

impl<O: Copy, const N: usize> Default for CapabilityTable<O, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// The set bits of `word`, lowest first, each once.
fn set_bits(mut word: u64) -> impl Iterator<Item = usize> {
    core::iter::from_fn(move || {
        if word == 0 {
            return None;
        }
        let bit = word.trailing_zeros() as usize;
        word &= word - 1; // clear the lowest set bit; each slot visited once
        Some(bit)
    })
}

impl<O: Copy, const N: usize> CapabilityTable<O, N> {
    /// How many slots the table has, occupied or not: its [`size`](Self::size), chosen when it was
    /// made and never changed. [`used`](Self::used) counts the occupied ones.
    pub const fn capacity(&self) -> usize {
        self.size()
    }

    /// Whether every slot is currently empty.
    pub fn is_empty(&self) -> bool {
        self.all_free()
    }

    /// Look up a slot. **The entire security mechanism, and it is a bounds check.**
    pub fn get(&self, slot: u64) -> Result<Capability<O>, Error> {
        // A slot that does not fit `usize` names nothing, on any target: truncating it would let
        // `2^32 + k` name slot `k` where `usize` is 32 bits.
        let slot = usize::try_from(slot).map_err(|_| Error::NoSuchSlot)?;
        self.slot(slot).ok_or(Error::NoSuchSlot)
    }

    /// Put a capability in the first free slot. Used at spawn, to hand a process its world, and
    /// on every `CALL` for the one-shot Reply, which is why it is one `trailing_zeros` per word
    /// and not a scan of the slots (see the free-slot set's own doc).
    pub fn insert(&mut self, capability: Capability<O>) -> Result<u64, Error> {
        let slot = self.first_free().ok_or(Error::NoFreeSlot)?;
        self.fill(slot, capability);
        Ok(slot as u64)
    }

    /// Put a capability in the **first free slot at or above `floor`**. [`insert`](Self::insert) is
    /// `floor` 0. A program's low slots can be fixed by number, with an empty one meaning "not
    /// granted", so what the program makes for itself must land above them.
    pub fn insert_at_or_above(
        &mut self,
        floor: u64,
        capability: Capability<O>,
    ) -> Result<u64, Error> {
        let floor = usize::try_from(floor).unwrap_or(usize::MAX);
        let slot = self.first_free_from(floor).ok_or(Error::NoFreeSlot)?;
        self.fill(slot, capability);
        Ok(slot as u64)
    }

    /// Put a capability in a **specific free slot**, refusing an occupied or out-of-range one.
    ///
    /// The targeted counterpart of [`insert`](Self::insert). A supervisor uses it to place a
    /// child's supervision rendezvous in a reserved slot rather than wherever first-free would fall,
    /// and refusing an occupied slot keeps that reservation honest: two things must never share the
    /// slot the owner reads when the child starts.
    pub fn insert_at(&mut self, slot: u64, capability: Capability<O>) -> Result<u64, Error> {
        if slot >= self.size() as u64 {
            return Err(Error::NoSuchSlot);
        }
        if self.slot(slot as usize).is_some() {
            return Err(Error::SlotOccupied);
        }
        self.fill(slot as usize, capability);
        Ok(slot)
    }

    /// Put a capability in a specific slot, replacing whatever was there. This is the door for
    /// building a table to a known shape (a loader, the proof builder); it consults no rights, so
    /// authority moves through [`derive`](Self::derive) and not through this.
    pub fn put(&mut self, slot: u64, capability: Capability<O>) -> Result<(), Error> {
        let slot = usize::try_from(slot).map_err(|_| Error::NoSuchSlot)?;
        self.fill(slot, capability).ok_or(Error::NoSuchSlot)?;
        Ok(())
    }

    /// **Copy a capability into another slot, with rights that are no greater.**
    ///
    /// The only way authority moves between slots, by [`Capability::delegate`]: the source must
    /// hold [`Rights::GRANT`] ([`Error::GrantRequired`]), and asking for rights it does not hold is
    /// [`Error::CannotWiden`], not a silent clamp: a loader that quietly grants less than was asked
    /// for is a loader nobody can reason about.
    pub fn derive(&mut self, from: u64, to: u64, rights: Rights) -> Result<(), Error> {
        let copy = self.get(from)?.delegate(rights)?;
        self.put(to, copy)
    }

    /// Drop a capability. The object may still exist; **we simply can no longer name it.**
    pub fn delete(&mut self, slot: u64) -> Result<(), Error> {
        let slot = usize::try_from(slot).map_err(|_| Error::NoSuchSlot)?;
        self.empty(slot).ok_or(Error::NoSuchSlot)?;
        Ok(())
    }

    /// **The occupied slots, lowest first, as `(slot, capability)`**: a read-only walk that costs a
    /// table's occupancy and not its capacity, because it follows the occupied masks as
    /// [`delete_matching`](Self::delete_matching) does.
    pub fn iter(&self) -> impl Iterator<Item = (u64, Capability<O>)> + '_ {
        (0..Self::WORDS).flat_map(move |word| {
            set_bits(self.occupied_word(word)).filter_map(move |bit| {
                let slot = word * u64::BITS as usize + bit;
                self.slot(slot).map(|capability| (slot as u64, capability))
            })
        })
    }

    /// Delete every occupied slot whose object satisfies `matches`, in place: the revocation
    /// sweeps' primitive, behaviorally a `get`-then-`delete` per slot. It reads each slot once and
    /// walks the occupied masks, not `0..N`, because a sweep visits every thread's table for every
    /// frame a revocation touches and should cost what a table holds, not its capacity.
    pub fn delete_matching(&mut self, mut matches: impl FnMut(&O) -> bool) {
        for word in 0..Self::WORDS {
            for bit in set_bits(self.occupied_word(word)) {
                let slot = word * u64::BITS as usize + bit;
                if matches!(self.slot(slot), Some(c) if matches(&c.object)) {
                    self.empty(slot);
                }
            }
        }
    }
}

/// **The high-water mark across every capability table in this binary, and the ceiling it was
/// measured against**, kept only with the `peak` feature. Packed as `peak << 16 | ceiling` so a
/// reader gets a pair true at one instant.
///
/// A reader sees the mark move without walking every table under a lock. [`note_peak`] saturates.
///
/// # BUGS
/// - It does not say which table: a `static` cannot be keyed by a const generic. An owner with one
///   instantiation reads the mark directly; a host test binary sees whichever climbed highest, and
///   `ceiling` tells which.
#[cfg(all(target_has_atomic = "32", feature = "peak"))]
static PEAK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Raise [`PEAK`] if `peak` beats what is recorded. Called from [`CapabilityTable`]'s one private
/// growth path, so it cannot be forgotten.
#[cfg(all(target_has_atomic = "32", feature = "peak"))]
fn note_peak(peak: u16, ceiling: usize) {
    use core::sync::atomic::Ordering;
    let ceiling = core::cmp::min(ceiling, u16::MAX as usize) as u32;
    let packed = ((peak as u32) << 16) | ceiling;
    // `fetch_max` rather than a compare-exchange loop: the packed word puts the peak in the high
    // half, so numeric max IS max-by-peak, and the ceiling that rides along is the one belonging to
    // the table that set the record.
    PEAK.fetch_max(packed, Ordering::Relaxed);
}

/// **The highest occupancy any capability table has reached, and that table's capacity.**
///
/// `(0, 0)` before anything has ever been inserted. One number for every instantiation linked
/// into the binary; see `PEAK`'s BUGS. Present only with the `peak` feature, because the record
/// is a `static` every table in the binary writes on growth, which a user who does not read it
/// should not pay for.
#[cfg(all(target_has_atomic = "32", feature = "peak"))]
pub fn highest_seen() -> (usize, usize) {
    let packed = PEAK.load(core::sync::atomic::Ordering::Relaxed);
    ((packed >> 16) as usize, (packed & 0xffff) as usize)
}

/// Machine-checked proofs of the capability model.
///
/// Each harness proves its property for every input, symbolically: `derive_never_widens_rights`
/// covers all 2^31 source and requested rights words (every bit but the marker) at once. Behind `#[cfg(kani)]`, so only `cargo
/// kani` builds it.
#[cfg(kani)]
mod verification {
    use super::*;

    /// Falsification: replayable `falsifications/verification.subset_is_reflexive.patch`
    /// Every capability is a subset of itself: the reflexive base case of the derivation order.
    #[kani::proof]
    fn subset_is_reflexive() {
        let a = Rights::from_word(kani::any());
        assert!(a.is_subset_of(a));
    }

    /// Falsification: replayable `falsifications/verification.subset_is_transitive.patch`
    /// **Rights cannot be laundered through a chain.** If B is derived from A and C from B, then C
    /// is no more than A. This is why a *flat* subset check suffices and we never need to walk a
    /// derivation tree to bound a capability: subset is transitive, so the chain can only narrow.
    #[kani::proof]
    fn subset_is_transitive() {
        let (a, b, c) = (
            Rights::from_word(kani::any()),
            Rights::from_word(kani::any()),
            Rights::from_word(kani::any()),
        );
        kani::assume(a.is_subset_of(b));
        kani::assume(b.is_subset_of(c));
        assert!(a.is_subset_of(c));
    }

    /// Falsification: replayable `falsifications/verification.from_bits_cannot_forge_a_right.patch`
    /// **Userspace cannot forge a right.** `from_bits` takes an attacker-controlled system call register
    /// (any u32) and the result holds only defined rights, for every possible input.
    #[kani::proof]
    fn from_bits_cannot_forge_a_right() {
        let raw: u32 = kani::any();
        assert!(Rights::from_bits(raw).is_subset_of(Rights::ALL));
    }

    /// Falsification: replayable `falsifications/verification.subset_matches_allows.patch`
    /// The two ways of asking the question agree: "a is no more than b" is exactly "b holds at
    /// least a". Proving them equivalent means a bug in one would show up against the other.
    #[kani::proof]
    fn subset_matches_allows() {
        let (a, b) = (
            Rights::from_word(kani::any()),
            Rights::from_word(kani::any()),
        );
        assert_eq!(a.is_subset_of(b), b.allows(a));
    }

    /// The storage of every table a harness builds: 67 slots, so a table may cross from the first
    /// free-slot word into the second, at slot 64.
    const PROOF_STORAGE: usize = 67;

    /// The slots whose state is arbitrary in [`any_capability_table`]. Three is enough to exhibit
    /// "the slot in question, a different slot, and an empty one" in every combination.
    const WINDOW: usize = 3;

    /// Where [`any_capability_table`]'s window may start: at slot 0, or across the boundary
    /// between the first two free-slot words (slots 62, 63 and 64).
    const WINDOW_AT_THE_WORD_BOUNDARY: usize = 62;

    /// A table of `size` slots in an arbitrary state of its window: the window starts at slot 0 or
    /// at slot 62, every slot in it below `size` is independently empty or holds a capability with
    /// symbolic object and rights, and every other slot is empty. With the window at 0 and `size`
    /// at most three, that is every state of every table of up to three slots, the old proofs'
    /// whole domain; with it at 62, the same freedom where one free-slot word ends and the next
    /// begins, so a floor at 62 or 63 searches across the boundary. `size` is the caller's, and
    /// each harness states its bound on it as an assumption.
    fn any_capability_table(size: usize) -> CapabilityTable<u8, PROOF_STORAGE> {
        let start: usize = kani::any();
        kani::assume(start == 0 || start == WINDOW_AT_THE_WORD_BOUNDARY);
        let mut cs = CapabilityTable::<u8, PROOF_STORAGE>::with_size(size)
            .expect("each harness assumes a size the storage holds");
        for offset in 0..WINDOW {
            let slot = start + offset;
            if slot < size && kani::any() {
                cs.put(
                    slot as u64,
                    Capability {
                        object: kani::any(),
                        rights: Rights::from_word(kani::any()),
                    },
                )
                .unwrap();
            }
        }
        cs
    }

    /// An arbitrary bit position of the free-slot set: a slot of the storage, or a bit past it.
    /// A claim checked at it holds at every position, so the harnesses quantify over slots with
    /// one symbolic index in place of a walk over the storage, which keeps every loop short.
    fn any_position() -> usize {
        let position: usize = kani::any();
        kani::assume(position < FREE_WORDS * 64);
        position
    }

    /// The free-slot set's bit at `position`.
    fn is_free_bit_set(cs: &CapabilityTable<u8, PROOF_STORAGE>, position: usize) -> bool {
        cs.free_mask()[position / 64] & (1 << (position % 64)) != 0
    }

    /// Whether the free-slot set agrees with the array at `position`: its bit is set exactly when
    /// the slot is below the size and empty, and a slot at or above the size is always empty.
    fn is_free_set_right_at(cs: &CapabilityTable<u8, PROOF_STORAGE>, position: usize) -> bool {
        let empty = cs.slot(position).is_none();
        is_free_bit_set(cs, position) == (position < cs.size() && empty)
            && (position < cs.size() || empty)
    }

    /// Whether the count agrees with the array: `used` is the number of occupied bits, and the
    /// occupied bit at `position` is set exactly when the slot holds a capability. Over every
    /// `position`, the two together say `used` is the number of occupied slots.
    fn is_count_right_at(cs: &CapabilityTable<u8, PROOF_STORAGE>, position: usize) -> bool {
        let occupied_bits: u32 = (0..FREE_WORDS)
            .map(|word| cs.occupied_word(word).count_ones())
            .sum();
        let occupied_bit = cs.occupied_word(position / 64) & (1 << (position % 64)) != 0;
        cs.used() == occupied_bits as usize && occupied_bit == cs.slot(position).is_some()
    }

    /// Falsification: replayable `falsifications/verification.the_count_is_the_slots.patch`
    /// **The occupancy count is the slots, for every reachable table state.**
    ///
    /// A drifted count reports a high-water mark that was never true. Covers both freeing paths,
    /// `delete` and `delete_matching`; `any_capability_table` builds through `put`.
    ///
    /// The bound: every size up to [`PROOF_STORAGE`], 67 slots, assumed below, and every slot
    /// index, through one symbolic position. `#[kani::unwind(5)]`: the longest loops are over
    /// the four free-slot words, and the sweep's walk over one word's occupied bits, which clears
    /// one bit per iteration and sees at most the window's three. The unwinding assertion fails if
    /// any loop could run once more.
    ///
    #[kani::proof]
    #[kani::unwind(5)]
    fn the_count_is_the_slots() {
        let position = any_position();
        let size: usize = kani::any();
        kani::assume(size <= PROOF_STORAGE);
        let mut cs = any_capability_table(size);
        assert!(
            is_count_right_at(&cs, position),
            "the count is wrong at the start"
        );

        // The sweep, which frees any number of slots in one pass and is the other freeing path.
        // It runs first, on the window's arbitrary state, so its walk sees at most three bits.
        let wanted: u8 = kani::any();
        cs.delete_matching(|o| *o == wanted);
        assert!(
            is_count_right_at(&cs, position),
            "delete_matching left the count behind"
        );

        // The floor insert and a second `put` over a slot that may be occupied.
        let _ = cs.insert_at_or_above(
            kani::any(),
            Capability {
                object: kani::any(),
                rights: Rights::from_word(kani::any()),
            },
        );
        assert!(
            is_count_right_at(&cs, position),
            "insert_at_or_above left the count behind"
        );
        let _ = cs.put(
            kani::any(),
            Capability {
                object: kani::any(),
                rights: Rights::from_word(kani::any()),
            },
        );
        assert!(
            is_count_right_at(&cs, position),
            "a second put left the count behind"
        );

        let slot: u64 = kani::any();
        let _ = cs.delete(slot);
        assert!(
            is_count_right_at(&cs, position),
            "delete left the count behind"
        );

        // And the mark never fell while all that was happening, which is what makes it a mark.
        assert!(cs.peak() >= cs.used());
    }

    /// Falsification: replayable `falsifications/verification.the_free_mask_is_the_empty_slots.patch`
    /// **The free-slot word is the set of empty slots, after every mutator.**
    ///
    /// `insert` believes the word: "free" over an occupied slot overwrites a live capability, and
    /// "occupied" over an empty one leaks it. Bits at and above the size must stay clear too, or a
    /// full table would not be zero words, and no slot at or above the size may ever be filled.
    /// Checked over every state `any_capability_table` builds and every slot index, through every
    /// mutator. The bound: every size up to [`PROOF_STORAGE`], assumed below, and every bit
    /// position, through one symbolic position. `#[kani::unwind(5)]`, by
    /// `the_count_is_the_slots`'s argument.
    ///
    #[kani::proof]
    #[kani::unwind(5)]
    fn the_free_mask_is_the_empty_slots() {
        let position = any_position();
        let capability = || Capability {
            object: kani::any(),
            rights: Rights::from_word(kani::any()),
        };
        let size: usize = kani::any();
        kani::assume(size <= PROOF_STORAGE);
        let mut cs = any_capability_table(size);
        assert!(is_free_set_right_at(&cs, position), "wrong after put");

        // The sweep runs first, on the window's arbitrary state, so its walk sees at most three
        // bits.
        let wanted: u8 = kani::any();
        cs.delete_matching(|o| *o == wanted);
        assert!(
            is_free_set_right_at(&cs, position),
            "wrong after delete_matching"
        );

        let _ = cs.insert(capability());
        assert!(is_free_set_right_at(&cs, position), "wrong after insert");

        let _ = cs.insert_at_or_above(kani::any(), capability());
        assert!(
            is_free_set_right_at(&cs, position),
            "wrong after insert_at_or_above"
        );

        let _ = cs.put(kani::any(), capability());
        assert!(
            is_free_set_right_at(&cs, position),
            "wrong after a second put"
        );

        let _ = cs.delete(kani::any());
        assert!(is_free_set_right_at(&cs, position), "wrong after delete");

        let _ = cs.insert_at(kani::any(), capability());
        assert!(is_free_set_right_at(&cs, position), "wrong after insert_at");

        let _ = cs.derive(kani::any(), kani::any(), Rights::from_word(kani::any()));
        assert!(is_free_set_right_at(&cs, position), "wrong after derive");

        assert_eq!(
            cs.is_empty(),
            (0..FREE_WORDS).all(|w| cs.free_mask()[w] == storage::all_free_word(size, w))
        );
        // `is_free_set_right_at` also said no door filled a slot at or above the size; nor did the
        // size move.
        assert_eq!(cs.size(), size, "the size changed");
    }

    /// Falsification: replayable `falsifications/verification.the_peak_never_falls_and_a_floor_insert_stays_above_its_floor.patch`
    /// **The high-water mark never falls across any operation, and a floor insert never lands
    /// below its floor.** One symbolic operation of any kind, applied to a symbolic table. The
    /// bound: every size up to [`PROOF_STORAGE`], assumed below. `#[kani::unwind(5)]`, by
    /// `the_count_is_the_slots`'s argument: a word holds at most the window's three occupied bits,
    /// and the four free-slot words are the longest loop.
    ///
    #[kani::proof]
    #[kani::unwind(5)]
    fn the_peak_never_falls_and_a_floor_insert_stays_above_its_floor() {
        let capability = Capability {
            object: kani::any(),
            rights: Rights::from_word(kani::any()),
        };
        let size: usize = kani::any();
        kani::assume(size <= PROOF_STORAGE);
        let mut cs = any_capability_table(size);
        let before = cs.peak();
        let floor: u64 = kani::any();
        let wanted: u8 = kani::any();
        let operation: u8 = kani::any();
        kani::assume(operation < 5);
        let mut landed = None;
        match operation {
            0 => landed = cs.insert_at_or_above(floor, capability).ok(),
            1 => drop(cs.insert(capability)),
            2 => drop(cs.delete(kani::any())),
            3 => drop(cs.insert_at(kani::any(), capability)),
            _ => cs.delete_matching(|o| *o == wanted),
        }
        assert!(cs.peak() >= before, "the mark fell");
        if let Some(slot) = landed {
            assert!(slot >= floor, "a floor insert landed below its floor");
        }
    }

    /// Falsification: replayable `falsifications/verification.a_deleted_capability_stays_deleted.patch`
    /// **Consume-on-use is final.** For every table state and every slot (in bounds or not), once
    /// `delete` succeeds the slot answers `NoSuchSlot` to both `get` and a second `delete`. This is
    /// the mechanism that makes a one-shot reply capability one-shot: the caller of `delete` removes
    /// it the instant it is invoked. The bound: every size up to [`PROOF_STORAGE`], assumed below.
    #[kani::proof]
    fn a_deleted_capability_stays_deleted() {
        let size: usize = kani::any();
        kani::assume(size <= PROOF_STORAGE);
        let mut cs = any_capability_table(size);
        let slot: u64 = kani::any();
        if cs.delete(slot).is_ok() {
            // The storage itself, before the accessors, so the claim rests on the array rather than
            // on two readers of it.
            assert!(
                cs.slot(slot as usize).is_none(),
                "the slot still holds a capability"
            );
            assert_eq!(cs.get(slot).err(), Some(Error::NoSuchSlot));
            assert_eq!(cs.delete(slot).err(), Some(Error::NoSuchSlot));
        }
    }

    /// Falsification: replayable `falsifications/verification.delete_touches_only_its_slot.patch`
    /// **Delete is slot-local.** Deleting any slot, in bounds or not, leaves every other slot
    /// exactly as it was. A server holding one-shot Reply capabilities for two callers consumes
    /// one and must still hold the other, or answering caller A would silently orphan caller B.
    /// The bound: every size up to [`PROOF_STORAGE`], assumed below.
    #[kani::proof]
    fn delete_touches_only_its_slot() {
        let size: usize = kani::any();
        kani::assume(size <= PROOF_STORAGE);
        let mut cs = any_capability_table(size);
        let victim: u64 = kani::any();
        let other: u64 = kani::any();
        kani::assume(victim != other);
        kani::assume(other < PROOF_STORAGE as u64);

        let before = cs.get(other);
        let _ = cs.delete(victim);
        assert_eq!(cs.get(other), before);
    }

    /// Falsification: replayable `falsifications/verification.derive_never_widens_rights.patch`
    /// **The central theorem, on the real `CapabilityTable::derive`.** For any source rights and any request,
    /// if the derive succeeds then the capability it stored holds no more than the source did, and
    /// holds exactly what was asked (no silent grant of more). There is no reachable input that
    /// widens authority.
    ///
    /// The bound: every size from two, the source and the destination, up to [`PROOF_STORAGE`],
    /// assumed below.
    #[kani::proof]
    fn derive_never_widens_rights() {
        let source_rights = Rights::from_word(kani::any());
        let requested = Rights::from_word(kani::any());

        let size: usize = kani::any();
        kani::assume((2..=PROOF_STORAGE).contains(&size));
        let mut cs = CapabilityTable::<u8, PROOF_STORAGE>::with_size(size).unwrap();
        cs.put(
            0,
            Capability {
                object: 0u8,
                rights: source_rights,
            },
        )
        .unwrap();

        if cs.derive(0, 1, requested).is_ok() {
            let derived = cs
                .slot(1)
                .expect("a successful derive filled the destination slot");
            // In raw bits, not through `is_subset_of`: `derive` guards on that predicate, so a
            // claim phrased through it would hold for any consistently wrong `is_subset_of`.
            assert_eq!(
                derived.rights.0.get() & !source_rights.0.get(),
                0,
                "a derived capability holds a right the source did not",
            );
            assert_eq!(
                requested.0.get() & !source_rights.0.get(),
                0,
                "a request wider than the source got past the guard",
            );
            // And it holds exactly what was asked: no silent grant of more, no silent clamp to
            // less. Field equality, so no predicate stands between the claim and the bits.
            assert_eq!(derived.rights.0.get(), requested.0.get());
            assert_eq!(derived.object, 0u8);
        }
    }

    /// Falsification: replayable `falsifications/verification.delegation_needs_grant_and_never_widens.patch`
    /// **Delegation needs `GRANT`, and never widens.** For every one of the 2^31 source rights words and
    /// every request, `delegate` succeeds only when the source held the `GRANT` bit and the copy's
    /// bits sit inside the source's, and the copy holds exactly what was asked. The other way too:
    /// a source with `GRANT` and a request inside it is never refused. Stated in raw bits, as
    /// `derive_never_widens_rights` is, so no predicate of the crate stands between the claim and
    /// the bits.
    #[kani::proof]
    fn delegation_needs_grant_and_never_widens() {
        const GRANT_BIT: u32 = 1 << 2;
        let source = Capability {
            object: 5u8,
            rights: Rights::from_word(kani::any()),
        };
        let requested = Rights::from_word(kani::any());

        match source.delegate(requested) {
            Ok(copy) => {
                assert_ne!(
                    source.rights.0.get() & GRANT_BIT,
                    0,
                    "a capability without GRANT was passed on"
                );
                assert_eq!(copy.rights.0.get() & !source.rights.0.get(), 0);
                assert_eq!(copy.rights.0.get(), requested.0.get());
                assert_eq!(copy.object, 5u8);
            }
            Err(Error::GrantRequired) => assert_eq!(source.rights.0.get() & GRANT_BIT, 0),
            Err(Error::CannotWiden) => {
                assert_ne!(source.rights.0.get() & GRANT_BIT, 0);
                assert_ne!(requested.0.get() & !source.rights.0.get(), 0);
            }
            Err(_) => panic!("delegate gave an answer it has no reason for"),
        }
    }

    /// Falsification: replayable `falsifications/verification.split_never_widens_rights.patch`
    /// **Authority never widens at the other mint site either: `split` inherits, it does not
    /// grant.** `MemoryRegion::SPLIT` mints outside [`CapabilityTable::derive`] through
    /// [`Capability::mint_child`], and this proves the child's rights are exactly the parent's,
    /// which implies the subset relation. Equality is the precise claim because a split passes
    /// `GRANT` down only when the parent holds it, so delegability comes from the root's mint, and
    /// rights down a budget tree never increase.
    #[kani::proof]
    fn split_never_widens_rights() {
        let parent = Capability {
            object: 7u8,
            rights: Rights::from_word(kani::any()),
        };
        let child_object: u8 = kani::any();

        let child = parent.mint_child(child_object);

        // Exactly the parent's, for every one of the 2^31 rights words: inheritance, not a grant.
        assert_eq!(
            child.rights, parent.rights,
            "an inheriting mint changed the child's rights",
        );
        // The weaker relation the capability model is phrased in, which the above implies.
        assert!(child.rights.is_subset_of(parent.rights));
        assert_eq!(child.object, child_object);
    }
}

#[cfg(test)]
mod tests;
