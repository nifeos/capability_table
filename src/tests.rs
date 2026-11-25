use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Object {
    Console,
    PageFrame(u64),
}

/// **The occupied masks are the occupied slots and nothing above them.** A sweep walks these
/// words in place of `0..N`, so a bit set for a free slot, or for a slot past the size, is a visit
/// to something that is not there; the sweep's own guard would hide it, so the words are checked
/// themselves.
#[test]
fn the_occupied_mask_is_exactly_the_occupied_slots() {
    let capability = |n| Capability {
        object: Object::PageFrame(n),
        rights: Rights::ALL,
    };
    let mut cs: CapabilityTable<Object, 8> = CapabilityTable::new();
    assert_eq!(cs.occupied_word(0), 0);
    cs.insert_at(2, capability(1)).unwrap();
    cs.insert_at(5, capability(2)).unwrap();
    assert_eq!(cs.occupied_word(0), 0b0010_0100);
    cs.delete(2).unwrap();
    assert_eq!(cs.occupied_word(0), 0b0010_0000);
    let mut full: CapabilityTable<Object, 64> = CapabilityTable::new();
    assert_eq!(full.occupied_word(0), 0);
    full.insert_at(63, capability(3)).unwrap();
    assert_eq!(full.occupied_word(0), 1 << 63);
    // Across a word: slot 64 is bit 0 of the second word, and the first word does not see it.
    let mut wide: CapabilityTable<Object, 130> = CapabilityTable::new();
    wide.insert_at(64, capability(4)).unwrap();
    wide.insert_at(129, capability(5)).unwrap();
    assert_eq!(
        [
            wide.occupied_word(0),
            wide.occupied_word(1),
            wide.occupied_word(2)
        ],
        [0, 1, 1 << 1]
    );
}

/// **A new process holds nothing.** The decision, as an assertion.
#[test]
fn a_new_capability_table_can_name_nothing() {
    let cs: CapabilityTable<Object, 16> = CapabilityTable::new();

    assert!(cs.is_empty());
    for slot in 0..cs.capacity() as u64 {
        assert_eq!(cs.get(slot).err(), Some(Error::NoSuchSlot));
    }
}

/// `delete_matching` is `get`-then-`delete` over every slot, done in place: everything the
/// predicate matches goes, and **a non-matching neighbor survives untouched**, rights and all.
/// The second half is the property worth the test: a revocation sweep that took a bystander's
/// capability would be a denial of service wearing a security fix's clothes.
#[test]
fn delete_matching_takes_the_matched_and_spares_the_neighbor() {
    let mut cs: CapabilityTable<Object, 16> = CapabilityTable::new();
    cs.put(
        0,
        Capability {
            object: Object::PageFrame(0x1000),
            rights: Rights::READ,
        },
    )
    .unwrap();
    cs.put(
        1,
        Capability {
            object: Object::Console,
            rights: Rights::WRITE,
        },
    )
    .unwrap();
    cs.put(
        15,
        Capability {
            object: Object::PageFrame(0x2000),
            rights: Rights::ALL,
        },
    )
    .unwrap();

    cs.delete_matching(|o| matches!(o, Object::PageFrame(_)));

    // Both frames are gone, wherever they sat, including the last slot.
    assert_eq!(cs.get(0).err(), Some(Error::NoSuchSlot));
    assert_eq!(cs.get(15).err(), Some(Error::NoSuchSlot));
    // The bystander keeps its object and its rights.
    let survivor = cs.get(1).unwrap();
    assert_eq!(survivor.object, Object::Console);
    assert_eq!(survivor.rights, Rights::WRITE);
}

/// You cannot fabricate a capability. There is nothing to guess.
#[test]
fn an_unheld_slot_is_not_permission_denied_it_is_nothing() {
    let mut cs: CapabilityTable<Object, 16> = CapabilityTable::new();
    cs.put(
        0,
        Capability {
            object: Object::Console,
            rights: Rights::WRITE,
        },
    )
    .unwrap();

    assert_eq!(cs.get(0).unwrap().object, Object::Console);

    // Every other slot, and every slot past the end.
    assert_eq!(cs.get(1).err(), Some(Error::NoSuchSlot));
    assert_eq!(cs.get(15).err(), Some(Error::NoSuchSlot));
    assert_eq!(cs.get(16).err(), Some(Error::NoSuchSlot));
    assert_eq!(cs.get(u64::MAX).err(), Some(Error::NoSuchSlot));
}

/// **Rights only ever narrow.** If delegation could widen, the model is theater: you would
/// simply derive yourself a better capability from the one you have.
#[test]
fn derive_cannot_widen_rights() {
    let mut cs: CapabilityTable<Object, 16> = CapabilityTable::new();
    cs.put(
        0,
        Capability {
            object: Object::PageFrame(0x1000),
            rights: Rights::READ.union(Rights::GRANT),
        },
    )
    .unwrap();

    // Narrowing to nothing: fine.
    assert!(cs.derive(0, 1, Rights::NONE).is_ok());
    // Same rights: fine.
    assert!(cs.derive(0, 2, Rights::READ.union(Rights::GRANT)).is_ok());

    // **Asking for WRITE when we only hold READ.**
    assert_eq!(
        cs.derive(0, 3, Rights::WRITE).err(),
        Some(Error::CannotWiden)
    );
    assert_eq!(cs.derive(0, 3, Rights::ALL).err(), Some(Error::CannotWiden));

    // And the failed derive left nothing behind.
    assert_eq!(cs.get(3).err(), Some(Error::NoSuchSlot));
}

/// A narrowed capability names the **same object**. Delegation moves authority, not identity.
#[test]
fn a_derived_capability_names_the_same_object_with_less_authority() {
    let mut cs: CapabilityTable<Object, 16> = CapabilityTable::new();
    cs.put(
        0,
        Capability {
            object: Object::PageFrame(0x4000),
            rights: Rights::READ.union(Rights::WRITE).union(Rights::GRANT),
        },
    )
    .unwrap();

    cs.derive(0, 5, Rights::READ).unwrap();

    let original = cs.get(0).unwrap();
    let copy = cs.get(5).unwrap();

    assert_eq!(original.object, copy.object, "not the same object");
    assert!(original.rights.allows(Rights::WRITE));
    assert!(!copy.rights.allows(Rights::WRITE), "the copy kept WRITE");
}

/// Deriving from an empty slot fails. You cannot lend what you do not hold.
#[test]
fn you_cannot_delegate_what_you_do_not_hold() {
    let mut cs: CapabilityTable<Object, 16> = CapabilityTable::new();
    assert_eq!(cs.derive(3, 4, Rights::READ).err(), Some(Error::NoSuchSlot));
}

/// **A capability without `GRANT` cannot be passed on, whatever is asked for.** The refusal is
/// its own answer, distinct from asking for more than is held, and a refused derive leaves the
/// destination slot empty.
#[test]
fn a_capability_without_grant_cannot_be_passed_on() {
    let mut cs: CapabilityTable<Object, 16> = CapabilityTable::new();
    let source = Capability {
        object: Object::Console,
        rights: Rights::READ.union(Rights::WRITE),
    };
    cs.put(0, source).unwrap();

    assert_eq!(
        source.delegate(Rights::READ).err(),
        Some(Error::GrantRequired)
    );
    assert_eq!(
        source.delegate(Rights::NONE).err(),
        Some(Error::GrantRequired)
    );
    assert_eq!(
        cs.derive(0, 1, Rights::READ).err(),
        Some(Error::GrantRequired)
    );
    assert_eq!(cs.get(1).err(), Some(Error::NoSuchSlot));
}

/// With `GRANT`, `delegate` narrows to exactly what was asked, names the same object, and refuses
/// a right the source lacks as `CannotWiden`.
#[test]
fn delegate_narrows_to_what_was_asked_and_refuses_more() {
    let source = Capability {
        object: Object::PageFrame(0x8000),
        rights: Rights::READ.union(Rights::GRANT),
    };
    let copy = source.delegate(Rights::READ).unwrap();
    assert_eq!(copy.object, source.object);
    assert_eq!(copy.rights, Rights::READ);
    assert_eq!(
        source.delegate(Rights::WRITE).err(),
        Some(Error::CannotWiden)
    );
}

/// `iter` walks exactly the occupied slots, lowest first, and agrees with `get`.
#[test]
fn iter_walks_the_occupied_slots_in_order() {
    let capability = |n| Capability {
        object: Object::PageFrame(n),
        rights: Rights::READ,
    };
    let mut cs: CapabilityTable<Object, 64> = CapabilityTable::new();
    assert_eq!(cs.iter().count(), 0);
    cs.put(40, capability(4)).unwrap();
    cs.put(3, capability(1)).unwrap();
    cs.put(63, capability(6)).unwrap();
    cs.delete(40).unwrap();
    let mut walk = cs.iter();
    assert_eq!(walk.next(), Some((3, capability(1))));
    assert_eq!(walk.next(), Some((63, capability(6))));
    assert_eq!(walk.next(), None);
    for (slot, held) in cs.iter() {
        assert_eq!(cs.get(slot), Ok(held));
    }
}

/// A specific slot that is occupied is `SlotOccupied`, and a full table is `NoFreeSlot`: two
/// different facts.
#[test]
fn an_occupied_slot_is_not_a_full_table() {
    let capability = Capability {
        object: Object::Console,
        rights: Rights::READ,
    };
    let mut cs: CapabilityTable<Object, 2> = CapabilityTable::new();
    cs.insert_at(0, capability).unwrap();
    assert_eq!(cs.insert_at(0, capability), Err(Error::SlotOccupied));
    cs.insert_at(1, capability).unwrap();
    assert_eq!(cs.insert(capability), Err(Error::NoFreeSlot));
}

#[test]
fn deleting_a_capability_makes_the_object_unnameable() {
    let mut cs: CapabilityTable<Object, 16> = CapabilityTable::new();
    cs.put(
        0,
        Capability {
            object: Object::Console,
            rights: Rights::ALL,
        },
    )
    .unwrap();

    cs.delete(0).unwrap();
    assert_eq!(cs.get(0).err(), Some(Error::NoSuchSlot));
    assert_eq!(cs.delete(0).err(), Some(Error::NoSuchSlot));
}

#[test]
fn rights_arithmetic() {
    assert!(Rights::ALL.allows(Rights::WRITE));
    assert!(!Rights::READ.allows(Rights::WRITE));
    assert!(Rights::NONE.is_subset_of(Rights::READ));
    assert!(Rights::READ.is_subset_of(Rights::ALL));
    assert!(!Rights::ALL.is_subset_of(Rights::READ));
    assert_eq!(Rights::ALL.intersect(Rights::READ), Rights::READ);
}

/// **Both halves of the packed high-water word, read exactly rather than as a floor.**
///
/// `PEAK` is shared by every table in this binary, so a floor cannot pin either half: `>>` for
/// `<<` in the peak half and `&` for `|` or `^` in the ceiling half survived one. Exactness holds because
/// `fetch_max` only raises and no table in this binary can exceed `MAXIMUM_SLOTS` of
/// `MAXIMUM_SLOTS` (the bound test ties it, writing the same word).
#[test]
fn the_high_water_word_reports_the_occupancy_and_the_capacity_that_set_it() {
    let capability = Capability {
        object: Object::PageFrame(3),
        rights: Rights::READ,
    };
    // Full at the most a table may have.
    let mut cs: CapabilityTable<Object, MAXIMUM_SLOTS> = CapabilityTable::new();
    for _ in 0..MAXIMUM_SLOTS {
        cs.insert(capability)
            .expect("a table of the bound holds the bound");
    }

    assert_eq!(
        highest_seen(),
        (MAXIMUM_SLOTS, MAXIMUM_SLOTS),
        "no table in this test binary can exceed the bound, so this record is the one standing"
    );
}

/// **The free-slot word at its edge, and first-free after a hole.** Sixty-four slots is the
/// case where every bit of the `u64` is a slot, so "all free" is `u64::MAX` and "full" is zero
/// with no bits above `N` to mistake for room. A hole punched in the middle must be the next
/// slot `insert` takes, lowest first, because the kernel's Reply mint relies on first-free.
#[test]
fn the_free_slot_word_fills_to_zero_and_hands_back_the_lowest_hole() {
    let capability = Capability {
        object: Object::PageFrame(1),
        rights: Rights::READ,
    };
    let mut cs: CapabilityTable<Object, 64> = CapabilityTable::new();
    assert_eq!(cs.free_mask(), [u64::MAX, 0, 0, 0]);
    for want in 0..64u64 {
        assert_eq!(cs.insert(capability), Ok(want));
    }
    assert_eq!(cs.free_mask(), [0; 4], "a full table is zero words");
    assert_eq!(cs.insert(capability), Err(Error::NoFreeSlot));

    cs.delete(20).unwrap();
    cs.delete(7).unwrap();
    assert_eq!(cs.free_mask(), [(1 << 20) | (1 << 7), 0, 0, 0]);
    assert_eq!(cs.insert(capability), Ok(7), "lowest hole first");
    assert_eq!(cs.insert(capability), Ok(20));
    assert_eq!(cs.used(), 64);

    // A small table's bits above N stay clear, so full is still zero there too.
    let mut small: CapabilityTable<Object, 3> = CapabilityTable::new();
    assert_eq!(small.free_mask(), [0b111, 0, 0, 0]);
    for _ in 0..3 {
        small.insert(capability).unwrap();
    }
    assert_eq!(small.free_mask(), [0; 4]);
    assert_eq!(small.insert(capability), Err(Error::NoFreeSlot));
}

#[test]
fn a_full_table_says_so() {
    let mut cs: CapabilityTable<Object, 2> = CapabilityTable::new();
    let capability = Capability {
        object: Object::Console,
        rights: Rights::ALL,
    };
    assert_eq!(cs.insert(capability), Ok(0));
    assert_eq!(cs.insert(capability), Ok(1));
    assert_eq!(cs.insert(capability).err(), Some(Error::NoFreeSlot));
}

/// **`insert_at_or_above` never lands below its floor**, finds the first free slot at or above
/// it, and is `insert` at floor 0.
#[test]
fn insert_at_or_above_respects_its_floor() {
    let mut t: CapabilityTable<u8, 64> = CapabilityTable::new();
    let capability = |o| Capability {
        object: o,
        rights: Rights::ALL,
    };
    assert_eq!(t.insert_at_or_above(12, capability(1)), Ok(12));
    assert_eq!(t.insert_at_or_above(12, capability(2)), Ok(13));
    assert_eq!(
        t.insert_at_or_above(0, capability(3)),
        Ok(0),
        "floor 0 is first free"
    );
    assert_eq!(
        t.insert_at_or_above(64, capability(4)),
        Err(Error::NoFreeSlot)
    );
    for s in 14..64 {
        t.insert_at(s, capability(5)).unwrap();
    }
    assert_eq!(
        t.insert_at_or_above(12, capability(6)),
        Err(Error::NoFreeSlot),
        "slots below the floor do not count"
    );
}

/// The rights bits are the system call wire format: delegation names them in a register, and
/// `from_bits` turns the register back into authority, masking off undefined bits. The exact values
/// are pinned because mutants (`1 << 1` as
/// `1 >> 1`, `from_bits` using `|` instead of a mask) survived when nothing pinned them. The `ALL`
/// union is spelled out by hand, since a right missing from `ALL` is dropped at every delegation
/// and a check that read `ALL` to check `ALL` would pass whatever it was given.
#[test]
fn rights_bits_are_the_wire_format() {
    assert_eq!(
        [
            Rights::READ.bits(),
            Rights::WRITE.bits(),
            Rights::GRANT.bits(),
            Rights::ENUMERATE.bits(),
            Rights::BIND.bits(),
            Rights::REVOKE.bits()
        ],
        [1, 2, 4, 8, 16, 32]
    );
    // Every defined bit is in ALL, and ALL defines nothing that is not a named right.
    assert_eq!(
        Rights::ALL.bits(),
        Rights::READ.bits()
            | Rights::WRITE.bits()
            | Rights::GRANT.bits()
            | Rights::ENUMERATE.bits()
            | Rights::BIND.bits()
            | Rights::REVOKE.bits()
    );
    // Undefined bits are dropped, never reinterpreted.
    assert_eq!(Rights::from_bits(!Rights::ALL.bits()), Rights::NONE);
    // Defined bits come back as exactly the rights they name.
    assert_eq!(Rights::from_bits(0b101), Rights::READ.union(Rights::GRANT));
    // Union is a union, not a toggle: adding a right twice cannot remove it.
    assert_eq!(Rights::READ.union(Rights::READ), Rights::READ);
}

/// `insert_at` is how a supervisor reserves the fault slot, so what matters is that the
/// capability lands in THAT slot, the slot comes back as the receipt, and an occupied slot
/// refuses rather than replaces (two things must never share the slot the kernel reads at
/// start).
#[test]
fn insert_at_fills_exactly_the_named_slot() {
    let mut cs: CapabilityTable<Object, 4> = CapabilityTable::new();
    let capability = Capability {
        object: Object::PageFrame(7),
        rights: Rights::READ,
    };
    assert_eq!(cs.insert_at(2, capability), Ok(2));
    assert_eq!(cs.get(2).unwrap().object, Object::PageFrame(7));
    assert!(!cs.is_empty());
    // The other slots are still empty, so it did not spray.
    assert_eq!(cs.get(0).err(), Some(Error::NoSuchSlot));
    // Occupied refuses; out of range is a different answer, as everywhere.
    assert_eq!(cs.insert_at(2, capability).err(), Some(Error::SlotOccupied));
    assert_eq!(cs.insert_at(9, capability).err(), Some(Error::NoSuchSlot));
    // capacity is the table's size in slots, not its population.
    assert_eq!(cs.capacity(), 4);
}

/// **The high-water mark is a mark, not a level**, which is the whole reason it exists: a boot
/// that filled the table and then emptied it reached the wall, and a count sampled afterwards
/// says it did not.
///
/// Every mutator that can occupy an empty slot is exercised here (`insert`, `insert_at`, and
/// `put` over an empty slot), because each has its own call to the private growth path and a
/// missed one would be invisible: the number would simply be a little too low, forever.
#[test]
fn the_peak_records_what_was_reached_and_never_what_is_left() {
    let capability = Capability {
        object: Object::PageFrame(1),
        rights: Rights::READ,
    };
    let mut cs: CapabilityTable<Object, 4> = CapabilityTable::new();
    assert_eq!((cs.used(), cs.peak()), (0, 0));

    assert_eq!(cs.insert(capability), Ok(0));
    assert_eq!(cs.insert_at(2, capability), Ok(2));
    cs.put(3, capability).expect("slot 3 is in range");
    assert_eq!((cs.used(), cs.peak()), (3, 3));

    // Replacing an occupant is not growth.
    cs.put(3, capability).expect("slot 3 is in range");
    assert_eq!((cs.used(), cs.peak()), (3, 3));

    // And emptying it does not lower the mark.
    cs.delete(0).expect("slot 0 is occupied");
    cs.delete_matching(|o| matches!(o, Object::PageFrame(_)));
    assert_eq!((cs.used(), cs.peak()), (0, 3));

    // Refusals leave the count alone. Both of `insert_at`'s, and `delete`'s.
    assert!(cs.insert_at(9, capability).is_err());
    assert!(cs.delete(1).is_err());
    assert_eq!((cs.used(), cs.peak()), (0, 3));

    // A full table refuses, and the mark is the capacity rather than one past it.
    let mut full: CapabilityTable<Object, 2> = CapabilityTable::new();
    assert!(full.insert(capability).is_ok());
    assert!(full.insert(capability).is_ok());
    assert_eq!(full.insert(capability).err(), Some(Error::NoFreeSlot));
    assert_eq!((full.used(), full.peak()), (2, 2));
}

/// The global is a convenience over the per-table mark and must never read *below* it, which is
/// the only property the kernel relies on: it prints the global and would understate the boot
/// if this were ever false. It is a floor rather than an equality because the static is shared
/// by every instantiation in the binary, including the other tests in this module.
#[test]
fn the_global_high_water_mark_is_never_below_a_table_that_reached_it() {
    let capability = Capability {
        object: Object::PageFrame(2),
        rights: Rights::WRITE,
    };
    let mut cs: CapabilityTable<Object, 8> = CapabilityTable::new();
    for _ in 0..5 {
        cs.insert(capability).expect("eight slots hold five");
    }
    let (peak, ceiling) = highest_seen();
    assert!(
        peak >= cs.peak(),
        "the global said {peak} while a table had reached {}",
        cs.peak()
    );
    assert!(
        ceiling > 0,
        "a recorded peak carries the table it came from"
    );
}

/// A slot number too wide for `usize` names nothing, on every target: on a 32-bit `usize`,
/// truncation would let `2^32 + k` name slot `k`.
#[test]
fn a_slot_past_the_width_of_usize_names_nothing() {
    let mut cs: CapabilityTable<Object, 16> = CapabilityTable::new();
    cs.put(
        0,
        Capability {
            object: Object::Console,
            rights: Rights::READ,
        },
    )
    .unwrap();
    for slot in [1u64 << 32, (1 << 32) + 1, u64::MAX] {
        assert_eq!(cs.get(slot).err(), Some(Error::NoSuchSlot), "{slot:#x}");
        assert_eq!(cs.delete(slot).err(), Some(Error::NoSuchSlot), "{slot:#x}");
        let again = Capability {
            object: Object::Console,
            rights: Rights::READ,
        };
        assert_eq!(
            cs.put(slot, again).err(),
            Some(Error::NoSuchSlot),
            "{slot:#x}"
        );
    }
    assert!(cs.get(0).is_ok());
}

/// A sweep may keep state between slots, which is why it takes `FnMut`, as `retain` does.
#[test]
fn a_sweep_may_count_what_it_deletes() {
    let mut cs: CapabilityTable<Object, 16> = CapabilityTable::new();
    for _ in 0..3 {
        cs.insert(Capability {
            object: Object::Console,
            rights: Rights::READ,
        })
        .unwrap();
    }
    let mut seen = 0;
    cs.delete_matching(|_| {
        seen += 1;
        true
    });
    assert_eq!(seen, 3);
    assert!(cs.is_empty());
}

/// `Error` prints, so it sits behind `?` into a boxed error.
#[test]
fn an_error_prints_and_is_an_error() {
    extern crate std;
    use std::string::ToString;
    let error: &dyn core::error::Error = &Error::NoFreeSlot;
    assert_eq!(error.to_string(), "the table is full");
}

/// **An empty slot costs nothing beyond its capability.** `Rights` never holds the zero word, so
/// `Option` takes it for `None`, even over an object type with no spare bit pattern of its own.
#[test]
fn an_empty_slot_is_no_larger_than_a_capability() {
    use core::mem::size_of;
    assert_eq!(size_of::<Option<Rights>>(), size_of::<Rights>());
    assert_eq!(
        size_of::<Option<Capability<u64>>>(),
        size_of::<Capability<u64>>()
    );
    assert_eq!(size_of::<Capability<u64>>(), 16);
    // 64 slots of 16 bytes, the four `u64` free words and three `u16` counts, rounded to eight.
    assert_eq!(size_of::<CapabilityTable<u64, 64>>(), 1064);
}

/// The marker bit is no right: `from_bits` drops bit 31 with every other undefined bit, and
/// `Debug` shows the rights alone.
#[test]
fn the_marker_bit_is_no_right() {
    assert_eq!(Rights::from_bits(u32::MAX), Rights::ALL);
    assert_eq!(Rights::from_bits(1 << 31), Rights::NONE);
    assert_eq!(Rights::NONE.bits(), 0);
    assert_eq!(Rights::ALL.bits(), 0b11_1111);
    extern crate std;
    assert_eq!(
        std::format!("{:?}", Rights::READ.union(Rights::GRANT)),
        "Rights(5)"
    );
}

/// **A table sized at creation answers to its size, not its storage.** Slots at and above the size
/// are out of range to every door, and the size never changes: deleting cannot shrink it and
/// filling cannot grow it.
#[test]
fn a_table_sized_at_creation_answers_to_its_size() {
    let capability = |n| Capability {
        object: Object::PageFrame(n),
        rights: Rights::ALL,
    };
    assert!(CapabilityTable::<Object, 8>::with_size(9).is_none());
    let mut cs = CapabilityTable::<Object, 8>::with_size(5).unwrap();
    assert_eq!((cs.size(), cs.capacity()), (5, 5));
    assert_eq!(cs.free_mask(), [0b1_1111, 0, 0, 0]);
    // A size that ends inside a later word sets that word's bits only up to the size.
    let partial = CapabilityTable::<Object, 256>::with_size(100).unwrap();
    assert_eq!(partial.free_mask(), [u64::MAX, (1 << 36) - 1, 0, 0]);
    for want in 0..5 {
        assert_eq!(cs.insert(capability(want)), Ok(want));
    }
    assert_eq!(cs.insert(capability(9)), Err(Error::NoFreeSlot));
    assert_eq!(
        cs.insert_at_or_above(5, capability(9)),
        Err(Error::NoFreeSlot)
    );
    assert_eq!(cs.insert_at(5, capability(9)), Err(Error::NoSuchSlot));
    assert_eq!(cs.put(7, capability(9)), Err(Error::NoSuchSlot));
    assert_eq!(cs.derive(0, 6, Rights::READ), Err(Error::NoSuchSlot));
    assert_eq!(cs.get(5), Err(Error::NoSuchSlot));
    cs.delete_matching(|_| true);
    assert!(cs.is_empty());
    assert_eq!(cs.size(), 5);
    // A table of no slots holds nothing and refuses everything.
    let mut none = CapabilityTable::<Object, 8>::with_size(0).unwrap();
    assert_eq!(none.insert(capability(1)), Err(Error::NoFreeSlot));
    assert_eq!(none.free_mask(), [0; 4]);
}

/// **The free-slot set crosses its words.** At the bound every word is in use, first-free carries
/// from one word to the next, a floor in a later word skips the earlier ones, and the walks visit
/// every word in order.
#[test]
fn the_free_slot_set_spans_its_words() {
    let capability = |n| Capability {
        object: Object::PageFrame(n),
        rights: Rights::READ,
    };
    let mut cs: CapabilityTable<Object, MAXIMUM_SLOTS> = CapabilityTable::new();
    assert_eq!(cs.free_mask(), [u64::MAX; 4]);
    for want in 0..MAXIMUM_SLOTS as u64 {
        assert_eq!(cs.insert(capability(want % 3)), Ok(want));
    }
    assert_eq!(cs.free_mask(), [0; 4]);
    cs.delete(200).unwrap();
    cs.delete(65).unwrap();
    assert_eq!(cs.free_mask(), [0, 1 << 1, 0, 1 << 8]);
    assert_eq!(cs.insert_at_or_above(66, capability(0)), Ok(200));
    assert_eq!(cs.insert(capability(2)), Ok(65));
    assert_eq!(
        cs.insert_at_or_above(255, capability(0)),
        Err(Error::NoFreeSlot)
    );
    assert_eq!(
        cs.insert_at_or_above(256, capability(0)),
        Err(Error::NoFreeSlot)
    );
    // The walk visits every occupied slot of every word, lowest first.
    extern crate std;
    let slots: std::vec::Vec<u64> = cs.iter().map(|(slot, _)| slot).collect();
    assert_eq!(
        slots,
        (0..MAXIMUM_SLOTS as u64).collect::<std::vec::Vec<_>>()
    );
    // The sweep reaches every word: a third of the slots hold object 1.
    cs.delete_matching(|o| *o == Object::PageFrame(1));
    assert_eq!(cs.used(), MAXIMUM_SLOTS - MAXIMUM_SLOTS / 3);
    assert!(cs.iter().all(|(_, c)| c.object != Object::PageFrame(1)));
    assert_eq!(cs.free_mask()[3] & (1 << 62), 0, "slot 254 holds object 2");
    assert_ne!(cs.free_mask()[3] & (1 << 61), 0, "slot 253 held object 1");
    // A floor in a later word lands there.
    assert_eq!(cs.insert_at_or_above(130, capability(1)), Ok(130));
}
