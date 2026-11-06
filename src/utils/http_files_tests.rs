use super::*;

#[test]
fn unix_permissions_to_u32() {
    let mut item = HttpFiles::new("", false);

    item.perms = String::from("777");
    item.perms_to_u32();
    assert_eq!(item.perms_u32, 511);

    item.perms = String::from("644");
    item.perms_to_u32();
    assert_eq!(item.perms_u32, 420);

    item.perms = String::from("650");
    item.perms_to_u32();
    assert_eq!(item.perms_u32, 424);
}
