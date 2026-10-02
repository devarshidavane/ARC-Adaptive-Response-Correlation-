fn main() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<std::process::Child>();
}
