- **Runtime key configuration**: Keys are provided by the consumer, enabling rotation

- [ ] Implement key rotation support (consumer-provided key selector)

### Key Rotation

```rust
pub struct RotatingKeyProvider<K: KeyProvider> {
    primary: Arc<K>,
    backup: Arc<K>,
    rotation_interval: Duration,
}

impl<K: KeyProvider> KeyProvider for RotatingKeyProvider<K> {
    fn get_signing_key(&self, key_id: Option<&str>) -> Result<&dyn Signer> {
        // Return primary or backup based on rotation state
    }
}
```
