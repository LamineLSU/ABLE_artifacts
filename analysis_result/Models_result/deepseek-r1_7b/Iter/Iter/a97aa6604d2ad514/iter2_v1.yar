rule "your_rule_name" {
    # Pattern for FFD2 bypass with surrounding operations
    pattern "your_pattern_name" (0x1)
        (E8) (?)
        (5A)
        (A3)
        (F8)
        (?)

    # Another pattern for a different bypassed instruction type
    pattern "another_pattern_name" (0x1)
        (74) (?)
        (?) (0C)
        (?) (?)

    # Third pattern capturing another bypass scenario
    pattern "third_pattern_name" (0x1)
        (6A) (?)
        (?) (?) 
        (?) (5?)
}