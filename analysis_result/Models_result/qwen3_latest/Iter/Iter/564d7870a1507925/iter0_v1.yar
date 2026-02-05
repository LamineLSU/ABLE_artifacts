rule EvasionCheck {
    meta:
        description = "Detects evasion logic based on cmp and jnc instructions"
    condition:
        (66 81 3C 24 E4 07 73 ??) or
        (73 07 E8 ?? ?? ?? ??) or
        (E8 ?? ?? ?? ?? 66 81 3C 24 E4 07)
}