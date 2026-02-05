rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting exit path"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {6D 45 8B 3E FE F9 C7 ?? ?? ?? ?? DD 99 3F AD 77 4A}
        $pattern1 = {85 C0 8B 56 56 8B 04 ?? ?? ?? ?? ?? ?D 56}
        $pattern2 = {E1C8 8B 56 56 8B 04 ?? ?? ?? ?? E1CA FF F2 73 0A}
}

# Explanation:
- Each pattern represents a different bypass method.
- `$pattern0` skips the `call eax` with an offset, using wildcards to ignore specific addresses.
- `$pattern1` skips multiple pushes without executing them, affecting register context.
- `$pattern2` skips a conditional jump before proceeding further, allowing bypass of checks.
}