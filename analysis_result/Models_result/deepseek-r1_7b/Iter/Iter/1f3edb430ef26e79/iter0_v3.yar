rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns for heap manipulation and stack spoofing"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } # Masking the real instruction
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } # Hiding stack manipulation
        $pattern2 = { 99 7E 3C 0F FF 45 4D 45 CC 5A 5A 16 } # Exploiting operand checks
}

condition:
    any of them
}