rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } //Target 1: CALL to runtime address
        $pattern1 = { 8B 45 ?? 33 CD 5B 5E } //Target 2: int3
        $pattern2 = { 68 40 11 CD 33 C9 E8 4B 17 00 00 } //Target 3: CALL to runtime address

    condition:
        any of them
}