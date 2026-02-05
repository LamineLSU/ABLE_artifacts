rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 }  # Targets the first call with surrounding context
        $pattern1 = { 6A ?? 5A 8B CE E8 }    # Targets a different instruction sequence leading to bypass
        $pattern2 = { FF 15 64 10 41 00 }   # Targets another unique instruction path

    condition:
        any of them
}