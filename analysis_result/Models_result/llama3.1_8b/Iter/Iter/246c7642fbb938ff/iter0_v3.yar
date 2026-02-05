rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC ?? ?? ?? ?? 59 }
        $pattern1 = { E8 C8 FF FF FF CA LL DW OR D PT R [0 04 0E 7C 3H ] FF 75 08 PU SH DW OR D PT R [E BP +0 8H ] }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}