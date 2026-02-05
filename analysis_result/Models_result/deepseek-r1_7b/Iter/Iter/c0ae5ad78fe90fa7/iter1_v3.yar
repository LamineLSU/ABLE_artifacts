rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 65 41 8B C8 FFFF ?? ???? }
        $pattern1 = { 74 ?? FF 75 08 ???? } 
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}