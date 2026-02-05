rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { 6A 35 6A 35 6A 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 8B 45 ?? 83 C4 14 52 5D C3 }

    condition:
        any of them
}