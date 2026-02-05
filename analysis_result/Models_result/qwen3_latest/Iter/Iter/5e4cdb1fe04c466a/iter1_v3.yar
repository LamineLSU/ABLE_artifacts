rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 }
        $pattern1 = { E8 ?? ?? ?? ?? 56 8B F8 }
        $pattern2 = { 0F 84 ?? ?? ?? ?? 83 C4 04 }

    condition:
        any of them
}