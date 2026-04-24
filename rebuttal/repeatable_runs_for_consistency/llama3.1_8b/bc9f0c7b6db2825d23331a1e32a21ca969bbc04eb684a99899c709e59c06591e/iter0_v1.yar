rule Evasion_Bypass
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 ?? 0F 84 ?? ?? ?? ?? 8B CE E8 25 05 00 00 }
        $pattern1 = { 6A 5B 5A 8B CE E8 25 05 00 00 85 C0 }
        $pattern2 = { FF 15 ?? ?? 41 00 FF 15 ?? ?? 41 00 FF 15 2C AB 04 10 }

    condition:
        any of them
}