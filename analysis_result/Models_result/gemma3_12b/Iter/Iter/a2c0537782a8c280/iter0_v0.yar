rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 01 FF 15 54 A0 F6 00 }
        $pattern1 = { 6A 00 6A 00 6A FF 8B F8 57 6A 00 6A 00 FF 15 50 A0 F6 00 }
        $pattern2 = { E8 11 F4 FF FF 8B D6 56 53 6A FF 57 6A 00 6A 00 FF 15 50 A0 F6 00 }

    condition:
        any of them
}