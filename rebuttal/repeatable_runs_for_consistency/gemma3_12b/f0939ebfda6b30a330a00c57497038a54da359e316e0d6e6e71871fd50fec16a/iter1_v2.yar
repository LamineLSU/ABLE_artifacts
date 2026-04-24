rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 01 51 57 FF 15 50 A0 41 01 85 FF 74 39 }
        $pattern1 = { 8B 4D C4 8B 7D C0 6A FF 6A 01 51 57 FF 15 7C A0 41 01 }
        $pattern2 = { 83 26 00 89 45 C0 8B D8 FF 34 1E FF 15 44 A0 41 01 }

    condition:
        any of them
}