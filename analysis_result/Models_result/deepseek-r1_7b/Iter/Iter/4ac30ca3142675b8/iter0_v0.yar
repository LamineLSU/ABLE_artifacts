rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting potential stack manipulation and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC F0 B6 61 C9 83 C4 14 E8 74 0A 00 5E 5D C3 }
        $pattern1 = { 8B 16 FF D2 5E 5D C3 }
        $pattern2 = { 8B EC 8B 45 08 8B EC E8 74 0A 18 56 6A 36 6A 00 51 8D B0 A0 0C 56 5E 5D C3 }

    condition:
        (any of them)
}