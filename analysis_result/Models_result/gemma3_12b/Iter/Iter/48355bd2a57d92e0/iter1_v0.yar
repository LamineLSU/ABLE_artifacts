rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 5D C8 8B 4D C4 8B 7D C0 6A FF 6A 01 51 57 FF 15 50 A0 B8 00 }
        $pattern1 = { FF 15 50 A0 B8 00 85 FF 74 39 8B 45 C4 8B F3 2B C3 89 45 C0 }
        $pattern2 = { 83 C6 04 83 EF 01 75 D6 8B 5D C8 53 E8 08 8D 02 00 }

    condition:
        any of them
}