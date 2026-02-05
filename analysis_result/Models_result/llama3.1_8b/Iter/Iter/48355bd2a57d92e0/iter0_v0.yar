rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 5D C8 8B 4D C4 8B 7D C0 6A FF 6A 01 }
        $pattern1 = { 83 C6 04 83 EF 01 75 D6 8B 5D C8 53 }
        $pattern2 = { E8 6A 3E 00 00 84 C0 74 20 64 A1 30 00 00 00 }

    condition:
        any of them
}