rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 5D C8 8B 4D C4 8B 7D C0 6A FF 6A 01 51 57 }
        $pattern1 = { 83 26 00 74 14 83 C6 04 83 EF 01 75 D6 }
        $pattern2 = { 8B 5D C8 8B 4D C4 8B 7D C0 6A FF 6A 01 51 57 }

    condition:
        any of them
}