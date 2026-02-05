rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,count=0"

    strings:
        $pattern1 = { 8B 5D C8 8B 4D C4 8B 7D C0 6A FF 6A 01 51 57 }
        $pattern2 = { FF 15 50 A0 20 00 85 FF 74 39 8B 45 C4 8B F3 }

    condition:
        any of them
}