rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 01 51 57 FF 15 50 A0 41 01 }
        $pattern1 = { 8B 45 C4 8B F3 2B C3 89 45 C0 }
        $pattern2 = { FF 15 84 A0 41 01 6A 02 EB F6 }

    condition:
        any of them
}