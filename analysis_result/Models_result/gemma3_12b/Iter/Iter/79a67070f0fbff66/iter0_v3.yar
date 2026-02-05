rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 9C 50 61 00 E8 8D 9A FF FF C7 45 C4 00 00 00 00 }
        $pattern1 = { 8B 45 C4 83 C0 01 89 45 C4 8B 4D C4 3B 4D FC 73 22 }
        $pattern2 = { 8B 55 E4 52 E8 5F 88 00 00 83 C4 04 50 E8 5F 88 00 00 }

    condition:
        any of them
}