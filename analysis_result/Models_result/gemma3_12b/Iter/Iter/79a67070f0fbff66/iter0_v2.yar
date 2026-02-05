rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 9C 50 61 00 E8 8D 9A FF FF C7 45 C4 00 00 00 00 }
        $pattern1 = { 83 3D 5C 42 61 00 00 74 05 E8 EF 9C FF FF 6A 00 8B 0D 60 42 61 00 }
        $pattern2 = { FF 15 A4 50 61 00 8B 45 C4 8B 4D C4 3B 4D FC 73 22 }

    condition:
        any of them
}