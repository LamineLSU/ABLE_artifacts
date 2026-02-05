rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 85 C0 }
        $pattern1 = { 85 C0 0F 84 33 FD FF FF 8B 85 F0 FE FF FF }
        $pattern2 = { FF 15 88 A0 3D 00 53 6A 40 53 68 40 11 3D 00 }

    condition:
        any of them
}