rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 91 80 00 00 00 FF 55 8B EC 83 EC 70 C6 45 90 73 }
        $pattern1 = { FF 15 5C C2 4C 00 8B 45 FC 50 8B 4D 08 8B 51 48 FF D2 8B 45 F8 }
        $pattern2 = { 6A 00 6A 04 8B 45 F8 83 C0 34 50 8B 4D FC 52 8B 45 D8 50 }

    condition:
        any of them
}