rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x0041E1E7,action0=skip,bp1=0x0041E20C,action1=skip,bp2=0x0041E214,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 8B 45 08 8B 48 14 56 6A 35 }
        $pattern1 = { 83 C4 14 52 8B 16 50 51 FF D2 }
        $pattern2 = { 5E 5D 8B 16 50 51 FF D2 }

    condition:
        any of them
}