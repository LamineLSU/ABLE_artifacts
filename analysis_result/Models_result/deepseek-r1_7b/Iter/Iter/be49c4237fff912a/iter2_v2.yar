rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE 01 32 E6 00 00 }
        $pattern1 = { 8B E5 01 32 A0 88 5D 01 32 A1 14 5D 01 32 A1 2C }
        $pattern2 = { 74 07 01 32 61 F8 5E 01 32 61 90 }

    condition:
        any of them
}