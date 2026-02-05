rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific trace patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 53 00 E6 D0 86 C3 }
        $pattern1 = { 8B 4D F8 53 00 E6 10 2C FF 15 14 75 EA 00 CA }
        $pattern2 = { 8B 4A CB 53 00 E6 D0 80 FF 15 44 74 EA 00 CA }

    condition:
        any of them
}