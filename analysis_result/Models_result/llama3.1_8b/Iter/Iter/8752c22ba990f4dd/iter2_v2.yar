rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 8B EC FF 75 08 E8 ?? ?? ?? FF }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern2 = { B8 00 10 00 00 0F 82 }

    condition:
        any of them
}