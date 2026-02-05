rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 25 05 00 00 3F 9D }
        $pattern1 = { FF 0D F8 6A 74 12 8B 45 FC }
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 }

    condition:
        (match $pattern0) || (match $pattern1) || (match $pattern2)
}