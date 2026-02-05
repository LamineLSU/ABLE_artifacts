rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific test-eax and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 74 12 }
        $pattern1 = { 83 F8 01 74 ?? F8 ?? 5A 4D F8 }
        $pattern2 = { 6A 5B ?? 00 00 01 10 E8 25 F0 FE FF FF ?? ?? }
    condition:
        any of them
}