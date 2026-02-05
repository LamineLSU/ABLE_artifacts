rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific exit points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 59 BD FF FF 8B 7B 10 8B 7B 10 85 FF 74 1C }
        $pattern1 = { E8 F7 FB FF FF BE 8B 45 FC } <!-- Adjusted for jbe before call -->
        $pattern2 = { 3B 75 04 8B 4D F8 } <!-- Specific cmp and mov sequence -->
}

condition:
    any of them